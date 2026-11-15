package frontend

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/hollis-labs/libs/mcp/plugin-mcp/go-mcp/sanitize"
	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func schema(properties map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func stringSchema() map[string]any { return map[string]any{"type": "string"} }
func discoverySchema(search bool) map[string]any {
	array := map[string]any{"type": "array", "items": stringSchema()}
	p := map[string]any{"servers": array, "cursor": stringSchema(), "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}
	if !search {
		p["names"] = array
		return schema(p)
	}
	p["query"] = map[string]any{"type": "string", "minLength": 1}
	p["tags"] = array
	p["detail"] = map[string]any{"type": "string", "enum": []string{"names", "summary", "schema"}}
	p["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 50}
	return schema(p, "query")
}
func (v *view) addInfrastructure() {
	read := &mcp.ToolAnnotations{ReadOnlyHint: true}
	add := func(name, description string, s map[string]any, fn mcp.ToolHandler) {
		t := &mcp.Tool{Name: name, Description: description, InputSchema: s, Annotations: read}
		v.infrastructure = append(v.infrastructure, t)
		v.server.AddTool(t, fn)
	}
	if v.admission.Selection.Mode == gateway.Search {
		for _, search := range []bool{false, true} {
			name, description := "mcp_gateway_tool_list", "Enumerate eligible tool schemas or hydrate exact names. Names cannot be combined with servers, limit or cursor. Resume with next_cursor."
			if search {
				name, description = "mcp_gateway_tool_search", "Search eligible tools by a nonempty query. Use detail=names, summary or schema. Dispatch with mcp_gateway_tool_call."
			}
			add(name, description, discoverySchema(search), func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var q gateway.Request
				if err := decode(r.Params.Arguments, &q); err != nil {
					//nolint:nilerr // MCP validation failures are tool results, not protocol errors.
					return toolError("invalid discovery arguments"), nil
				}
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(r.Params.Arguments, &fields)
				if _, ok := fields["limit"]; ok && q.Limit < 1 {
					return toolError("limit must be a positive integer"), nil
				}
				if _, ok := fields["detail"]; ok && q.Detail == "" {
					return toolError("detail must be names, summary or schema"), nil
				}
				var out gateway.Result
				var err error
				if search {
					out, err = v.service.Search(q)
				} else {
					out, err = v.service.List(q)
				}
				if err != nil {
					return toolError(err.Error()), nil
				}
				return result(out), nil
			})
		}
		destructive := true
		callTool := &mcp.Tool{Name: "mcp_gateway_tool_call", Description: "Dispatch one eligible exact tool using its arguments schema. Targets may mutate state; this dispatcher is not read-only.", InputSchema: schema(map[string]any{"name": map[string]any{"type": "string", "minLength": 1}, "arguments": map[string]any{"type": "object"}}, "name", "arguments"), Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive}}
		v.infrastructure = append(v.infrastructure, callTool)
		v.server.AddTool(callTool, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if decode(r.Params.Arguments, &in) != nil || in.Name == "" {
				//nolint:nilerr // MCP validation failures are tool results.
				return toolError("name and arguments are required"), nil
			}
			args, err := object(in.Arguments)
			if err != nil {
				return toolError(err.Error()), nil
			}
			if in.Name == gateway.ResultNextTool {
				return v.next(args)
			}
			if isInfrastructure(in.Name) {
				return toolError("discovery infrastructure cannot be recursively dispatched"), nil
			}
			args, _ = sanitize.Sanitize(args)
			out, err := v.service.Call(ctx, in.Name, args, map[string]any(r.Params.Meta))
			if err != nil {
				return toolError(err.Error()), nil
			}
			return out, nil
		})
	}
	add("mcp_gateway_status", "Explain effective discovery mode, tool visibility and upstream health. Full lint findings are paged.", schema(map[string]any{"name": stringSchema(), "detail": map[string]any{"type": "string", "enum": []string{"summary", "full"}}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": gateway.MaxStatusLint}, "cursor": stringSchema()}), func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var in struct {
			Name   string  `json:"name"`
			Detail string  `json:"detail"`
			Limit  *int    `json:"limit"`
			Cursor *string `json:"cursor"`
		}
		if decode(r.Params.Arguments, &in) != nil {
			//nolint:nilerr // MCP validation failures are tool results.
			return toolError("invalid status arguments"), nil
		}
		st := v.service.Status(in.Name)
		if in.Detail == "full" {
			limit, cursor := 0, ""
			if in.Limit != nil {
				limit = *in.Limit
				if limit < 1 {
					return toolError("limit must be positive"), nil
				}
			}
			if in.Cursor != nil {
				cursor = *in.Cursor
			}
			p, err := st.Page(limit, cursor)
			if err != nil {
				return toolError(err.Error()), nil
			}
			return result(p), nil
		}
		if in.Detail != "" && in.Detail != "summary" || in.Limit != nil || in.Cursor != nil {
			return toolError("limit and cursor require detail=full"), nil
		}
		if in.Name != "" {
			if isInfrastructure(in.Name) {
				visible := in.Name == "mcp_gateway_status" || in.Name == gateway.ResultNextTool || v.admission.Selection.Mode == gateway.Search
				st.Visible = &visible
				st.Reason = "gateway infrastructure"
			}
			return result(st), nil
		}
		return result(st.Summary()), nil
	})
	add(gateway.ResultNextTool, "Resume a capped read result from this caller's snapshot. Cursors expire after ten minutes.", schema(map[string]any{"cursor": stringSchema()}, "cursor"), func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := object(r.Params.Arguments)
		if err != nil {
			return toolError(err.Error()), nil
		}
		return v.next(args)
	})
}
func (v *view) next(args map[string]any) (*mcp.CallToolResult, error) {
	cursor, ok := args["cursor"].(string)
	if !ok || cursor == "" || len(args) != 1 {
		return toolError("cursor is required"), nil
	}
	out, _, err := v.pager.Next(cursor, gateway.DefaultResultCapBytes)
	if err != nil {
		return toolError(err.Error()), nil
	}
	return out, nil
}
func (v *view) tools() []*mcp.Tool {
	v.catalogMu.Lock()
	defer v.catalogMu.Unlock()
	return append([]*mcp.Tool{}, v.definitions...)
}
func (v *view) refreshTools() {
	v.catalogMu.Lock()
	defer v.catalogMu.Unlock()
	if v.ctx.Err() == nil {
		v.refreshToolsLocked()
	}
}
func (v *view) refreshToolsLocked() {
	// The SDK definitions are a transport index. Dispatch independently resolves
	// the current snapshot, so removing or replacing a declaration cannot retain authority.
	all := v.snapshot()
	raw, _ := json.Marshal(all.Entries)
	digest := sha256.Sum256(raw)
	if v.definitions != nil && digest == v.catalogDigest {
		return
	}
	v.catalogDigest = digest
	for _, name := range v.registered {
		v.server.RemoveTools(name)
	}
	v.registered = nil
	seen := map[string]bool{}
	colliding := map[string]bool{}
	for _, e := range all.Entries {
		if seen[e.Tool.Name] || isInfrastructure(e.Tool.Name) {
			colliding[e.Tool.Name] = true
		}
		seen[e.Tool.Name] = true
	}
	v.definitions = nil
	for _, e := range all.Entries {
		if colliding[e.Tool.Name] {
			continue
		}
		tool := gateway.ClientSafeTool(e.Tool)
		name := tool.Name
		v.server.AddTool(tool, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := object(r.Params.Arguments)
			if err != nil {
				return toolError(err.Error()), nil
			}
			args, _ = sanitize.Sanitize(args)
			out, err := v.service.Call(ctx, name, args, map[string]any(r.Params.Meta))
			if err != nil {
				return toolError(err.Error()), nil
			}
			return out, nil
		})
		v.registered = append(v.registered, name)
		v.definitions = append(v.definitions, tool)
	}
	// Keep infrastructure declarations alongside real tools for ProtocolList.
	v.definitions = append(v.definitions, v.infrastructure...)
}
