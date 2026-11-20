package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hollis-labs/libs/security/secrets/redact"
	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/config"
	gateway "github.com/hollis-labs/mcp-gateway/internal/gateway"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Runtime is the only owner of upstream processes and connections. Views
// retain no lifecycle authority over it.
type Runtime struct {
	pool     *ClientPool
	registry *ToolRegistry
	known    map[string]bool
	tags     map[string][]string
	mu       sync.Mutex
	next     uint64
	subs     map[uint64]func()
	done     chan struct{}
}

func New(entries []config.MCPServerEntry, protected []string) (*Runtime, error) {
	r := &Runtime{registry: NewToolRegistry(), known: map[string]bool{}, tags: map[string][]string{}, subs: map[uint64]func(){}}
	paths := []string{}
	for _, p := range protected {
		if !filepath.IsAbs(p) || p == string(filepath.Separator) {
			return nil, fmt.Errorf("protected paths must be absolute directories")
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, fmt.Errorf("protected directory unavailable")
		}
		st, err := os.Stat(resolved)
		if err != nil || !st.IsDir() {
			return nil, fmt.Errorf("protected directory unavailable")
		}
		paths = append(paths, resolved)
	}
	private := append([]config.MCPServerEntry{}, entries...)
	for i, e := range private {
		if e.ID == "" || e.ID == "tether" {
			return nil, fmt.Errorf("empty or reserved upstream id")
		}
		if _, ok := r.known[e.ID]; ok {
			return nil, fmt.Errorf("duplicate upstream id")
		}
		if e.ForwardRunToken && e.Transport != "http" && e.Transport != "sse" {
			return nil, fmt.Errorf("forward_run_token requires HTTP/SSE")
		}
		if e.IsEnabled() && e.Transport == "stdio" && len(paths) == 0 {
			return nil, fmt.Errorf("stdio upstreams require protected control-plane directories")
		}
		if e.ProxyServiceTokenFile != "" {
			if e.Token != "" || (e.Transport != "http" && e.Transport != "sse") {
				return nil, fmt.Errorf("service credential requires HTTP/SSE without token")
			}
			token, err := config.ReadBearerFile(e.ProxyServiceTokenFile)
			if err != nil {
				return nil, err
			}
			private[i].Token = token
		}
		r.known[e.ID] = e.IsEnabled()
		r.tags[e.ID] = append([]string{}, e.Tags...)
	}
	r.pool = NewClientPool(private, r.registry)
	// The owner lifetime is independent of the first caller that triggers startup.
	r.pool.lazyCtx, r.pool.cancel = context.WithCancel(context.Background())
	r.pool.lazyReady = map[string]chan struct{}{}
	r.pool.requireConfinement = true
	r.pool.confineRemote = true
	r.pool.protectedPaths = paths
	r.pool.remoteHTTPClientFactory = func(e config.MCPServerEntry) (func(map[string]string, int) *http.Client, error) {
		u, err := url.Parse(e.URL)
		if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid upstream HTTP endpoint")
		}
		return func(headers map[string]string, seconds int) *http.Client {
			base := http.DefaultTransport
			if e.Transport == "sse" {
				base = &sseLifetimeTransport{base: base}
			}
			return &http.Client{Transport: &originTransport{base: base, origin: u, headers: headers, forwardAttribution: e.ProxyServiceTokenFile != "", forwardRunToken: e.ForwardRunToken}, Timeout: time.Duration(seconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		}, nil
	}
	r.pool.SetToolRefreshHandler(func(ToolRefreshResult) {
		r.mu.Lock()
		callbacks := []func(){}
		for _, f := range r.subs {
			callbacks = append(callbacks, f)
		}
		r.mu.Unlock()
		for _, f := range callbacks {
			f()
		}
	})
	r.done = make(chan struct{})
	go r.refreshLoop()
	return r, nil
}

func (r *Runtime) Start(ctx context.Context, ids []string) error {
	return r.pool.startOrigins(ctx, ids)
}
func (r *Runtime) Close() { r.pool.Shutdown(); <-r.done }
func (r *Runtime) refreshLoop() {
	defer close(r.done)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-r.pool.lazyCtx.Done():
			return
		case <-tick.C:
			ctx, cancel := context.WithTimeout(r.pool.lazyCtx, 15*time.Second)
			_, _ = r.pool.RefreshAll(ctx)
			cancel()
		}
	}
}
func (r *Runtime) Known() map[string]bool {
	out := map[string]bool{"tether": true}
	for k, v := range r.known {
		out[k] = v
	}
	return out
}
func (r *Runtime) Subscribe(f func()) func() {
	r.mu.Lock()
	r.next++
	id := r.next
	r.subs[id] = f
	r.mu.Unlock()
	return func() { r.mu.Lock(); delete(r.subs, id); r.mu.Unlock() }
}

// Snapshot filters all diagnostic dimensions with the same authority set.
func (r *Runtime) Snapshot(ids []string) gateway.Snapshot {
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	s := gateway.Snapshot{Entries: []gateway.Entry{}, Origins: []gateway.OriginStatus{}}
	for _, st := range r.pool.StatusSummary() {
		if allowed[st.ID] {
			s.Origins = append(s.Origins, gateway.OriginStatus{ID: st.ID, Status: st.Status, Degraded: st.Degraded, ToolCount: st.CatalogedTools, InventoryExamined: st.InventoryExamined, Error: st.Error})
			if st.Status != "connected" {
				r.pool.Retry(st.ID)
			}
		}
	}
	for _, id := range ids {
		if _, known := r.known[id]; !known && id != "tether" {
			s.Origins = append(s.Origins, gateway.OriginStatus{ID: id, Status: "pending_restart", Error: "upstream is not in this gateway runtime configuration"})
		}
	}
	for _, tool := range r.registry.AllDefinitions() {
		entry, ok := r.registry.Lookup(tool.Name)
		if ok && allowed[entry.ServerID] {
			s.Entries = append(s.Entries, gateway.Entry{Tool: tool, Origin: entry.ServerID, Tags: r.tags[entry.ServerID]})
		}
	}
	lint, collisions := r.registry.NameDiagnostics()
	for _, v := range lint {
		if allowed[v.Origin] {
			s.Lint = append(s.Lint, v)
		}
	}
	for _, v := range collisions {
		visible := true
		for _, owner := range v.Owners {
			if !allowed[owner.Origin] {
				visible = false
			}
		}
		if visible {
			s.Collisions = append(s.Collisions, v)
		} else {
			for i := range s.Origins {
				for _, owner := range v.Owners {
					if s.Origins[i].ID == owner.Origin {
						s.Origins[i].Error = "tool name collision; other owner outside this view"
					}
				}
			}
		}
	}
	sort.Slice(s.Origins, func(i, j int) bool { return s.Origins[i].ID < s.Origins[j].ID })
	return s
}

func (r *Runtime) Call(ctx context.Context, name string, args, meta map[string]any) (*mcp.CallToolResult, error) {
	entry, ok := r.registry.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown upstream tool")
	}
	if entry.Client == nil {
		return nil, fmt.Errorf("upstream unavailable; request was not sent")
	}
	if err := r.pool.unavailableError(entry.ServerID, entry.Client); err != nil {
		r.pool.Retry(entry.ServerID)
		return nil, err
	}
	runToken := authority.VerifiedRunToken(ctx)
	result, err := entry.Client.CallTool(ctx, &mcp.CallToolParams{Name: entry.UpstreamName, Arguments: args, Meta: mcp.Meta(meta)})
	if err != nil {
		scrubbed := err
		for _, configured := range r.pool.entries {
			if configured.ID == entry.ServerID {
				scrubbed = r.pool.redactError(err, configured)
				break
			}
		}
		text := scrubbed.Error()
		if runToken != "" {
			text = strings.ReplaceAll(text, runToken, "[redacted]")
		}
		return nil, &redactedError{text: proxyRedactionSet(r.pool.entries).Redact("upstream call failed; execution outcome may be unknown; request was not replayed: " + text), err: err}
	}
	return scrubServiceToolResult(result, runToken)
}

type originTransport struct {
	base               http.RoundTripper
	origin             *url.URL
	headers            map[string]string
	forwardAttribution bool
	forwardRunToken    bool
}

func (t *originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.origin.Scheme || !strings.EqualFold(req.URL.Host, t.origin.Host) {
		return nil, fmt.Errorf("upstream credential transport refused another origin")
	}
	out := req.Clone(req.Context())
	for k := range out.Header {
		low := strings.ToLower(k)
		if low == "authorization" || low == "x-run-token" || strings.HasPrefix(low, "x-tether-") || strings.HasPrefix(low, "x-forwarded-") {
			delete(out.Header, k)
		}
	}
	for k, v := range t.headers {
		if !strings.EqualFold(k, authority.RunTokenHeader) {
			out.Header.Set(k, v)
		}
	}
	call, _ := req.Context().Value(forwardedToolCallKey{}).(bool)
	if a, ok := authority.FromContext(req.Context()); ok && call && t.forwardAttribution && req.Method == http.MethodPost {
		for k, v := range map[string]string{"X-Forwarded-User-Id": "session:" + a.SessionID, "X-Tether-Session-Id": a.SessionID, "X-Tether-Agent-Urn": a.AgentURN, "X-Tether-Workstream-Id": a.WorkstreamID, "X-Tether-Launch-Id": a.LaunchID, "X-Tether-Project-Id": a.ProjectID, "X-Tether-Logical-Agent-Id": a.LogicalAgentID, "X-Tether-Continues-Session-Id": a.ContinuesSessionID} {
			if v != "" {
				out.Header.Set(k, v)
			}
		}
	}
	if call && t.forwardRunToken && req.Method == http.MethodPost {
		run := authority.VerifiedRun(req.Context())
		if token := authority.VerifiedRunToken(req.Context()); token != "" && run.URN != "" && run.Session != "" {
			out.Header.Set(authority.RunTokenHeader, token)
			// Bind token-bearing headers to signed claims, independently of optional
			// observation attribution. Session-only callers may have no AgentURN.
			out.Header.Set("X-Tether-Agent-Urn", run.URN)
			out.Header.Set("X-Tether-Session-Id", run.Session)
			out.Header.Set("X-Forwarded-User-Id", "session:"+run.Session)
		}
	}
	return t.base.RoundTrip(out)
}

type forwardedToolCallKey struct{}

func withForwardedToolCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, forwardedToolCallKey{}, true)
}
func proxyRedactionSet(entries []config.MCPServerEntry) *redact.Set {
	r := &redact.Set{}
	for _, e := range entries {
		r.Add(stderrRedactionValues(e)...)
	}
	return r
}
func scrubServiceToolResult(result *mcp.CallToolResult, secret string) (*mcp.CallToolResult, error) {
	if secret == "" || result == nil {
		return result, nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("upstream result could not be scrubbed")
	}
	quoted, _ := json.Marshal(secret)
	fragment := string(quoted[1 : len(quoted)-1])
	raw = []byte(strings.ReplaceAll(string(raw), fragment, "[redacted]"))
	var out mcp.CallToolResult
	if json.Unmarshal(raw, &out) != nil {
		return nil, fmt.Errorf("upstream result could not be scrubbed")
	}
	return &out, nil
}
