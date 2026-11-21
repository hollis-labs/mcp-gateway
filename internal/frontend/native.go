package frontend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/authority"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// A generation belongs to exactly one admitted caller view. No session or
// recovery flight is shared with another bearer, selector, or run proof.
type nativeSession struct {
	session    *mcp.ClientSession
	done       chan struct{}
	failed     bool // guarded by nativeMu
	generation uint64
}
type nativeFlight struct {
	done chan struct{}
	err  error
}

func (v *view) nativeEvent(kind string, generation uint64, ok bool) {
	if v.h.opts.Observer != nil {
		v.h.opts.Observer.Record(Event{At: time.Now().UTC(), Principal: v.admission.Principal.ID, Session: v.admission.Principal.SessionID, Origin: "tether", Lifecycle: kind, Generation: generation, OK: ok})
	}
}
func (v *view) trackNative(s *mcp.ClientSession) *nativeSession {
	v.nativeMu.Lock()
	v.nativeGeneration++
	n := &nativeSession{session: s, done: make(chan struct{}), generation: v.nativeGeneration}
	v.nativeMu.Unlock()
	v.nativeEvent("native_connected", n.generation, true)
	go func() {
		_ = s.Wait()
		close(n.done)
		v.nativeEvent("native_closed", n.generation, false)
	}()
	return n
}
func nativeDone(n *nativeSession) bool {
	select {
	case <-n.done:
		return true
	default:
		return false
	}
}

// ensureNative permits one bounded replacement at a time. Waiters can cancel
// independently; teardown cancels the leader as well. Failed flights are not
// cached, so a subsequent freshly admitted operation may recover.
func (v *view) ensureNative(ctx context.Context) (*nativeSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.nativeMu.Lock()
	if v.ctx.Err() != nil {
		v.nativeMu.Unlock()
		return nil, fmt.Errorf("MCP session closed")
	}
	if f := v.nativeFlight; f != nil {
		v.nativeMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-v.ctx.Done():
			return nil, fmt.Errorf("MCP session closed")
		case <-f.done:
			if f.err != nil {
				return nil, f.err
			}
			v.nativeMu.Lock()
			n := v.native
			v.nativeMu.Unlock()
			return n, nil
		}
	}
	old := v.native
	if old != nil && !old.failed && !nativeDone(old) {
		v.nativeMu.Unlock()
		return old, nil
	}
	f := &nativeFlight{done: make(chan struct{})}
	v.nativeFlight = f
	v.nativeMu.Unlock()

	err := v.replaceNative(ctx, old)
	v.nativeMu.Lock()
	f.err = err
	v.nativeFlight = nil
	n := v.native
	close(f.done)
	v.nativeMu.Unlock()
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (v *view) replaceNative(ctx context.Context, old *nativeSession) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	stop := context.AfterFunc(v.ctx, cancel)
	defer func() { stop(); cancel() }()
	generation := uint64(0)
	if old != nil {
		generation = old.generation
	}
	v.nativeEvent("native_recovery_started", generation, false)
	defer func() {
		if resultErr != nil {
			v.nativeEvent("native_recovery_failed", generation, false)
		}
	}()
	// Native's transport obtains the latest bearer from this same view, and the
	// immutable selectors carry its original run token. Recheck admission before
	// connecting, even when the triggering operation already passed middleware.
	var err error
	ctx, err = v.admitNative(ctx)
	if err != nil {
		return err
	}
	s, err := v.h.opts.Authority.Native(ctx, v.bearer, v.selectors)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = s.Close()
		}
	}()
	var tools []*mcp.Tool
	for tool, err := range s.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		tools = append(tools, tool)
	}
	var resources []*mcp.Resource
	for resource, err := range s.Resources(ctx, nil) {
		if err != nil {
			return err
		}
		resources = append(resources, resource)
	}
	// Publish inventory and transport together, ahead of releasing the flight.
	// catalogMu also serializes against view teardown and upstream refreshes.
	v.catalogMu.Lock()
	defer v.catalogMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	v.inventoryMu.Lock()
	v.nativeTools = tools
	v.inventoryMu.Unlock()
	v.bindResourcesLocked(resources)
	v.refreshToolsLocked()
	n := v.trackNative(s)
	v.nativeMu.Lock()
	v.native = n
	v.nativeMu.Unlock()
	committed = true
	if old != nil {
		_ = old.session.Close()
	}
	v.nativeEvent("native_recovered", n.generation, true)
	return nil
}

func (v *view) invalidateNative(n *nativeSession, err error) bool {
	if err == nil {
		return false
	}
	v.nativeMu.Lock()
	defer v.nativeMu.Unlock()
	// Use the SDK's typed transport signal, never tool error text (which can be
	// business data). A completed Wait also proves this client cannot be reused.
	if !errors.Is(err, mcp.ErrSessionMissing) && !errors.Is(err, mcp.ErrConnectionClosed) && !nativeDone(n) {
		return false
	}
	n.failed = true
	return true
}
func (v *view) callNative(ctx context.Context, tool *mcp.Tool, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	n, err := v.ensureNative(ctx)
	if err != nil {
		return nil, err
	}
	out, err := n.session.CallTool(ctx, params)
	if !v.invalidateNative(n, err) {
		return out, err
	}
	// Repair for future operations, but never replay a possibly executed write.
	// Require both read-only and idempotent declarations for automatic replay.
	replacement, recoveryErr := v.ensureNative(ctx)
	if recoveryErr != nil {
		return nil, fmt.Errorf("native session lost; operation outcome uncertain and was not retried; recovery failed: %w", recoveryErr)
	}
	if !retryableNativeTool(tool) {
		return nil, fmt.Errorf("native session lost; operation outcome uncertain and was not retried")
	}
	// Resolve again after refreshed inventory: removed or newly mutating tools
	// must not retain the old declaration's permission to retry.
	target, resolveErr := v.service.ResolveTarget(params.Name)
	if resolveErr != nil || target.Origin != "tether" || !retryableNativeTool(target.Tool) {
		return nil, fmt.Errorf("native tool changed during recovery; operation was not retried")
	}
	ctx, err = v.admitNative(ctx)
	if err != nil {
		return nil, err
	}
	out, err = replacement.session.CallTool(ctx, params)
	v.invalidateNative(replacement, err)
	return out, err
}

// Admission is never inferred from a cached generation. In particular, a
// waiter may join a replacement admitted on behalf of another concurrent
// operation, so replay requires its own fresh check and verified run context.
func (v *view) admitNative(ctx context.Context) (context.Context, error) {
	a, err := v.h.opts.Authority.Admit(ctx, v.bearer(), v.selectors)
	if err != nil {
		return ctx, err
	}
	if a.Fingerprint != v.admission.Fingerprint || a.Principal.ID != v.admission.Principal.ID || a.Principal.SessionID != v.admission.Principal.SessionID {
		return ctx, fmt.Errorf("MCP authority changed")
	}
	if v.selectors.RunToken != "" {
		prior := v.admission.Run
		run := a.Run
		if prior == nil || run == nil || *run != *prior || run.Expires <= time.Now().Unix() {
			return ctx, fmt.Errorf("MCP run authority changed")
		}
		ctx = authority.WithVerifiedRunToken(ctx, v.selectors.RunToken, *run)
	}
	return ctx, nil
}

func retryableNativeTool(tool *mcp.Tool) bool {
	a := tool.Annotations
	return a != nil && a.ReadOnlyHint && a.IdempotentHint && (a.DestructiveHint == nil || !*a.DestructiveHint)
}

func (v *view) bindResourcesLocked(resources []*mcp.Resource) {
	for _, uri := range v.nativeResources {
		v.server.RemoveResources(uri)
	}
	v.nativeResources = nil
	for _, resource := range resources {
		v.nativeResources = append(v.nativeResources, resource.URI)
		v.server.AddResource(resource, func(ctx context.Context, r *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			n, err := v.ensureNative(ctx)
			if err != nil {
				return nil, err
			}
			out, err := n.session.ReadResource(ctx, r.Params)
			if !v.invalidateNative(n, err) {
				return out, err
			}
			n, err = v.ensureNative(ctx)
			if err != nil {
				return nil, err
			}
			ctx, err = v.admitNative(ctx)
			if err != nil {
				return nil, err
			}
			out, err = n.session.ReadResource(ctx, r.Params)
			v.invalidateNative(n, err)
			return out, err
		})
	}
}
