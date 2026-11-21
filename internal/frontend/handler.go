// Package frontend binds every protocol operation to fresh Tether authority.
package frontend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	"github.com/hollis-labs/mcp-gateway/internal/registry"
	"github.com/hollis-labs/mcp-gateway/internal/upstream"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type Authority interface {
	Admit(context.Context, string, authority.Selectors) (authority.Admission, error)
	Native(context.Context, func() string, authority.Selectors) (*mcp.ClientSession, error)
}
type Event struct {
	Lifecycle      string                  `json:"lifecycle,omitempty"`
	Generation     uint64                  `json:"generation,omitempty"`
	At             time.Time               `json:"at"`
	Principal      string                  `json:"principal"`
	Session        string                  `json:"session,omitempty"`
	Tool           string                  `json:"tool"`
	Origin         string                  `json:"origin"`
	DurationMS     int64                   `json:"duration_ms"`
	OK             bool                    `json:"ok"`
	Correlation    registry.Correlation    `json:"correlation"`
	Classification registry.Classification `json:"classification"`
}
type Observer interface{ Record(Event) }
type Options struct {
	Authority         Authority
	Runtime           *upstream.Runtime
	Registry          *registry.Cache
	Observer          Observer
	MaxViews          int
	MaxPrincipalViews int
	IdleTimeout       time.Duration
	// HostGuarded is set only by the composition root after installing hostguard.
	HostGuarded bool
}
type Handler struct {
	opts      Options
	ctx       context.Context
	cancel    context.CancelFunc
	sdk       http.Handler
	mu        sync.Mutex
	views     map[*view]bool
	sessions  map[string]*view
	done      chan struct{}
	requests  sync.WaitGroup
	closed    bool
	closeOnce sync.Once
}
type view struct {
	h                *Handler
	server           *mcp.Server
	nativeMu         sync.Mutex
	native           *nativeSession
	nativeFlight     *nativeFlight
	nativeGeneration uint64
	inventoryMu      sync.RWMutex
	nativeResources  []string
	service          *gateway.Service
	pager            *gateway.ResultPager
	admission        authority.Admission
	selectors        authority.Selectors
	ids              []string
	mu               sync.Mutex
	token            string
	expiry           *time.Time
	expiryTimer      *time.Timer
	last             time.Time
	active           int
	closed           bool
	ready            bool
	ctx              context.Context
	cancel           context.CancelFunc
	unsubscribe      func()
	catalogMu        sync.Mutex
	registered       []string
	nativeTools      []*mcp.Tool
	definitions      []*mcp.Tool
	infrastructure   []*mcp.Tool
	catalogDigest    [32]byte
}
type viewKey struct{}

func New(ctx context.Context, o Options) (*Handler, error) {
	if o.Authority == nil || o.Runtime == nil {
		return nil, fmt.Errorf("authority and runtime are required")
	}
	if o.Registry == nil {
		o.Registry = registry.New("", "")
	}
	if o.MaxViews <= 0 {
		o.MaxViews = 128
	}
	if o.MaxPrincipalViews <= 0 {
		o.MaxPrincipalViews = 16
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 2 * time.Minute
	}
	// #nosec G118 -- Handler.Close owns the returned cancellation function.
	ctx, cancel := context.WithCancel(ctx)
	h := &Handler{opts: o, ctx: ctx, cancel: cancel, views: map[*view]bool{}, sessions: map[string]*view{}, done: make(chan struct{})}
	h.sdk = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		v, _ := r.Context().Value(viewKey{}).(*view)
		if v == nil {
			return nil
		}
		return v.server
	}, &mcp.StreamableHTTPOptions{SessionTimeout: 15 * time.Minute, CrossOriginProtection: http.NewCrossOriginProtection(), DisableLocalhostProtection: o.HostGuarded})
	go h.monitor()
	return h, nil
}
func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.cancel()
		h.mu.Unlock()
		<-h.done
		h.mu.Lock()
		vs := []*view{}
		for v := range h.views {
			vs = append(vs, v)
		}
		h.mu.Unlock()
		for _, v := range vs {
			h.remove(v)
		}
		h.requests.Wait()
	})
}
func selectors(r *http.Request) (authority.Selectors, error) {
	var s authority.Selectors
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return s, fmt.Errorf("invalid selectors")
	}
	for key, target := range map[string]*string{"profile": &s.Profile, "discovery_mode": &s.Mode} {
		values := append([]string{}, query[key]...)
		header := "X-Tether-Profile"
		if key == "discovery_mode" {
			header = "X-Tether-Discovery-Mode"
		}
		values = append(values, r.Header.Values(header)...)
		for _, v := range values {
			if v == "" || (*target != "" && *target != v) {
				return s, fmt.Errorf("invalid selectors")
			}
			*target = v
		}
	}
	return s, nil
}
func token(r *http.Request) (string, error) {
	a := r.Header.Values("Authorization")
	if len(a) != 1 || len(a[0]) > 4096 {
		return "", fmt.Errorf("unauthorized")
	}
	parts := strings.Fields(a[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("unauthorized")
	}
	return parts[1], nil
}
func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}
func authorityFail(w http.ResponseWriter, err error) {
	var e *authority.Error
	if errors.As(err, &e) {
		fail(w, e.Status, e.Code)
	} else {
		fail(w, 503, "identity_unavailable")
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		fail(w, 503, "gateway_stopping")
		return
	}
	h.requests.Add(1)
	h.mu.Unlock()
	defer h.requests.Done()
	if r.Method != http.MethodPost && r.Method != http.MethodGet && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, GET, DELETE")
		fail(w, 405, "method_not_allowed")
		return
	}
	ctx, cancelRequest := context.WithCancel(r.Context())
	stopRequest := context.AfterFunc(h.ctx, cancelRequest)
	defer func() { stopRequest(); cancelRequest() }()
	r = r.WithContext(ctx)
	if h.ctx.Err() != nil {
		fail(w, 503, "gateway_stopping")
		return
	}
	t, err := token(r)
	if err != nil {
		fail(w, 401, "unauthorized")
		return
	}
	s, err := selectors(r)
	if err != nil {
		fail(w, 400, "invalid_mcp_selectors")
		return
	}
	s.RunToken, err = authority.ReadRunToken(r.Header)
	if err != nil {
		fail(w, 401, "unauthorized")
		return
	}
	a, err := h.opts.Authority.Admit(r.Context(), t, s)
	if err != nil {
		authorityFail(w, err)
		return
	}
	if r.Header.Get("Mcp-Session-Id") == "" {
		if r.Method != http.MethodPost {
			fail(w, 400, "mcp_session_required")
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		_ = r.Body.Close()
		if readErr != nil || len(raw) > 1<<20 {
			fail(w, 400, "invalid_initialize")
			return
		}
		var rpc struct {
			Method  string                `json:"method"`
			JSONRPC string                `json:"jsonrpc"`
			ID      json.RawMessage       `json:"id"`
			Params  *mcp.InitializeParams `json:"params"`
		}
		if json.Unmarshal(raw, &rpc) != nil || rpc.Method != "initialize" || rpc.JSONRPC != "2.0" || len(rpc.ID) == 0 || string(rpc.ID) == "null" || rpc.Params == nil || rpc.Params.ProtocolVersion == "" || rpc.Params.ClientInfo == nil || rpc.Params.Capabilities == nil {
			fail(w, 400, "initialize_required")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	id := r.Header.Get("Mcp-Session-Id")
	h.mu.Lock()
	v := h.sessions[id]
	h.mu.Unlock()
	if id != "" && v == nil {
		fail(w, 404, "mcp_session_not_found")
		return
	}
	if v != nil {
		if v.selectors != s || v.admission.Fingerprint != a.Fingerprint {
			h.remove(v)
			fail(w, 401, "mcp_session_authority_changed")
			return
		}
		v.adopt(t, a.Principal.ExpiresAt)
	} else {
		v, err = h.prepare(r.Context(), t, s, a)
		if err != nil {
			fail(w, 503, "mcp_view_unavailable")
			return
		}
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		fail(w, 401, "mcp_session_closed")
		return
	}
	v.last = time.Now()
	if r.Method == http.MethodPost {
		v.active++
	}
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		if r.Method == http.MethodPost {
			v.active--
		}
		v.mu.Unlock()
	}()
	rctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(v.ctx, cancel)
	defer func() { stop(); cancel() }()
	response := &statusWriter{ResponseWriter: w, status: http.StatusOK, onHeader: func(status int) {
		// Publish before initialize's response can be flushed: the client may
		// immediately send initialized or open its standalone stream.
		assigned := w.Header().Get("Mcp-Session-Id")
		if assigned != "" && status < 400 {
			h.mu.Lock()
			if h.views[v] {
				h.sessions[assigned] = v
			}
			h.mu.Unlock()
		}
	}}
	h.sdk.ServeHTTP(response, r.WithContext(context.WithValue(rctx, viewKey{}, v)))
	assigned := w.Header().Get("Mcp-Session-Id")
	if assigned != "" {
		h.mu.Lock()
		if h.views[v] {
			h.sessions[assigned] = v
		}
		h.mu.Unlock()
	}
	if r.Method == http.MethodDelete || (id == "" && (assigned == "" || response.status >= 400)) {
		h.remove(v)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	onHeader    func(int)
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	if w.onHeader != nil {
		w.onHeader(status)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
func (w *statusWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (v *view) bearer() string { v.mu.Lock(); defer v.mu.Unlock(); return v.token }
func (v *view) adopt(token string, expiry *time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.expiry != nil && (expiry == nil || expiry.Before(*v.expiry)) {
		return
	}
	v.token = token
	v.expiry = expiry
	if v.expiryTimer != nil {
		v.expiryTimer.Stop()
	}
	if expiry != nil {
		v.expiryTimer = time.AfterFunc(time.Until(*expiry), func() { v.h.removeView(v, true) })
	}
}
func (h *Handler) prepare(ctx context.Context, t string, s authority.Selectors, a authority.Admission) (*view, error) {
	vctx, cancel := context.WithCancel(h.ctx)
	v := &view{h: h, ctx: vctx, cancel: cancel, admission: a, selectors: s, token: t, expiry: a.Principal.ExpiresAt, last: time.Now(), pager: gateway.NewResultPager()}
	h.mu.Lock()
	if h.closed || h.ctx.Err() != nil {
		h.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("gateway stopping")
	}
	count := 0
	for x := range h.views {
		if x.admission.Principal.ID == a.Principal.ID {
			count++
		}
	}
	if len(h.views) >= h.opts.MaxViews || count >= h.opts.MaxPrincipalViews {
		h.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("view capacity")
	}
	h.views[v] = true
	h.mu.Unlock()
	v.adopt(t, a.Principal.ExpiresAt)
	ok := false
	defer func() {
		if !ok {
			h.remove(v)
		}
	}()
	v.catalogMu.Lock()
	defer v.catalogMu.Unlock()
	ctx, cancelPrepare := context.WithTimeout(ctx, 15*time.Second)
	stopPrepare := context.AfterFunc(v.ctx, cancelPrepare)
	defer func() { stopPrepare(); cancelPrepare() }()
	known := h.opts.Runtime.Known()
	for _, id := range a.Policy.Servers {
		if _, exists := known[id]; !exists {
			known[id] = true
		}
	}
	ids := append([]string{}, a.Policy.Servers...)
	var err error
	for _, floor := range a.AuthorityProfiles {
		ids, err = gateway.SelectOrigins(known, ids, floor.Profile)
		if err != nil {
			return nil, err
		}
	}
	ids, err = gateway.SelectOrigins(known, ids, a.Profile.Profile)
	if err != nil {
		return nil, err
	}
	v.ids = ids
	if err = h.opts.Runtime.Start(ctx, ids); err != nil {
		var collision *gateway.CollisionError
		if !errors.As(err, &collision) {
			return nil, err
		}
	}
	native, err := h.opts.Authority.Native(ctx, v.bearer, s)
	if err != nil {
		return nil, err
	}
	v.native = v.trackNative(native)
	for tool, err := range native.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		v.nativeTools = append(v.nativeTools, tool)
	}
	v.service = &gateway.Service{Selection: a.Selection, Policy: &gateway.Policy{Selection: a.Profile, Floors: a.AuthorityProfiles, ServerOrder: append([]string{"tether"}, ids...)}, Snapshot: v.snapshot, ScoreAll: gateway.BM25ScoreAll, Dispatch: v.dispatch}
	if err = v.service.Policy.ValidateNames(v.snapshot()); err != nil {
		return nil, err
	}
	instructions := ""
	if a.Profile.Profile != nil {
		instructions = a.Profile.Profile.Instructions
	}
	v.server = mcp.NewServer(&mcp.Implementation{Name: "mcp-gateway", Version: "1"}, &mcp.ServerOptions{Instructions: instructions, SupportedProtocolVersions: []string{"2025-11-25"}})
	v.addInfrastructure()
	v.refreshToolsLocked()
	v.server.AddReceivingMiddleware(v.middleware)
	v.unsubscribe = h.opts.Runtime.Subscribe(v.refreshTools)
	// Native resources remain Tether-owned and are checked on every read.
	var resources []*mcp.Resource
	for resource, err := range native.Resources(ctx, nil) {
		if err != nil {
			break
		}
		resources = append(resources, resource)
	}
	v.bindResourcesLocked(resources)
	v.mu.Lock()
	v.ready = true
	v.mu.Unlock()
	ok = true
	return v, nil
}
func (v *view) snapshot() gateway.Snapshot {
	s := v.h.opts.Runtime.Snapshot(v.ids)
	v.inventoryMu.RLock()
	defer v.inventoryMu.RUnlock()
	for _, t := range v.nativeTools {
		s.Entries = append(s.Entries, gateway.Entry{Tool: t, Origin: "tether"})
	}
	s.Origins = append(s.Origins, gateway.OriginStatus{ID: "tether", Status: "connected", ToolCount: len(v.nativeTools), InventoryExamined: true})
	seen := map[string]gateway.Entry{}
	blocked := map[string]bool{}
	for _, e := range s.Entries {
		if prior, ok := seen[e.Tool.Name]; ok {
			blocked[e.Tool.Name] = true
			s.Collisions = append(s.Collisions, gateway.CollidingName(e.Tool.Name, gateway.ToolOwner{Origin: prior.Origin, Name: prior.Tool.Name, Kind: "tool"}, gateway.ToolOwner{Origin: e.Origin, Name: e.Tool.Name, Kind: "tool"}))
		}
		if isInfrastructure(e.Tool.Name) {
			blocked[e.Tool.Name] = true
		}
		seen[e.Tool.Name] = e
	}
	entries := s.Entries[:0]
	for _, e := range s.Entries {
		if !blocked[e.Tool.Name] {
			entries = append(entries, e)
		}
	}
	s.Entries = entries
	return s
}
func (h *Handler) remove(v *view) { h.removeView(v, false) }
func (h *Handler) removeView(v *view, expiredOnly bool) {
	v.mu.Lock()
	if v.closed || (expiredOnly && (v.expiry == nil || time.Now().Before(*v.expiry))) {
		v.mu.Unlock()
		return
	}
	v.closed = true
	if v.expiryTimer != nil {
		v.expiryTimer.Stop()
	}
	v.cancel()
	v.mu.Unlock()
	h.mu.Lock()
	delete(h.views, v)
	for id, x := range h.sessions {
		if x == v {
			delete(h.sessions, id)
		}
	}
	h.mu.Unlock()
	v.catalogMu.Lock()
	defer v.catalogMu.Unlock()
	if v.unsubscribe != nil {
		v.unsubscribe()
	}
	if v.server != nil {
		for session := range v.server.Sessions() {
			_ = session.Close()
		}
	}
	v.nativeMu.Lock()
	native := v.native
	v.nativeMu.Unlock()
	if native != nil {
		_ = native.session.Close()
	}
}

func (h *Handler) monitor() {
	defer close(h.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-tick.C:
			h.mu.Lock()
			vs := []*view{}
			for v := range h.views {
				vs = append(vs, v)
			}
			h.mu.Unlock()
			var checks sync.WaitGroup
			for _, v := range vs {
				checks.Add(1)
				go func() {
					defer checks.Done()
					v.mu.Lock()
					idle := v.active == 0 && time.Since(v.last) > h.opts.IdleTimeout
					ready := v.ready
					v.mu.Unlock()
					if !ready {
						return
					}
					if idle {
						h.remove(v)
						return
					}
					a, err := h.opts.Authority.Admit(h.ctx, v.bearer(), v.selectors)
					if err != nil {
						var e *authority.Error
						if errors.As(err, &e) && e.Temporary() {
							return
						}
						h.remove(v)
					} else if a.Fingerprint != v.admission.Fingerprint {
						h.remove(v)
					}
				}()
			}
			checks.Wait()
		}
	}
}

func (v *view) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if v.ctx.Err() != nil {
			return nil, fmt.Errorf("MCP session closed")
		}
		a, err := v.h.opts.Authority.Admit(ctx, v.bearer(), v.selectors)
		if err != nil {
			return nil, err
		}
		if a.Fingerprint != v.admission.Fingerprint {
			return nil, fmt.Errorf("MCP authority changed")
		}
		if v.selectors.RunToken != "" {
			if a.Run == nil {
				return nil, fmt.Errorf("run verification unavailable")
			}
			ctx = authority.WithVerifiedRunToken(ctx, v.selectors.RunToken, *a.Run)
		}
		ctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(v.ctx, cancel)
		defer func() { stop(); cancel() }()
		if _, err := v.ensureNative(ctx); err != nil {
			return nil, err
		}
		if method == "tools/list" {
			v.refreshTools()
			r, ok := req.(*mcp.ListToolsRequest)
			if !ok {
				return nil, fmt.Errorf("invalid list request")
			}
			cursor := ""
			if r.Params != nil {
				cursor = r.Params.Cursor
			}
			all := v.tools()
			tools, nextCursor, err := v.service.ProtocolList(all, isInfrastructure, cursor)
			if err != nil {
				return nil, err
			}
			ttl := 30000
			if a.Selection.Mode == gateway.Search {
				ttl = 300000
			}
			out := &mcp.ListToolsResult{Tools: tools, NextCursor: nextCursor}
			out.TTLMs = ttl
			out.CacheScope = "private"
			return out, nil
		}
		return next(ctx, method, req)
	}
}

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}
func object(raw []byte) (map[string]any, error) {
	var args map[string]any
	if err := decode(raw, &args); err != nil || args == nil {
		return nil, fmt.Errorf("arguments must be an object")
	}
	return args, nil
}
func toolError(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}
func result(value any) *mcp.CallToolResult {
	raw, err := json.Marshal(value)
	if err != nil {
		return toolError("result encoding failed")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, StructuredContent: value}
}
func isInfrastructure(name string) bool {
	return gateway.IsInfrastructure(name) || name == gateway.ResultNextTool
}

func (v *view) dispatch(ctx context.Context, name string, args, meta map[string]any) (*mcp.CallToolResult, error) {
	e, err := v.service.ResolveTarget(name)
	if err != nil {
		return toolError(err.Error()), nil
	}
	if e.Origin == "cerberus" && v.admission.MachineAccess != "read-write" && !readOnlyMachine(e.Tool) {
		return toolError("machine authority: caller has read-only machine access"), nil
	}
	clean := map[string]any{}
	for k, value := range meta {
		l := strings.ToLower(k)
		if strings.HasPrefix(k, "io.modelcontextprotocol/") || strings.HasPrefix(l, "x-tether-") || strings.HasPrefix(l, "x-forwarded-") || l == "x-run-token" || strings.HasPrefix(l, "tether.") || l == "mcp_gateway.correlation" || strings.HasPrefix(l, "mcp_gateway.caller") {
			continue
		}
		clean[k] = value
	}
	correlation, _ := meta["mcp_gateway.correlation_id"].(string)
	resolved := v.h.opts.Registry.ResolveCorrelation(correlation)
	if resolved.State != "absent" {
		clean["mcp_gateway.correlation"] = resolved
	}
	if resolver, ok := v.h.opts.Authority.(interface {
		CallerContext(context.Context, string) (authority.Attribution, error)
	}); ok {
		if a, lookupErr := resolver.CallerContext(ctx, v.bearer()); lookupErr == nil && a.Matches(v.admission.Principal) {
			ctx = authority.WithAttribution(ctx, a)
			clean["tether.context"] = a
		}
	}
	start := time.Now()
	var out *mcp.CallToolResult
	if e.Origin == "tether" {
		out, err = v.callNative(ctx, e.Tool, &mcp.CallToolParams{Name: name, Arguments: args, Meta: mcp.Meta(clean)})
	} else {
		out, err = v.h.opts.Runtime.Call(ctx, name, args, clean)
	}
	if v.h.opts.Observer != nil {
		v.h.opts.Observer.Record(Event{At: start.UTC(), Principal: v.admission.Principal.ID, Session: v.admission.Principal.SessionID, Tool: name, Origin: e.Origin, DurationMS: time.Since(start).Milliseconds(), OK: err == nil && out != nil && !out.IsError, Correlation: resolved, Classification: v.h.opts.Registry.Classify(e.Origin, e.Tool)})
	}
	if err != nil {
		return nil, err
	}
	if out == nil {
		return toolError("upstream returned no result"), nil
	}
	var resultCap *gateway.ResultCap
	if v.admission.Profile.Profile != nil {
		resultCap = v.admission.Profile.Profile.ResultCap
	}
	out, _ = v.pager.Cap(name, e.Tool.Annotations != nil && e.Tool.Annotations.ReadOnlyHint, out, resultCap.For(name, gateway.DefaultMaxResultBytes))
	return out, nil
}
func readOnlyMachine(t *mcp.Tool) bool {
	if t.Annotations != nil && t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
		return false
	}
	name := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(t.Name), "cerberus_"), "cerberus.")
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
	if len(parts) == 0 {
		return false
	}
	writes := []string{"exec", "run", "delete", "remove", "apply", "fix", "install", "enroll", "restart", "write", "set", "create", "update", "and", "then"}
	for _, p := range parts {
		if slices.Contains(writes, p) {
			return false
		}
	}
	if t.Annotations != nil && t.Annotations.ReadOnlyHint {
		return true
	}
	reads := []string{"list", "get", "show", "describe", "status", "read", "search", "health", "whoami", "inspect", "info", "check", "history", "audit", "ls", "find", "query"}
	return slices.Contains(reads, parts[0]) || slices.Contains(reads, parts[len(parts)-1])
}
