package frontend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	"github.com/hollis-labs/mcp-gateway/internal/upstream"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type nativeRepro struct {
	failConnect       atomic.Bool
	afterInventory    func()
	changeFingerprint atomic.Bool
	changeRun         atomic.Bool
	release           chan struct{}
	afterDrop         func()
	events            []Event
	businessError     atomic.Bool
	rejectAfterDrop   atomic.Bool
	h                 *Handler
	backend           *mcp.Server
	outer             *mcp.ClientSession
	endpoint          string
	connects          atomic.Int64
	executions        atomic.Int64
	drop              atomic.Bool
	dropEvery         atomic.Bool
	reject            atomic.Bool
	block             atomic.Bool
	started           chan struct{}
	mu                sync.Mutex
	sessions          map[string]string
}

// This exercises the real authority.Client.Native HTTP transport, admission
// decoder, selectors and signed run headers, rather than a fake ClientSession.
func newNativeRepro(t *testing.T, idle time.Duration, readOnly, idempotent bool) *nativeRepro {
	t.Helper()
	f := &nativeRepro{release: make(chan struct{}), backend: mcp.NewServer(&mcp.Implementation{Name: "native-repro", Version: "1"}, nil), started: make(chan struct{}, 8), sessions: map[string]string{}}
	f.backend.AddTool(&mcp.Tool{Name: "tether_action", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, IdempotentHint: idempotent}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.executions.Add(1)
		if f.businessError.Load() {
			return toolError("session not found"), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil
	})
	f.backend.AddResource(&mcp.Resource{URI: "fixture:///old", Name: "old"}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "fixture:///old", Text: "old"}}}, nil
	})
	runExpiry := time.Now().Add(time.Hour).Unix()
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return f.backend }, &mcp.StreamableHTTPOptions{SessionTimeout: idle, JSONResponse: true})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/admit") && !strings.HasSuffix(r.URL.Path, "/native") {
			http.NotFound(w, r)
			return
		}
		run := r.Header.Get(authority.RunTokenHeader)
		if r.Header.Get("Authorization") != "Bearer caller-token" || (run != "run-first" && run != "run-second") {
			t.Error("authority headers lost")
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		if f.reject.Load() {
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/admit") {
			var selectors authority.Selectors
			if err := json.NewDecoder(r.Body).Decode(&selectors); err != nil {
				t.Error(err)
			}
			if selectors.Profile != "fixture" || selectors.Mode != "flat" {
				t.Error("selectors lost")
			}
			a := authority.Admission{SchemaVersion: 1, Principal: authority.Principal{Verified: true, ID: "principal", Kind: "session", SessionID: "session"}, Policy: (gateway.SessionPolicy{SessionID: "session", Servers: []string{}}).Seal(), MachineAccess: "read-only", Selection: gateway.Selection{Mode: gateway.Flat}, Fingerprint: run, Run: &authority.Run{URN: "msg://agent/test/" + run, Session: "session", RunID: run, JTI: run, Expires: runExpiry}}
			if f.changeFingerprint.Load() {
				a.Fingerprint = "changed"
			}
			if f.changeRun.Load() {
				a.Run.JTI = "changed"
			}
			_ = json.NewEncoder(w).Encode(a)
			return
		}
		if r.URL.Query().Get("profile") != "fixture" || r.URL.Query().Get("discovery_mode") != "flat" {
			t.Error("native selectors lost")
		}
		var raw []byte
		var method string
		if r.Method == http.MethodPost {
			raw, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var rpc struct{ Method string }
			_ = json.Unmarshal(raw, &rpc)
			method = rpc.Method
		}
		if method == "resources/list" && f.connects.Load() > 1 && f.afterInventory != nil {
			f.afterInventory()
		}
		if method == "initialize" {
			f.connects.Add(1)
			if f.failConnect.Load() {
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if f.block.Load() {
				f.started <- struct{}{}
				select {
				case <-r.Context().Done():
					return
				case <-f.release:
				case <-time.After(2 * time.Second):
					return
				}
			}
		}
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			f.mu.Lock()
			prior := f.sessions[id]
			f.mu.Unlock()
			if prior != "" && prior != run {
				t.Error("native session crossed run authority")
			}
		}
		if method == "tools/call" && (f.drop.Swap(false) || f.dropEvery.Load()) {
			// Execute first, then lose the response. The gateway cannot know whether
			// a mutation committed and must not replay it.
			recorder := httptest.NewRecorder()
			sdk.ServeHTTP(recorder, r)
			if f.afterDrop != nil {
				f.afterDrop()
			}
			if f.rejectAfterDrop.Load() {
				f.reject.Store(true)
			}
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		sdk.ServeHTTP(w, r)
		if method == "initialize" {
			f.mu.Lock()
			f.sessions[w.Header().Get("Mcp-Session-Id")] = run
			f.mu.Unlock()
		}
	}))
	t.Cleanup(backend.Close)
	auth := &authority.Client{HTTP: &http.Client{Transport: routeAuthorityTransport{http.DefaultTransport, backend.URL}}}
	runtime, err := upstream.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	f.h, err = New(context.Background(), Options{Authority: auth, Runtime: runtime, IdleTimeout: time.Minute, Observer: f})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.h.Close)
	outer := httptest.NewServer(f.h)
	t.Cleanup(outer.Close)
	f.endpoint = outer.URL + "?profile=fixture&discovery_mode=flat"
	f.outer = f.dial(t, "run-first")
	return f
}
func (f *nativeRepro) dial(t *testing.T, run string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := mcp.NewClient(&mcp.Implementation{Name: "outer", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: f.endpoint, HTTPClient: &http.Client{Transport: runHeaderTransport{http.DefaultTransport, run}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func (f *nativeRepro) native(t *testing.T) *nativeSession {
	t.Helper()
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	for v := range f.h.views {
		v.nativeMu.Lock()
		n := v.native
		v.nativeMu.Unlock()
		return n
	}
	t.Fatal("no view")
	return nil
}
func closeNative(t *testing.T, n *nativeSession) {
	t.Helper()
	if err := n.session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-n.done:
	case <-time.After(3 * time.Second):
		t.Fatal("native did not close")
	}
}
func invokeNative(ctx context.Context, s *mcp.ClientSession) (*mcp.CallToolResult, error) {
	return s.CallTool(ctx, &mcp.CallToolParams{Name: "tether_action", Arguments: map[string]any{}})
}
func assertNativeOK(t *testing.T, s *mcp.ClientSession) {
	t.Helper()
	out, err := invokeNative(context.Background(), s)
	if err != nil || out == nil || out.IsError {
		t.Fatalf("call failed: result=%+v err=%v", out, err)
	}
}

// Artifact 1403's diagnostic is inverted here: outer SID survives actual SDK
// idle eviction, fresh admission reconnects the native session, and writes run
// exactly once per requested call.
func TestNativeIdleEvictionRecovery(t *testing.T) {
	f := newNativeRepro(t, 150*time.Millisecond, false, false)
	assertNativeOK(t, f.outer)
	id := f.outer.ID()
	n := f.native(t)
	select {
	case <-n.done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle eviction not observed")
	}
	assertNativeOK(t, f.outer)
	assertNativeOK(t, f.outer)
	if f.outer.ID() != id || f.connects.Load() != 2 || f.executions.Load() != 3 {
		t.Fatalf("sid preserved=%v connects=%d executions=%d", f.outer.ID() == id, f.connects.Load(), f.executions.Load())
	}
	t.Log("native idle eviction: outer SID unchanged; connects=2; mutation executions=3 for 3 requests")
}
func TestNativeConcurrentRecoveryAndInventory(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	closeNative(t, f.native(t))
	f.backend.RemoveResources("fixture:///old")
	f.backend.AddResource(&mcp.Resource{URI: "fixture:///new", Name: "new"}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "fixture:///new", Text: "new"}}}, nil
	})
	f.backend.AddTool(&mcp.Tool{Name: "tether_new", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return result("new"), nil })
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			out, err := invokeNative(context.Background(), f.outer)
			if err != nil || out == nil || out.IsError {
				t.Errorf("concurrent recovery: %v %+v", err, out)
			}
		})
	}
	wg.Wait()
	if f.connects.Load() != 2 || f.executions.Load() != 24 {
		t.Fatalf("single flight failed: connects=%d executions=%d", f.connects.Load(), f.executions.Load())
	}
	tools, err := f.outer.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "tether_new" {
			found = true
		}
	}
	if !found {
		t.Fatal("new tool missing")
	}
	resources, err := f.outer.ListResources(context.Background(), nil)
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].URI != "fixture:///new" {
		t.Fatalf("stale resources: %+v %v", resources, err)
	}
	r, err := f.outer.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "fixture:///new"})
	if err != nil || r.Contents[0].Text != "new" {
		t.Fatalf("resource not rebound: %+v %v", r, err)
	}
}
func TestNativeUncertainMutationNeverReplayed(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	f.drop.Store(true)
	out, err := invokeNative(context.Background(), f.outer)
	if err == nil && (out == nil || !out.IsError) {
		t.Fatal("uncertain write reported success")
	}
	message := fmt.Sprint(err)
	if out != nil {
		raw, _ := json.Marshal(out)
		message += string(raw)
	}
	if !strings.Contains(message, "uncertain") {
		t.Fatal("lost mutation response did not report uncertain outcome")
	}
	if f.executions.Load() != 1 || f.connects.Load() != 2 {
		t.Fatalf("write replayed or session not repaired: executions=%d connects=%d", f.executions.Load(), f.connects.Load())
	}
	assertNativeOK(t, f.outer)
	if f.executions.Load() != 2 {
		t.Fatal("future write failed")
	}
}
func TestNativeReadRetryBounded(t *testing.T) {
	for _, tc := range []struct {
		name               string
		idempotent, always bool
		want               int64
		success            bool
	}{{"safe read", true, false, 2, true}, {"read without idempotence", false, false, 1, false}, {"retry also loses session", true, true, 2, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNativeRepro(t, 0, true, tc.idempotent)
			f.drop.Store(true)
			f.dropEvery.Store(tc.always)
			out, err := invokeNative(context.Background(), f.outer)
			success := err == nil && out != nil && !out.IsError
			if success != tc.success || f.executions.Load() != tc.want || f.connects.Load() != 2 {
				t.Fatalf("success=%v executions=%d connects=%d err=%v", success, f.executions.Load(), f.connects.Load(), err)
			}
		})
	}
}
func TestNativeRecoveryAuthorityIsolation(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	second := f.dial(t, "run-second")
	f.h.mu.Lock()
	var ns []*nativeSession
	for v := range f.h.views {
		v.nativeMu.Lock()
		ns = append(ns, v.native)
		v.nativeMu.Unlock()
	}
	f.h.mu.Unlock()
	for _, n := range ns {
		closeNative(t, n)
	}
	var wg sync.WaitGroup
	for _, s := range []*mcp.ClientSession{f.outer, second} {
		wg.Go(func() {
			out, err := invokeNative(context.Background(), s)
			if err != nil || out == nil || out.IsError {
				t.Errorf("isolated call failed: %v %+v", err, out)
			}
		})
	}
	wg.Wait()
	if f.connects.Load() != 4 {
		t.Fatalf("cross-view reuse: connects=%d", f.connects.Load())
	}
	f.reject.Store(true)
	out, err := invokeNative(context.Background(), f.outer)
	if err == nil && out != nil && !out.IsError {
		t.Fatal("revoked authority accepted")
	}
	if f.connects.Load() != 4 {
		t.Fatal("revoked authority reconnected")
	}
}
func TestNativeRecoveryCancellationAndTeardown(t *testing.T) {
	for _, teardown := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller cancellation", true: "view teardown"}[teardown], func(t *testing.T) {
			f := newNativeRepro(t, 0, false, false)
			closeNative(t, f.native(t))
			f.block.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { _, _ = invokeNative(ctx, f.outer); close(done) }()
			select {
			case <-f.started:
			case <-time.After(3 * time.Second):
				t.Fatal("recovery did not start")
			}
			f.h.mu.Lock()
			var flight *nativeFlight
			for v := range f.h.views {
				v.nativeMu.Lock()
				flight = v.nativeFlight
				v.nativeMu.Unlock()
			}
			f.h.mu.Unlock()
			if flight == nil {
				t.Fatal("missing recovery flight")
			}
			if teardown {
				f.h.Close()
			} else {
				cancel()
			}
			select {
			case <-flight.done:
			case <-time.After(3 * time.Second):
				t.Fatal("recovery flight did not cancel")
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("recovery did not cancel")
			}
			f.block.Store(false)
			if !teardown {
				assertNativeOK(t, f.outer)
			}
		})
	}
}

func (f *nativeRepro) Record(e Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}
func TestNativeBusinessErrorDoesNotTriggerRecovery(t *testing.T) {
	f := newNativeRepro(t, 0, true, true)
	f.businessError.Store(true)
	out, err := invokeNative(context.Background(), f.outer)
	if err != nil || out == nil || !out.IsError || f.connects.Load() != 1 || f.executions.Load() != 1 {
		t.Fatalf("business error caused recovery: err=%v connects=%d executions=%d", err, f.connects.Load(), f.executions.Load())
	}
}
func TestNativeRecoveryRechecksAuthority(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	f.drop.Store(true)
	f.rejectAfterDrop.Store(true)
	out, err := invokeNative(context.Background(), f.outer)
	if err == nil && out != nil && !out.IsError {
		t.Fatal("refused replacement succeeded")
	}
	if f.connects.Load() != 1 || f.executions.Load() != 1 {
		t.Fatal("refused authority reconnected or replayed write")
	}
	f.mu.Lock()
	var failed bool
	for _, e := range f.events {
		if e.Lifecycle == "native_recovery_failed" {
			failed = true
		}
	}
	f.mu.Unlock()
	if !failed {
		t.Fatal("recovery failure evidence missing")
	}
	f.reject.Store(false)
	f.rejectAfterDrop.Store(false)
	assertNativeOK(t, f.outer)
	if f.connects.Load() != 2 || f.executions.Load() != 2 {
		t.Fatal("subsequent admitted call did not recover")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var recovered bool
	for _, e := range f.events {
		if e.Lifecycle == "native_recovered" && e.Generation == 2 {
			recovered = true
		}
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "run-first") || strings.Contains(string(raw), "caller-token") {
			t.Fatal("lifecycle evidence leaked credentials")
		}
	}
	if !recovered {
		t.Fatal("recovery lifecycle evidence missing")
	}
}

func TestInitializePublishesSessionBeforeResponse(t *testing.T) {
	runtime, err := upstream.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	a := &fixtureAuthority{backend: echoServer("tether_echo"), admission: authority.Admission{SchemaVersion: 1, Principal: authority.Principal{Verified: true, ID: "session", SessionID: "session"}, Fingerprint: "stable", MachineAccess: "read-only", Policy: (gateway.SessionPolicy{SessionID: "session"}).Seal(), Selection: gateway.Selection{Mode: gateway.Flat}}}
	h, err := New(context.Background(), Options{Authority: a, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	release := make(chan struct{})
	defer close(release)
	original := h.sdk
	h.sdk = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original.ServeHTTP(w, r)
		if r.Header.Get("Mcp-Session-Id") == "" {
			<-release
		}
	})
	server := httptest.NewServer(h)
	// Release initialize before closing HTTP, including failure cleanup.
	t.Cleanup(server.Close)
	s := connect(t, server.URL)
	if err := s.Ping(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRetryUsesRefreshedDeclaration(t *testing.T) {
	f := newNativeRepro(t, 0, true, true)
	f.afterDrop = func() {
		f.backend.RemoveTools("tether_action")
		f.backend.AddTool(&mcp.Tool{Name: "tether_action", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.executions.Add(1)
			return result("mutation"), nil
		})
	}
	f.drop.Store(true)
	out, err := invokeNative(context.Background(), f.outer)
	if err == nil && out != nil && !out.IsError {
		t.Fatal("changed tool replayed")
	}
	if f.executions.Load() != 1 || f.connects.Load() != 2 {
		t.Fatal("retry retained stale read-only declaration")
	}
	assertNativeOK(t, f.outer)
	if f.executions.Load() != 2 {
		t.Fatal("explicit future mutation did not execute")
	}
}

func TestNativeRecoveryWaiterCancellation(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	closeNative(t, f.native(t))
	f.block.Store(true)
	done := make(chan error, 1)
	go func() {
		out, err := invokeNative(context.Background(), f.outer)
		if err == nil && (out == nil || out.IsError) {
			err = fmt.Errorf("leader call failed")
		}
		done <- err
	}()
	select {
	case <-f.started:
	case <-time.After(3 * time.Second):
		t.Fatal("leader did not start")
	}
	f.h.mu.Lock()
	var v *view
	for candidate := range f.h.views {
		v = candidate
	}
	f.h.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := v.ensureNative(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter did not cancel: %v", err)
	}
	v.nativeMu.Lock()
	flight := v.nativeFlight
	v.nativeMu.Unlock()
	select {
	case <-flight.done:
		t.Fatal("waiter canceled leader")
	default:
	}
	f.block.Store(false)
	close(f.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("leader did not finish")
	}
	if f.connects.Load() != 2 || f.executions.Load() != 1 {
		t.Fatal("waiter started another flight or replayed")
	}
}

func TestNativeRecoveryWithoutResources(t *testing.T) {
	_, h, s := fixture(t, gateway.Flat, nil)
	h.mu.Lock()
	var n *nativeSession
	for v := range h.views {
		v.nativeMu.Lock()
		n = v.native
		v.nativeMu.Unlock()
	}
	h.mu.Unlock()
	closeNative(t, n)
	out, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "tether_echo", Arguments: map[string]any{}})
	if err != nil || out == nil || out.IsError {
		t.Fatalf("tool-only native recovery failed: %v %+v", err, out)
	}
}

func TestNativeRetryFreshAdmission(t *testing.T) {
	for _, kind := range []string{"revoked", "fingerprint", "run binding"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativeRepro(t, 0, true, true)
			f.afterInventory = func() {
				switch kind {
				case "revoked":
					f.reject.Store(true)
				case "fingerprint":
					f.changeFingerprint.Store(true)
				case "run binding":
					f.changeRun.Store(true)
				}
			}
			f.drop.Store(true)
			out, err := invokeNative(context.Background(), f.outer)
			if err == nil && out != nil && !out.IsError {
				t.Fatal("retry accepted changed authority")
			}
			if f.executions.Load() != 1 || f.connects.Load() != 2 {
				t.Fatalf("retry executed with changed authority: executions=%d connects=%d", f.executions.Load(), f.connects.Load())
			}
		})
	}
}

func TestNativeReplacementRejectsChangedRunBinding(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	closeNative(t, f.native(t))
	f.changeRun.Store(true)
	out, err := invokeNative(context.Background(), f.outer)
	if err == nil && out != nil && !out.IsError {
		t.Fatal("replacement accepted changed run binding")
	}
	if f.executions.Load() != 0 || f.connects.Load() != 1 {
		t.Fatal("replacement used changed run authority")
	}
}

func TestNativeFailedReplacementIsBoundedAndRecoverable(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	id := f.outer.ID()
	closeNative(t, f.native(t))
	f.failConnect.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := invokeNative(ctx, f.outer)
	if err == nil && out != nil && !out.IsError {
		t.Fatal("failed replacement reported success")
	}
	if ctx.Err() != nil {
		t.Fatal("failed replacement did not return promptly")
	}
	if f.connects.Load() != 2 || f.executions.Load() != 0 {
		t.Fatalf("replacement looped or dispatched: connects=%d executions=%d", f.connects.Load(), f.executions.Load())
	}
	f.failConnect.Store(false)
	assertNativeOK(t, f.outer)
	if f.outer.ID() != id || f.connects.Load() != 3 || f.executions.Load() != 1 {
		t.Fatal("failed replacement poisoned future independent call")
	}
}
func TestNativeRecoveryRemovesOldToolBindings(t *testing.T) {
	f := newNativeRepro(t, 0, false, false)
	oldID := f.native(t).session.ID()
	// Force inventory replacement after the SDK transport has registered the
	// original action handler in the outer server.
	closeNative(t, f.native(t))
	f.backend.RemoveTools("tether_action")
	f.backend.AddTool(&mcp.Tool{Name: "tether_replacement", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return result("new handler"), nil
	})
	list, err := f.outer.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range list.Tools {
		if tool.Name == "tether_action" {
			t.Fatal("removed tool still listed")
		}
		if tool.Name == "tether_replacement" {
			found = true
		}
	}
	if !found {
		t.Fatal("replacement tool not listed")
	}
	out, err := invokeNative(context.Background(), f.outer)
	if err == nil && out != nil && !out.IsError {
		t.Fatal("removed tool handler still dispatched")
	}
	if f.executions.Load() != 0 {
		t.Fatal("removed tool executed")
	}
	out, err = f.outer.CallTool(context.Background(), &mcp.CallToolParams{Name: "tether_replacement", Arguments: map[string]any{}})
	if err != nil || out == nil || out.IsError {
		t.Fatal("replacement tool handler not rebound")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		raw, _ := json.Marshal(e)
		for _, secret := range []string{oldID, "caller-token", "run-first", "session not found"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("lifecycle evidence contained native ID, raw error or credentials")
			}
		}
	}
}
