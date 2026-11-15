package frontend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/config"
	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	"github.com/hollis-labs/mcp-gateway/internal/upstream"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type fixtureAuthority struct {
	mu          sync.Mutex
	admission   authority.Admission
	refused     bool
	outage      bool
	waitStarted chan struct{}
	backend     *mcp.Server
}

func (a *fixtureAuthority) Admit(_ context.Context, token string, _ authority.Selectors) (authority.Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.outage {
		return authority.Admission{}, &authority.Error{Status: 503, Code: "identity_unavailable"}
	}
	if token != "caller-token" || a.refused {
		return authority.Admission{}, &authority.Error{Status: 401, Code: "unauthorized"}
	}
	return a.admission, nil
}
func (a *fixtureAuthority) Native(ctx context.Context, _ func() string, _ authority.Selectors) (*mcp.ClientSession, error) {
	x, y := mcp.NewInMemoryTransports()
	if _, err := a.backend.Connect(ctx, x, nil); err != nil {
		return nil, err
	}
	return mcp.NewClient(&mcp.Implementation{Name: "fixture", Version: "1"}, nil).Connect(ctx, y, nil)
}

type tokenTransport struct{ base http.RoundTripper }

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer caller-token")
	return t.base.RoundTrip(r)
}

func echoServer(name string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	s.AddTool(&mcp.Tool{Name: name, Description: "Echo raw JSON", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(r.Params.Arguments)}}}, nil
	})
	return s
}
func connect(t *testing.T, endpoint string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &http.Client{Transport: tokenTransport{http.DefaultTransport}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func fixture(t *testing.T, mode gateway.Mode, profile *gateway.Profile) (*fixtureAuthority, *Handler, *mcp.ClientSession) {
	return fixtureExpiry(t, mode, profile, nil)
}
func fixtureExpiry(t *testing.T, mode gateway.Mode, profile *gateway.Profile, expiry *time.Time) (*fixtureAuthority, *Handler, *mcp.ClientSession) {
	t.Helper()
	native := echoServer("tether_echo")
	waitStarted := make(chan struct{})
	var once sync.Once
	native.AddTool(&mcp.Tool{Name: "tether_wait", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		once.Do(func() { close(waitStarted) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	external := echoServer("other_echo")
	external.AddTool(&mcp.Tool{Name: "other_wait", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		once.Do(func() { close(waitStarted) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	origin := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return external }, nil))
	t.Cleanup(origin.Close)
	runtime, err := upstream.New([]config.MCPServerEntry{{ID: "other", Transport: "http", URL: origin.URL, AllowUnconfinedRemote: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	a := &fixtureAuthority{backend: native, waitStarted: waitStarted, admission: authority.Admission{SchemaVersion: 1, Principal: authority.Principal{Verified: true, ID: "session-fixture", Kind: "session", SessionID: "fixture", ExpiresAt: expiry}, Fingerprint: "stable", MachineAccess: "read-only", Policy: (gateway.SessionPolicy{SessionID: "fixture", Servers: []string{"other"}}).Seal(), Selection: gateway.Selection{Mode: mode, Source: "fixture"}, Profile: gateway.ProfileSelection{Profile: profile}}}
	h, err := New(context.Background(), Options{Authority: a, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return a, h, connect(t, srv.URL)
}

func TestNumericArgumentsSurviveBothRoutes(t *testing.T) {
	for _, mode := range []gateway.Mode{gateway.Flat, gateway.Search} {
		t.Run(string(mode), func(t *testing.T) {
			_, _, s := fixture(t, mode, nil)
			for _, name := range []string{"tether_echo", "other_echo"} {
				input := json.RawMessage(`{"large":9007199254740993,"tiny":1e-400,"nested":[9007199254740993]}`)
				target := name
				if mode == gateway.Search {
					input = json.RawMessage(`{"name":"` + name + `","arguments":` + string(input) + `}`)
					target = "mcp_gateway_tool_call"
				}
				out, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: target, Arguments: input})
				if err != nil {
					t.Fatal(err)
				}
				if out.IsError {
					t.Fatalf("%s error: %+v", name, out.Content)
				}
				text := out.Content[0].(*mcp.TextContent).Text
				if !strings.Contains(text, "9007199254740993") || !strings.Contains(text, "1e-400") {
					t.Fatalf("%s rounded: %s", name, text)
				}
			}
		})
	}
}
func TestNativeToolsIndependentOfUpstreamServerRestriction(t *testing.T) {
	_, _, s := fixture(t, gateway.Flat, nil)
	out, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range out.Tools {
		found = found || tool.Name == "tether_echo"
	}
	if !found {
		t.Fatal("native tool was removed by upstream-only server restriction")
	}
	_, _, denied := fixture(t, gateway.Flat, &gateway.Profile{Servers: []string{}})
	res, err := denied.CallTool(context.Background(), &mcp.CallToolParams{Name: "tether_echo", Arguments: map[string]any{}})
	if err == nil && !res.IsError {
		t.Fatal("empty profile server list allowed native call")
	}
}
func TestRevocationDeniesExistingSession(t *testing.T) {
	a, _, s := fixture(t, gateway.Search, nil)
	a.mu.Lock()
	a.refused = true
	a.mu.Unlock()
	if _, err := s.ListTools(context.Background(), nil); err == nil {
		t.Fatal("revoked session kept listing")
	}
	if _, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "mcp_gateway_tool_call", Arguments: map[string]any{"name": "other_echo", "arguments": map[string]any{}}}); err == nil {
		t.Fatal("revoked session kept calling")
	}
}
func TestSelectorsCannotConflict(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/mcp?profile=one", nil)
	r.Header.Set("X-Tether-Profile", "two")
	if _, err := selectors(r); err == nil {
		t.Fatal("conflicting selectors accepted")
	}
}

func TestKnownExpiryCancelsExternalCallDuringAuthorityOutage(t *testing.T) {
	expiry := time.Now().Add(1200 * time.Millisecond)
	a, _, s := fixtureExpiry(t, gateway.Flat, nil, &expiry)
	done := make(chan error, 1)
	go func() {
		_, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "other_wait", Arguments: map[string]any{}})
		done <- err
	}()
	select {
	case <-a.waitStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("call did not start")
	}
	a.mu.Lock()
	a.outage = true
	a.mu.Unlock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("known expiry did not cancel in-flight external call during outage")
	}
}

func TestRefreshReplacesExpiryTimerWithoutRegressing(t *testing.T) {
	expiry := time.Now().Add(500 * time.Millisecond)
	a, h, s := fixtureExpiry(t, gateway.Flat, nil, &expiry)
	extended := time.Now().Add(4 * time.Second)
	a.mu.Lock()
	a.admission.Principal.ExpiresAt = &extended
	a.mu.Unlock()
	if err := s.Ping(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	var v *view
	for item := range h.views {
		v = item
	}
	h.mu.Unlock()
	if v == nil {
		t.Fatal("missing initialized view")
	}
	v.adopt("older-token", &expiry)
	select {
	case <-v.ctx.Done():
		t.Fatal("view closed before old expiry")
	case <-time.After(700 * time.Millisecond):
	}
	if err := s.Ping(context.Background(), nil); err != nil {
		t.Fatalf("old timer closed refreshed view: %v", err)
	}
	if v.bearer() != "caller-token" {
		t.Fatal("older expiry replaced refreshed bearer")
	}
}

func TestMalformedInitializationAndWrongMethodDoNotConsumeViewCapacity(t *testing.T) {
	_, h, s := fixture(t, gateway.Flat, nil)
	_ = s.Close()
	h.opts.MaxViews = 1
	server := httptest.NewServer(h)
	defer server.Close()
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodPost} {
		request, _ := http.NewRequest(method, server.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		request.Header.Set("Authorization", "Bearer caller-token")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("malformed operation accepted")
		}
	}
	// A real initialization still fits the one-view quota.
	connected := connect(t, server.URL)
	defer connected.Close()
	if err := connected.Ping(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

type blockedAuthority struct {
	started chan struct{}
	once    sync.Once
}

func (b *blockedAuthority) Admit(ctx context.Context, _ string, _ authority.Selectors) (authority.Admission, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return authority.Admission{}, ctx.Err()
}
func (b *blockedAuthority) Native(context.Context, func() string, authority.Selectors) (*mcp.ClientSession, error) {
	return nil, context.Canceled
}

func TestShutdownCancelsAdmissionAndCannotCreateLateView(t *testing.T) {
	runtime, err := upstream.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	a := &blockedAuthority{started: make(chan struct{})}
	h, err := New(context.Background(), Options{Authority: a, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	request.Header.Set("Authorization", "Bearer caller-token")
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(response, request) }()
	<-a.started
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not cancel admission")
	}
	<-done
	next := httptest.NewRecorder()
	h.ServeHTTP(next, request)
	if next.Code != http.StatusServiceUnavailable {
		t.Fatal("closed handler admitted new work")
	}
}
