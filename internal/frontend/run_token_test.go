package frontend

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

type runHeaderTransport struct {
	base  http.RoundTripper
	token string
}

func (t runHeaderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer caller-token")
	if t.token != "" {
		r.Header.Set(authority.RunTokenHeader, t.token)
	}
	return t.base.RoundTrip(r)
}

// routeAuthorityTransport keeps real admission HTTP decoding/validation in the
// test while substituting only the Tether UDS dialer.
type routeAuthorityTransport struct {
	base     http.RoundTripper
	endpoint string
}

func (t routeAuthorityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme = "http"
	r.URL.Host = strings.TrimPrefix(t.endpoint, "http://")
	return t.base.RoundTrip(r)
}

func TestVerifiedRunTokenEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		opt       bool
		transport string
	}{{true, "http"}, {false, "http"}, {true, "sse"}, {false, "sse"}} {
		opt := tc.opt
		t.Run(tc.transport+map[bool]string{true: " opted in", false: " default off"}[opt], func(t *testing.T) {
			const signed = "synthetic-run-secret"
			const otherSigned = "synthetic-run-other"
			var mu sync.Mutex
			var observed []string
			leaf := echoServer("other_echo")
			leaf.AddTool(&mcp.Tool{Name: "other_leak", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				raw, _ := json.Marshal(r.Params.Meta)
				if strings.Contains(string(raw), signed) || strings.Contains(string(raw), "spoofed-run") {
					t.Error("raw token leaked into MCP metadata")
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: signed}}, StructuredContent: map[string]any{"echo": signed}}, nil
			})
			var leafHandler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return leaf }, nil)
			if tc.transport == "sse" {
				leafHandler = mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return leaf }, nil)
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					raw, readErr := io.ReadAll(r.Body)
					if readErr != nil {
						t.Error(readErr)
					}
					r.Body = io.NopCloser(bytes.NewReader(raw))
					var rpc struct {
						Method string
						Params struct{ Arguments struct{ Caller string } }
					}
					_ = json.Unmarshal(raw, &rpc)
					if rpc.Method == "tools/call" && rpc.Params.Arguments.Caller != "" {
						want := map[string]string{"first": signed, "second": otherSigned}[rpc.Params.Arguments.Caller]
						if !opt {
							want = ""
						}
						if r.Header.Get(authority.RunTokenHeader) != want {
							t.Error("concurrent caller token crossed views")
						}
					}
				}
				mu.Lock()
				actualRun := r.Header.Get(authority.RunTokenHeader)
				if actualRun != "" {
					wantURN := "msg://session/local/session"
					if actualRun == otherSigned {
						wantURN = "msg://agent/test/second"
					}
					if r.Header.Get("X-Tether-Agent-Urn") != wantURN || r.Header.Get("X-Tether-Session-Id") != "session" {
						t.Error("Ops signed caller binding missing or crossed views")
					}
				} else if r.Header.Get("X-Tether-Agent-Urn") != "" || r.Header.Get("X-Tether-Session-Id") != "" {
					t.Error("caller headers on service-only request")
				}
				observed = append(observed, r.Header.Get(authority.RunTokenHeader))
				mu.Unlock()
				leafHandler.ServeHTTP(w, r)
			}))
			defer origin.Close()
			runtime, err := upstream.New([]config.MCPServerEntry{{ID: "other", Transport: tc.transport, URL: origin.URL, AllowUnconfinedRemote: true, ForwardRunToken: opt}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			nativeHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return echoServer("tether_echo") }, nil)
			var revoked bool
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				run := r.Header.Get(authority.RunTokenHeader)
				mu.Lock()
				deny := revoked
				mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer caller-token" || run != "" && ((run != signed && run != otherSigned) || deny) {
					w.WriteHeader(401)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/native") {
					nativeHandler.ServeHTTP(w, r)
					return
				}
				a := authority.Admission{SchemaVersion: 1, Principal: authority.Principal{Verified: true, ID: "principal", Kind: "session", SessionID: "session"}, Policy: (gateway.SessionPolicy{SessionID: "session", Servers: []string{"other"}}).Seal(), Fingerprint: "legacy", MachineAccess: "read-only", Selection: gateway.Selection{Mode: gateway.Flat}}
				if run != "" {
					a.Run = &authority.Run{URN: "msg://session/local/session", Session: "session", RunID: "execution", JTI: "nonce", Expires: time.Now().Add(time.Hour).Unix()}
					a.Fingerprint = "verified-first"
					if run == otherSigned {
						a.Fingerprint = "verified-second"
						a.Run.JTI = "nonce-second"
						a.Run.URN = "msg://agent/test/second"
					}
				}
				_ = json.NewEncoder(w).Encode(a)
			}))
			defer backend.Close()
			auth := &authority.Client{HTTP: &http.Client{Transport: routeAuthorityTransport{http.DefaultTransport, backend.URL}}}
			h, err := New(context.Background(), Options{Authority: auth, Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			srv := httptest.NewServer(h)
			defer srv.Close()
			dial := func(token string) (*mcp.ClientSession, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return mcp.NewClient(&mcp.Implementation{Name: "fixture", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: runHeaderTransport{http.DefaultTransport, token}}}, nil)
			}
			if bad, dialErr := dial("forged-run"); dialErr == nil {
				_ = bad.Close()
				t.Fatal("forged run admitted")
			}
			sess, err := dial(signed)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sess.Close() }()
			mu.Lock()
			for _, token := range observed {
				if token != "" {
					t.Error("caller token used for shared startup")
				}
			}
			observed = nil
			mu.Unlock()
			out, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "other_leak", Arguments: map[string]any{}, Meta: mcp.Meta{"X-Run-Token": "spoofed-run"}})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), signed) {
				t.Fatal("upstream echo exposed run token")
			}
			mu.Lock()
			found := false
			for _, token := range observed {
				if token == signed {
					found = true
				} else if token != "" {
					t.Error("unexpected caller token")
				}
			}
			if found != opt {
				t.Error("wrong opt-in behavior on actual HTTP call")
			}
			observed = nil
			mu.Unlock()
			second, err := dial(otherSigned)
			if err != nil {
				t.Fatal(err)
			}
			var calls sync.WaitGroup
			for _, caller := range []struct {
				session *mcp.ClientSession
				label   string
			}{{sess, "first"}, {second, "second"}} {
				calls.Go(func() {
					for range 10 {
						_, callErr := caller.session.CallTool(context.Background(), &mcp.CallToolParams{Name: "other_echo", Arguments: map[string]any{"caller": caller.label}})
						if callErr != nil {
							t.Error(callErr)
							return
						}
					}
				})
			}
			calls.Wait()
			_ = second.Close()
			// Discard concurrent observations before checking the subsequent legacy view.
			mu.Lock()
			observed = nil
			mu.Unlock()
			tampered, err := dial(signed)
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`))
			req.Header.Set("Authorization", "Bearer caller-token")
			req.Header.Set("Mcp-Session-Id", tampered.ID())
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatal("removing run token from retained view accepted")
			}
			_ = tampered.Close()
			legacy, err := dial("")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = legacy.Close() }()
			if _, callErr := legacy.CallTool(context.Background(), &mcp.CallToolParams{Name: "other_echo", Arguments: map[string]any{}}); callErr != nil {
				t.Fatal(callErr)
			}
			mu.Lock()
			for _, token := range observed {
				if token != "" {
					t.Error("previous caller token leaked to legacy view")
				}
			}
			revoked = true
			observed = nil
			mu.Unlock()
			_, err = sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "other_echo", Arguments: map[string]any{}})
			if err == nil {
				t.Fatal("revoked run executed")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(observed) != 0 {
				t.Fatal("revoked run reached upstream")
			}
		})
	}
}
