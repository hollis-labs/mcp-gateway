package frontend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/upstream"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type fixtureBearer struct{ token string }

func (b fixtureBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// TestRealTetherBackend is run by Tether's isolated backend fixture. No live
// daemon, credential store or shared catalog is accessed by this contract test.
func TestRealTetherBackend(t *testing.T) {
	socket := os.Getenv("TETHER_TEST_BACKEND_SOCKET")
	if socket == "" {
		t.Skip("requires the Tether disposable backend fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	token := os.Getenv("TETHER_TEST_CALLER_TOKEN")
	localToken := os.Getenv("TETHER_TEST_LOCAL_TOKEN")
	remote, err := authority.New(socket, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remote.Admit(ctx, localToken, authority.Selectors{}); err == nil {
		t.Fatal("ordinary local token admitted to remote pair")
	} else {
		var refused *authority.Error
		if !errors.As(err, &refused) || refused.Status != 404 {
			t.Fatalf("remote ordinary-token refusal: %v", err)
		}
	}
	for _, remoteIngress := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "network"}[remoteIngress], func(t *testing.T) {
			client, err := authority.New(socket, remoteIngress)
			if err != nil {
				t.Fatal(err)
			}
			a, err := client.Admit(ctx, token, authority.Selectors{Mode: "search"})
			if err != nil {
				t.Fatal(err)
			}
			if a.Principal.SessionID != os.Getenv("TETHER_TEST_SESSION_ID") {
				t.Fatal("admitted session differs from issued fixture")
			}
			if !remoteIngress {
				if _, err = client.Admit(ctx, localToken, authority.Selectors{}); err != nil {
					t.Fatalf("local ordinary token: %v", err)
				}
			}
			runtime, err := upstream.New(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			h, err := New(ctx, Options{Authority: client, Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(h)
			defer srv.Close()
			defer h.Close()
			session, err := mcp.NewClient(&mcp.Implementation{Name: "standalone-contract", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "?discovery_mode=search", HTTPClient: &http.Client{Transport: fixtureBearer{token}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			listed, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			hasCall := false
			for _, tool := range listed.Tools {
				if tool.Name == "tether_tool_call" {
					t.Fatal("old wrapper leaked")
				}
				hasCall = hasCall || tool.Name == "mcp_gateway_tool_call"
			}
			if !hasCall {
				t.Fatal("standalone discovery wrapper absent")
			}
			for _, name := range []string{"tether_health", "tether_docs_list"} {
				out, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: "mcp_gateway_tool_call", Arguments: map[string]any{"name": name, "arguments": map[string]any{}}})
				if callErr != nil {
					t.Fatal(callErr)
				}
				if out.IsError {
					t.Fatalf("%s refused", name)
				}
			}
			denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "mcp_gateway_tool_call", Arguments: map[string]any{"name": "tether_agent_create", "arguments": map[string]any{}}})
			if err == nil && !denied.IsError {
				t.Fatal("read credential dispatched agent mutation")
			}
		})
	}
}
