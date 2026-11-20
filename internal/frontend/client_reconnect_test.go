package frontend

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/client"
	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	"github.com/hollis-labs/mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The authority is synthetic; admission, retained views and the HTTP client are
// real. Refresh is an explicit new connection, never a replay of tools/call.
type reconnectAuthority struct {
	fixtureAuthority
	refreshed atomic.Bool
	denied    atomic.Int64
}

func (a *reconnectAuthority) Admit(_ context.Context, bearer string, selectors authority.Selectors) (authority.Admission, error) {
	want := "old-session-credential"
	if a.refreshed.Load() {
		want = "new-session-credential"
	}
	if bearer != want || selectors.RunToken != "synthetic-execution-proof" {
		a.denied.Add(1)
		return authority.Admission{}, &authority.Error{Status: 401, Code: "unauthorized"}
	}
	return a.admission, nil
}

func TestRunTokenClientReconnectAfterGateway401(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var calls atomic.Int64
	native := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	native.AddTool(&mcp.Tool{Name: "tether_mutate", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil
	})
	a := &reconnectAuthority{fixtureAuthority: fixtureAuthority{backend: native, admission: authority.Admission{
		SchemaVersion: 1,
		Principal:     authority.Principal{Verified: true, ID: "session-fixture", Kind: "session", SessionID: "fixture"},
		Fingerprint:   "bound-execution",
		MachineAccess: "read-only",
		Policy:        (gateway.SessionPolicy{SessionID: "fixture"}).Seal(),
		Selection:     gateway.Selection{Mode: gateway.Flat},
		Run:           &authority.Run{URN: "msg://session/local/fixture", Session: "fixture", RunID: "execution", JTI: "execution-nonce", Expires: time.Now().Add(time.Hour).Unix()},
	}}}
	runtime, err := upstream.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	h, err := New(ctx, Options{Authority: a, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()
	credential := filepath.Join(t.TempDir(), "session-credential")
	newClient := func(token string) *client.Client {
		t.Helper()
		if writeErr := os.WriteFile(credential, []byte(token), 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
		c, clientErr := client.New(srv.URL, credential)
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		return c
	}
	opts := client.MCPOptions{RunToken: "synthetic-execution-proof"}
	oldClient := newClient("old-session-credential")
	old, err := oldClient.ConnectMCP(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = old.Close() }()
	if _, listErr := old.ListTools(ctx, nil); listErr != nil {
		t.Fatal(listErr)
	}
	a.refreshed.Store(true)
	if _, callErr := old.CallTool(ctx, &mcp.CallToolParams{Name: "tether_mutate"}); callErr == nil {
		t.Fatal("stale credential was accepted")
	}
	if a.denied.Load() == 0 || calls.Load() != 0 {
		t.Fatal("401 must deny the mutation without replay")
	}
	// Rewriting the file cannot update the frozen old client. Its reconnect
	// must still fail, rather than silently dropping the bearer or run proof.
	freshClient := newClient("new-session-credential")
	if stale, staleErr := oldClient.ConnectMCP(ctx, opts); staleErr == nil {
		_ = stale.Close()
		t.Fatal("frozen client unexpectedly reloaded credentials")
	}
	fresh, err := freshClient.ConnectMCP(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if fresh.ID() == old.ID() {
		t.Fatal("refresh reused the old MCP session")
	}
	if _, listErr := fresh.ListTools(ctx, nil); listErr != nil {
		t.Fatal(listErr)
	}
	if out, callErr := fresh.CallTool(ctx, &mcp.CallToolParams{Name: "tether_mutate"}); callErr != nil || out.IsError {
		t.Fatalf("fresh session call failed: %v", callErr)
	}
	if calls.Load() != 1 {
		t.Fatal("mutation was replayed or never dispatched")
	}
}
