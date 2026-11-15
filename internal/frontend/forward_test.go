package frontend

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/client"
	"github.com/hollis-labs/mcp-gateway/internal/forward"
	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestForwarderPreservesNumericDispatch(t *testing.T) {
	_, h, _ := fixture(t, gateway.Search, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "caller")
	if err := os.WriteFile(path, []byte("caller-token"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(srv.URL, path)
	if err != nil {
		t.Fatal(err)
	}
	x, y := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- forward.Run(ctx, c, client.MCPOptions{}, x) }()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "forward-test", Version: "1"}, nil).Connect(ctx, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "mcp_gateway_tool_call", Arguments: json.RawMessage(`{"name":"other_echo","arguments":{"large":9007199254740993,"tiny":1e-400}}`)})
	if err != nil {
		t.Fatal(err)
	}
	text := out.Content[0].(*mcp.TextContent).Text
	if out.IsError || !strings.Contains(text, "9007199254740993") || !strings.Contains(text, "1e-400") {
		t.Fatalf("forwarded call changed: %s", text)
	}
	_ = session.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forwarder did not close")
	}
}
