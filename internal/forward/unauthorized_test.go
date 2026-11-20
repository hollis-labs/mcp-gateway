package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRunTokenForwarderDoesNotRetryUnauthorized(t *testing.T) {
	for _, method := range []string{"tools/list", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			var initializes, rejected atomic.Int64
			server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-session" || r.Header.Get("X-Run-Token") != "synthetic-run" {
					t.Error("session credential or run token missing")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodPost {
					var msg struct {
						Method string `json:"method"`
					}
					// Preserve the body for the SDK after observing the method.
					var raw json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
						t.Error(err)
						return
					}
					_ = r.Body.Close()
					_ = json.Unmarshal(raw, &msg)
					r.Body = io.NopCloser(bytes.NewReader(raw))
					if msg.Method == "initialize" {
						initializes.Add(1)
					}
					if msg.Method == method {
						rejected.Add(1)
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "credential")
			if err := os.WriteFile(path, []byte("synthetic-session"), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := client.New(srv.URL, path)
			if err != nil {
				t.Fatal(err)
			}
			d := &daemonSession{client: c, opts: client.MCPOptions{RunToken: "synthetic-run"}}
			defer d.close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if method == "tools/list" {
				_, err = d.invokeRead(ctx, func(s *mcp.ClientSession) (mcp.Result, error) { return s.ListTools(ctx, nil) })
			} else {
				_, err = d.callTool(ctx, &mcp.CallToolParams{Name: "mutation"})
			}
			if err == nil {
				t.Fatal("401 was swallowed")
			}
			if initializes.Load() != 1 || rejected.Load() != 1 {
				t.Fatalf("401 retried: initializations=%d requests=%d", initializes.Load(), rejected.Load())
			}
		})
	}
}
