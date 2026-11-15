package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListenerChoosesAuthorityAndSeparatesAdminIdentity(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "network", true: "unix"}[local], func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "gateway-shell-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			t.Setenv("SUBSTRATE_CONFIG", "")
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
			t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
			t.Setenv(dataDirEnv, filepath.Join(dir, "data"))
			backendPath := filepath.Join(dir, "backend.sock")
			ln, err := net.Listen("unix", backendPath)
			if err != nil {
				t.Fatal(err)
			}
			routes := make(chan string, 4)
			backend := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				routes <- r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"error":{"code":"fixture_authority_unavailable"}}`)
			})}
			go func() { _ = backend.Serve(ln) }()
			defer backend.Close()
			started, err := start(context.Background(), plan([]string{"serve"}))
			if err != nil {
				t.Fatal(err)
			}
			defer started.Stop(context.Background())
			started.App.Config[substrateApp] = map[string]any{"tether_socket": backendPath}
			addr := "127.0.0.1:0"
			if local {
				addr = "unix:" + filepath.Join(dir, "gateway.sock")
			}
			started.App.Config["httphost"].(map[string]any)["addr"] = addr
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			ready := make(chan net.Addr, 1)
			go func() { done <- serve(ctx, started.App, func(a net.Addr) { ready <- a }) }()
			var bound net.Addr
			select {
			case bound = <-ready:
			case serveErr := <-done:
				t.Fatalf("serve: %v", serveErr)
			case <-time.After(10 * time.Second):
				t.Fatal("listener not ready")
			}
			client := &http.Client{Timeout: 3 * time.Second}
			base := "http://" + bound.String()
			if local {
				base = "http://localhost"
				client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", bound.String())
				}}
			}
			request := func(path string) *http.Response {
				r, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
				r.Header.Set("Authorization", "Bearer delegated-fixture")
				r.Header.Set("X-Tether-Remote", "false")
				r.Header.Set("Content-Type", "application/json")
				resp, requestErr := client.Do(r)
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp
			}
			if resp := request("/mcp"); resp.StatusCode != 503 {
				t.Fatalf("delegated bearer intercepted: %d", resp.StatusCode)
			}
			expected := "/gateway/mcp/remote/admit"
			if local {
				expected = "/gateway/mcp/admit"
			}
			if got := <-routes; got != expected {
				t.Fatalf("authority route %s want %s", got, expected)
			}
			r, _ := http.NewRequest(http.MethodGet, base+"/api/gateway/status", nil)
			r.Header.Set("Authorization", "Bearer delegated-fixture")
			resp, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatalf("delegated bearer admitted to admin lane: %d", resp.StatusCode)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("shutdown did not finish")
			}
		})
	}
}
