package upstream

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
	"github.com/hollis-labs/mcp-gateway/internal/config"
	"gopkg.in/yaml.v3"
)

const fixtureRun = "synthetic-run-secret"
const fixtureSpoof = "static-spoof"

func TestRunTokenTransportBoundary(t *testing.T) {
	origin, _ := url.Parse("https://upstream.example.test")
	for _, tc := range []struct {
		name                string
		opt, verified, call bool
		method, want        string
	}{
		{"present", true, true, true, "POST", fixtureRun},
		{"absent", true, false, true, "POST", ""},
		{"not opted in", false, true, true, "POST", ""},
		{"initialization and ping", true, true, false, "POST", ""},
		{"background stream", true, true, true, "GET", ""},
		{"teardown", true, true, true, "DELETE", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &captureTransport{}
			transport := &originTransport{base: base, origin: origin, forwardRunToken: tc.opt, headers: map[string]string{"x-run-token": fixtureSpoof, "Authorization": "Bearer service"}}
			ctx := context.Background()
			if tc.verified {
				ctx = authority.WithVerifiedRunToken(ctx, fixtureRun)
			}
			if tc.call {
				ctx = withForwardedToolCall(ctx)
			}
			req, _ := http.NewRequestWithContext(ctx, tc.method, origin.String()+"/mcp", nil)
			req.Header.Set(authority.RunTokenHeader, "caller-spoof")
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if got := base.request.Header.Get(authority.RunTokenHeader); got != tc.want {
				t.Fatal("wrong run token forwarding decision")
			}
			if req.Header.Get(authority.RunTokenHeader) != "caller-spoof" {
				t.Fatal("input request mutated")
			}
			req.URL, _ = url.Parse("https://elsewhere.example.test/mcp")
			if _, err := transport.RoundTrip(req); err == nil {
				t.Fatal("run token escaped configured origin")
			}
		})
	}
}

func TestRunTokensRemainRequestScoped(t *testing.T) {
	origin, _ := url.Parse("https://upstream.example.test")
	var wg sync.WaitGroup
	for _, token := range []string{"synthetic-run-a", "synthetic-run-b"} {
		wg.Go(func() {
			for range 25 {
				base := &captureTransport{}
				transport := &originTransport{base: base, origin: origin, forwardRunToken: true}
				ctx := withForwardedToolCall(authority.WithVerifiedRunToken(context.Background(), token))
				req, _ := http.NewRequestWithContext(ctx, "POST", origin.String(), nil)
				resp, err := transport.RoundTrip(req)
				if err != nil {
					t.Error(err)
					return
				}
				_ = resp.Body.Close()
				if base.request.Header.Get(authority.RunTokenHeader) != token {
					t.Error("cross-caller token leak")
				}
			}
		})
	}
	wg.Wait()
}

func TestRunTokenConfigOptIn(t *testing.T) {
	var entry config.MCPServerEntry
	if err := yaml.Unmarshal([]byte("id: example\ntransport: http\nurl: https://upstream.example.test\nforward_run_token: true\n"), &entry); err != nil {
		t.Fatal(err)
	}
	if !entry.ForwardRunToken {
		t.Fatal("opt-in not decoded")
	}
	r, err := New([]config.MCPServerEntry{entry}, nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := r.pool.remoteHTTPClientFactory(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !build(nil, 1).Transport.(*originTransport).forwardRunToken {
		t.Fatal("opt-in not wired to transport")
	}
	r.Close()
	entry.Transport = "stdio"
	if r, err := New([]config.MCPServerEntry{entry}, nil); err == nil {
		r.Close()
		t.Fatal("stdio accepted HTTP-only opt-in")
	}
}
