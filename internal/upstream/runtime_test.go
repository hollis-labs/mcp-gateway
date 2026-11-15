package upstream

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hollis-labs/mcp-gateway/internal/authority"
)

type captureTransport struct{ request *http.Request }

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.request = r
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
}
func TestServiceTransportBindsCredentialAndAttributionToOrigin(t *testing.T) {
	origin, _ := url.Parse("https://upstream.example.test")
	base := &captureTransport{}
	transport := &originTransport{base: base, origin: origin, headers: map[string]string{"Authorization": "Bearer service-credential"}, forwardAttribution: true}
	attribution := authority.Attribution{Verified: true, SessionResolved: true, Source: "daemon", PrincipalID: "principal", PrincipalKind: "session", SessionID: "verified-session"}
	ctx := withForwardedToolCall(authority.WithAttribution(context.Background(), attribution))
	r, _ := http.NewRequestWithContext(ctx, "POST", origin.String()+"/mcp", nil)
	r.Header.Set("Authorization", "Bearer caller-credential")
	r.Header.Set("X-Tether-Session-Id", "spoofed")
	r.Header.Set("X-Forwarded-User-Id", "spoofed")
	if _, err := transport.RoundTrip(r); err != nil {
		t.Fatal(err)
	}
	if base.request.Header.Get("Authorization") != "Bearer service-credential" || base.request.Header.Get("X-Tether-Session-Id") != "verified-session" {
		t.Fatal("service credential or resolved attribution missing")
	}
	if r.Header.Get("Authorization") != "Bearer caller-credential" {
		t.Fatal("shared caller request mutated")
	}
	r.URL, _ = url.Parse("https://elsewhere.example.test/mcp")
	if _, err := transport.RoundTrip(r); err == nil {
		t.Fatal("credential followed another origin")
	}
}
