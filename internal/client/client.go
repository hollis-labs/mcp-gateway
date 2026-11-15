// Package client connects a frozen delegated credential to the gateway. It
// never opens Tether state or starts an upstream process.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/hollis-labs/mcp-gateway/internal/config"
)

var ErrDaemonUnreachable = errors.New("gateway unreachable")

type Client struct {
	baseURL string
	http    *http.Client
}

func New(address, tokenFile string) (*Client, error) {
	token, err := config.ReadBearerFile(tokenFile)
	if err != nil {
		return nil, err
	}
	base := http.DefaultTransport
	endpoint := strings.TrimRight(address, "/")
	if strings.HasPrefix(address, "unix:") {
		socket := strings.TrimPrefix(address, "unix:")
		if !filepath.IsAbs(socket) {
			return nil, fmt.Errorf("gateway Unix socket must be absolute")
		}
		base = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
		endpoint = "http://localhost"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fmt.Errorf("gateway address must be an HTTP origin or absolute Unix socket")
	}
	return &Client{baseURL: endpoint, http: &http.Client{Transport: credentialTransport{base: base, origin: u, token: token}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type credentialTransport struct {
	base   http.RoundTripper
	origin *url.URL
	token  string
}

func (t credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != t.origin.Scheme || r.URL.Host != t.origin.Host {
		return nil, fmt.Errorf("gateway credential origin refused")
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}
