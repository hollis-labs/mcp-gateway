// Package authority consumes Tether's versioned admission API. It never
// authenticates a caller from a claimed identity or cached grant.
package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/gateway"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type Principal struct {
	Verified  bool       `json:"verified"`
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Scopes    []string   `json:"scopes"`
	SessionID string     `json:"session_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
type Admission struct {
	SchemaVersion     int                        `json:"schema_version"`
	Principal         Principal                  `json:"principal"`
	Policy            gateway.SessionPolicy      `json:"policy"`
	MachineAccess     string                     `json:"machine_access"`
	Profile           gateway.ProfileSelection   `json:"profile"`
	AuthorityProfiles []gateway.ProfileSelection `json:"authority_profiles"`
	Selection         gateway.Selection          `json:"selection"`
	Fingerprint       string                     `json:"fingerprint"`
}
type Selectors struct {
	Profile string `json:"profile,omitempty"`
	Mode    string `json:"discovery_mode,omitempty"`
}
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string   { return e.Code }
func (e *Error) Temporary() bool { return e.Status >= 500 }

// Client consumes the Tether authority API. Remote is selected by the application's accepted listener, never by
// caller input. All network ingress uses the permanently narrowed route pair.
type Client struct {
	Socket string
	Remote bool
	HTTP   *http.Client
}

func New(socket string, remote bool) (*Client, error) {
	if !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("tether socket must be absolute")
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Client{Socket: socket, Remote: remote, HTTP: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) path(suffix string) string {
	if c.Remote {
		return "/gateway/mcp/remote/" + suffix
	}
	return "/gateway/mcp/" + suffix
}
func (c *Client) Admit(ctx context.Context, token string, s Selectors) (Admission, error) {
	var out Admission
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b, _ := json.Marshal(s)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+c.path("admit"), bytes.NewReader(b))
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out, &Error{503, "identity_unavailable"}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return out, &Error{503, "invalid_authority_response"}
	}
	if resp.StatusCode != 200 {
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error.Code == "" {
			e.Error.Code = "authority_refused"
		}
		return out, &Error{resp.StatusCode, e.Error.Code}
	}
	if json.Unmarshal(raw, &out) != nil || out.SchemaVersion != 1 || !out.Principal.Verified || out.Principal.ID == "" || out.Fingerprint == "" || out.Policy.Servers == nil || out.Policy.Digest != out.Policy.Seal().Digest || gateway.ValidateMode(string(out.Selection.Mode)) != nil {
		return Admission{}, &Error{503, "invalid_authority_response"}
	}
	if out.Profile.Profile != nil && out.Profile.Profile.Validate() != nil {
		return Admission{}, &Error{503, "invalid_authority_response"}
	}
	for _, f := range out.AuthorityProfiles {
		if f.Profile == nil || f.Profile.Validate() != nil {
			return Admission{}, &Error{503, "invalid_authority_response"}
		}
	}
	if out.MachineAccess != "read-only" && out.MachineAccess != "read-write" {
		return Admission{}, &Error{503, "invalid_authority_response"}
	}
	return out, nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token func() string
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "http" || req.URL.Host != "localhost" {
		return nil, fmt.Errorf("native transport refused another origin")
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token())
	return t.base.RoundTrip(r)
}
func (c *Client) Native(ctx context.Context, token func() string, s Selectors) (*mcp.ClientSession, error) {
	u := url.URL{Scheme: "http", Host: "localhost", Path: c.path("native")}
	q := url.Values{}
	if s.Profile != "" {
		q.Set("profile", s.Profile)
	}
	if s.Mode != "" {
		q.Set("discovery_mode", s.Mode)
	}
	u.RawQuery = q.Encode()
	h := &http.Client{Transport: bearerTransport{c.HTTP.Transport, token}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return mcp.NewClient(&mcp.Implementation{Name: "mcp-gateway-native", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: u.String(), HTTPClient: h}, nil)
}
