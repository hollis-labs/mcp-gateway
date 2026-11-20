package authority

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/gateway"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

const fixtureRun = "synthetic-run-secret"

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRunTokenHeaderEnvelope(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("x", 4097), "a b", "a,b", "a\r\nb", "a\x00b"} {
		h := http.Header{RunTokenHeader: []string{value}}
		if _, err := ReadRunToken(h); err == nil {
			t.Error("accepted invalid envelope")
		}
	}
	if _, err := ReadRunToken(http.Header{RunTokenHeader: []string{"a", "b"}}); err == nil {
		t.Fatal("accepted duplicate header")
	}
	if token, err := ReadRunToken(http.Header{}); err != nil || token != "" {
		t.Fatal("legacy absent header refused")
	}
	if token, err := ReadRunToken(http.Header{RunTokenHeader: []string{"a.b.c"}}); err != nil || token != "a.b.c" {
		t.Fatal("valid envelope refused")
	}
}

func TestAdmissionRequiresRunVerificationAndCarriesHeader(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, mode := range []string{"verified", "legacy backend", "wrong session", "missing urn", "unsafe urn", "expired", "forged", "absent"} {
			t.Run(mode+map[bool]string{true: " remote", false: " local"}[remote], func(t *testing.T) {
				runToken := fixtureRun
				if mode == "absent" {
					runToken = ""
				}
				response := Admission{SchemaVersion: 1, Principal: Principal{Verified: true, ID: "principal", SessionID: "session"}, Policy: (gateway.SessionPolicy{Servers: []string{}}).Seal(), Fingerprint: "bound", MachineAccess: "read-only", Selection: gateway.Selection{Mode: gateway.Flat}}
				if mode != "legacy backend" && mode != "absent" {
					response.Run = &Run{URN: "msg://session/local/session", Session: "session", RunID: "execution", JTI: "nonce", Expires: time.Now().Add(time.Hour).Unix()}
				}
				if mode == "wrong session" {
					response.Run.Session = "another"
				}
				if mode == "missing urn" {
					response.Run.URN = ""
				}
				if mode == "unsafe urn" {
					response.Run.URN = "invalid\r\nheader"
				}
				if mode == "expired" {
					response.Run.Expires = time.Now().Add(-time.Hour).Unix()
				}
				c := &Client{Remote: remote, HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Header.Get(RunTokenHeader) != runToken || req.Header.Get("Authorization") != "Bearer caller" {
						t.Error("lost separate credentials")
					}
					if req.URL.Path != cPath(remote) {
						t.Error("wrong admission route")
					}
					raw, _ := io.ReadAll(req.Body)
					if strings.Contains(string(raw), fixtureRun) {
						t.Error("token serialized into selectors")
					}
					body, _ := json.Marshal(response)
					status := 200
					if mode == "forged" {
						status = 401
						body = []byte(`{"error":{"code":"unauthorized"}}`)
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
				})}}
				got, err := c.Admit(context.Background(), "caller", Selectors{RunToken: runToken})
				if mode == "verified" || mode == "absent" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("unverified run accepted")
				}
				if mode == "verified" && (got.Principal.ExpiresAt == nil || got.Principal.ExpiresAt.Unix() != response.Run.Expires) {
					t.Fatal("run expiry not applied to view")
				}
			})
		}
	}
}
func cPath(remote bool) string {
	if remote {
		return "/gateway/mcp/remote/admit"
	}
	return "/gateway/mcp/admit"
}

func TestNativeTransportKeepsRunTokenWithBearerRefresh(t *testing.T) {
	bearer := "first"
	transport := bearerTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get(RunTokenHeader) != fixtureRun || req.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("native credentials lost")
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}), token: func() string { return bearer }, runToken: fixtureRun}
	for _, method := range []string{"POST", "GET", "DELETE"} {
		req, _ := http.NewRequest(method, "http://localhost/native", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if req.Header.Get(RunTokenHeader) != "" {
			t.Fatal("request mutated")
		}
		bearer = "refreshed"
	}
	req, _ := http.NewRequest("POST", "https://elsewhere.example.test/", nil)
	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("native credential escaped origin")
	}
}
