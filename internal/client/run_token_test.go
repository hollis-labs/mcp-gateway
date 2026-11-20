package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type captureRunTransport struct{ t *testing.T }

const fixtureRun = "synthetic-run-secret"

func (c captureRunTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("X-Run-Token") != fixtureRun || req.Header.Get("X-Tether-Client-Label") != "label" {
		c.t.Error("launcher header missing")
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}
func TestLauncherRunTokenOnEveryMethod(t *testing.T) {
	tr := mcpErrorTransport{base: captureRunTransport{t}, runToken: fixtureRun, clientLabel: "label"}
	for _, method := range []string{"POST", "GET", "DELETE"} {
		req, _ := http.NewRequest(method, "http://gateway.example.test/mcp", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if req.Header.Get("X-Run-Token") != "" {
			t.Fatal("input mutated")
		}
	}
}
func TestRunBearingClientRefusesRedirect(t *testing.T) {
	var escaped atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { escaped.Store(true); w.WriteHeader(500) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Run-Token") != fixtureRun {
			t.Error("source token missing")
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := &Client{baseURL: source.URL, http: source.Client()}
	sess, err := c.ConnectMCP(context.Background(), MCPOptions{RunToken: fixtureRun})
	if err == nil {
		_ = sess.Close()
		t.Fatal("redirect unexpectedly initialized")
	}
	if escaped.Load() {
		t.Fatal("token followed redirect")
	}
}
