package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(p, []byte("fixture-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRefreshFailureRetainsWholeSnapshot(t *testing.T) {
	phase := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if phase == 0 {
			_, _ = w.Write([]byte(`{"records":[{"id":"correlation:one","kind":"correlation","lifecycle":"active"}],"boundary":1,"as_of":"2026-01-01T00:00:00Z","schemas":[],"has_more":false}`))
			return
		}
		if phase == 2 {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if strings.Contains(r.URL.Query().Get("args"), "next") {
			http.Error(w, "failed", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"records":[{"id":"correlation:two","kind":"correlation","lifecycle":"active"}],"boundary":2,"as_of":"2026-01-02T00:00:00Z","schemas":[],"has_more":true,"cursor":"next"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, tokenFile(t))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{1, 2} {
		phase = p
		if err := c.Refresh(context.Background()); err == nil {
			t.Fatal("bad snapshot accepted")
		}
		old := c.ResolveCorrelation("correlation:one")
		if old.State != "resolved" || !old.Stale || c.ResolveCorrelation("correlation:two").State != "unresolved" {
			t.Fatal("partial snapshot published or stale state omitted")
		}
	}
}

// TestRealRegistrySnapshot runs under Registry's real SQLite/service/HTTP
// fixture. The fixture supplies a reviewed tool and enough records to page.
func TestRealRegistrySnapshot(t *testing.T) {
	endpoint := os.Getenv("REGISTRY_TEST_URL")
	if endpoint == "" {
		t.Skip("requires the disposable Registry service fixture")
	}
	c := New(endpoint, os.Getenv("REGISTRY_TEST_TOKEN_FILE"))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Status().Ready || c.Status().Stale || len(c.records) < 201 {
		t.Fatal("snapshot did not page through actual Registry")
	}
	tool := &mcp.Tool{Name: "example_echo", Description: "Echo fixture", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
	classified := c.Classify("example", tool)
	if classified.State != "reviewed" || classified.Effective == nil || classified.Stale {
		raw, _ := json.Marshal(classified)
		t.Fatalf("actual review not consumed: %s", raw)
	}
	tool.Description = "Changed observed definition"
	if c.Classify("example", tool).State != "definition_mismatch" {
		t.Fatal("changed live tool inherited review")
	}
}
