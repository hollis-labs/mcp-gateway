// Package api serves the gateway's own administration lane. Its Substrate
// identity is separate from the delegated bearer accepted by /mcp.
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/mcp-gateway/internal/registry"
	"github.com/hollis-labs/mcp-gateway/internal/telemetry"
)

func RegisterScopes(t *libauth.ScopeTable) {
	t.Route(http.MethodGet, "/api/gateway/status", "mcp-gateway.read")
	t.Route(http.MethodGet, "/api/gateway/events", "mcp-gateway.read")
}
func New(cache *registry.Cache, recorder *telemetry.Recorder) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/gateway/events", func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 {
				http.Error(w, "limit must be 1..100", http.StatusBadRequest)
				return
			}
			limit = n
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": recorder.Recent(limit), "retention": recorder.Summary()})
	})
	mux.HandleFunc("GET /api/gateway/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"registry": cache.Status(), "telemetry": recorder.Summary(), "authority": "tether-delegated-per-operation", "sourceproxy_refs": "not-connected", "retained_recovery": "not-connected"})
	})
	return mux
}
