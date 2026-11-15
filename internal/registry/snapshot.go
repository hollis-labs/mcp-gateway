// Package registry reads declared metadata without giving it routing authority.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hollis-labs/mcp-gateway/internal/config"
	"github.com/hollis-labs/substrate/kinds"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type Review struct {
	DefinitionHash string                `json:"definition_hash"`
	State          string                `json:"state"`
	Effective      *kinds.Classification `json:"effective,omitempty"`
	Stale          bool                  `json:"stale,omitempty"`
}
type Record struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Lifecycle string          `json:"lifecycle"`
	Payload   json.RawMessage `json:"payload"`
	Review    *Review         `json:"review,omitempty"`
}
type page struct {
	Records  []Record `json:"records"`
	Cursor   string   `json:"cursor"`
	HasMore  bool     `json:"has_more"`
	Boundary int64    `json:"boundary"`
	AsOf     string   `json:"as_of"`
}
type Status struct {
	Configured bool      `json:"configured"`
	Ready      bool      `json:"ready"`
	Stale      bool      `json:"stale"`
	FetchedAt  time.Time `json:"fetched_at,omitempty"`
	Boundary   int64     `json:"boundary"`
	Error      string    `json:"error,omitempty"`
}
type Cache struct {
	URL, TokenFile string
	HTTP           *http.Client
	mu             sync.RWMutex
	records        map[string]Record
	status         Status
}

func New(endpoint, tokenFile string) *Cache {
	return &Cache{URL: strings.TrimRight(endpoint, "/"), TokenFile: tokenFile, HTTP: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, records: map[string]Record{}, status: Status{Configured: endpoint != ""}}
}
func (c *Cache) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.status
	if s.Ready && time.Since(s.FetchedAt) > 2*time.Minute {
		s.Stale = true
	}
	return s
}
func (c *Cache) Refresh(ctx context.Context) error {
	if c.URL == "" {
		return nil
	}
	err := c.refresh(ctx)
	if err != nil {
		c.mu.Lock()
		c.status.Stale = true
		c.status.Error = "registry_snapshot_unavailable"
		c.mu.Unlock()
	}
	return err
}
func (c *Cache) refresh(ctx context.Context) error {
	u, err := url.Parse(c.URL)
	if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid Registry endpoint")
	}
	token, err := config.ReadBearerFile(c.TokenFile)
	if err != nil {
		return err
	}
	var boundary int64
	cursor := ""
	seen := map[string]bool{}
	records := map[string]Record{}
	for n := 0; n < 100; n++ {
		args, _ := json.Marshal(map[string]any{"query": map[string]any{"limit": 200, "cursor": cursor}})
		// #nosec G704 -- Endpoint is operator configuration, validated above; redirects are disabled.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/v1/snapshot?"+url.Values{"args": {string(args)}}.Encode(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		// #nosec G704 -- Credential goes only to the configured Registry endpoint; redirects are disabled.
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("registry unavailable")
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
		_ = resp.Body.Close()
		if e != nil || resp.StatusCode != 200 || len(raw) > 16<<20 {
			return fmt.Errorf("registry snapshot unavailable")
		}
		var p page
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return fmt.Errorf("invalid Registry snapshot")
		}
		for _, key := range []string{"records", "has_more", "boundary", "as_of", "schemas"} {
			if len(fields[key]) == 0 || string(fields[key]) == "null" {
				return fmt.Errorf("invalid Registry snapshot")
			}
		}
		if json.Unmarshal(raw, &p) != nil || p.Records == nil || p.Boundary < 0 {
			return fmt.Errorf("invalid Registry snapshot")
		}
		if _, err := time.Parse(time.RFC3339Nano, p.AsOf); err != nil {
			return fmt.Errorf("invalid Registry snapshot time")
		}
		if n == 0 {
			boundary = p.Boundary
		} else if boundary != p.Boundary {
			return fmt.Errorf("registry snapshot boundary changed")
		}
		for _, r := range p.Records {
			if r.ID == "" {
				return fmt.Errorf("invalid Registry record")
			}
			if _, dup := records[r.ID]; dup {
				return fmt.Errorf("duplicate Registry snapshot identity")
			}
			records[r.ID] = r
		}
		if !p.HasMore {
			c.mu.Lock()
			c.records = records
			c.status = Status{Configured: true, Ready: true, FetchedAt: time.Now().UTC(), Boundary: boundary}
			c.mu.Unlock()
			return nil
		}
		if p.Cursor == "" || seen[p.Cursor] {
			return fmt.Errorf("invalid Registry snapshot cursor")
		}
		seen[p.Cursor] = true
		cursor = p.Cursor
	}
	return fmt.Errorf("registry snapshot exceeds bounded refresh")
}
func (c *Cache) Run(ctx context.Context) {
	_ = c.Refresh(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.Refresh(ctx)
		}
	}
}

type Correlation struct {
	ID               string `json:"id,omitempty"`
	State            string `json:"state"`
	SnapshotBoundary int64  `json:"snapshot_boundary,omitempty"`
	Stale            bool   `json:"stale,omitempty"`
}

func (c *Cache) ResolveCorrelation(id string) Correlation {
	out := Correlation{ID: id, State: "unresolved"}
	if id == "" {
		out.State = "absent"
		return out
	}
	if len(id) > 512 || strings.ContainsAny(id, "\r\n\x00") {
		out.ID = ""
		out.State = "invalid"
		return out
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out.SnapshotBoundary = c.status.Boundary
	out.Stale = c.status.Stale || (c.status.Ready && time.Since(c.status.FetchedAt) > 2*time.Minute)
	r, ok := c.records[id]
	if ok && r.Kind == "correlation" && r.Lifecycle != "archived" && r.Lifecycle != "deleted" {
		out.State = "resolved"
	}
	return out
}

type Classification struct {
	ID             string                `json:"id,omitempty"`
	State          string                `json:"state"`
	DefinitionHash string                `json:"definition_hash,omitempty"`
	Effective      *kinds.Classification `json:"effective,omitempty"`
	Stale          bool                  `json:"stale,omitempty"`
}

func (c *Cache) Classify(origin string, tool *mcp.Tool) Classification {
	out := Classification{State: "unknown"}
	id, err := kinds.ToolID("mcp", origin, tool.Name)
	if err != nil {
		return out
	}
	out.ID = id
	c.mu.RLock()
	r, ok := c.records[id]
	out.Stale = c.status.Stale || (c.status.Ready && time.Since(c.status.FetchedAt) > 2*time.Minute)
	c.mu.RUnlock()
	if !ok || r.Kind != "tool" {
		return out
	}
	if r.Lifecycle == "archived" || r.Lifecycle == "deleted" {
		out.State = r.Lifecycle
		return out
	}
	declared, err := kinds.ParseToolJSON(r.Payload)
	if err != nil {
		return out
	}
	hash, err := kinds.DefinitionHash(*declared)
	if err != nil || r.Review == nil || hash != r.Review.DefinitionHash {
		return out
	}
	// Compute the observed projection independently. A current review of a
	// different schema is never inherited by the live tool.
	raw, _ := json.Marshal(tool)
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return out
	}
	observed := *declared
	observed.Definition = kinds.Definition{Name: tool.Name, Title: tool.Title, Description: fields["description"], InputSchema: fields["inputSchema"], OutputSchema: fields["outputSchema"], Annotations: fields["annotations"], Icons: fields["icons"], Meta: fields["_meta"]}
	actual, err := kinds.DefinitionHash(observed)
	out.DefinitionHash = actual
	if err != nil || actual != hash {
		out.State = "definition_mismatch"
		return out
	}
	out.State = r.Review.State
	out.Effective = r.Review.Effective
	return out
}
