package authority

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Attribution is resolved by Tether from the same credential as admission.
// It is observation data and never substitutes for an admission response.
type Attribution struct {
	Verified           bool   `json:"verified"`
	SessionResolved    bool   `json:"session_resolved,omitempty"`
	Source             string `json:"source,omitempty"`
	PrincipalID        string `json:"principal_id,omitempty"`
	PrincipalKind      string `json:"principal_kind,omitempty"`
	SessionID          string `json:"session_id,omitempty"`
	AgentURN           string `json:"agent_urn,omitempty"`
	WorkstreamID       string `json:"workstream_id,omitempty"`
	TaskID             string `json:"task_id,omitempty"`
	LaunchID           string `json:"launch_id,omitempty"`
	ProjectID          string `json:"project_id,omitempty"`
	LogicalAgentID     string `json:"logical_agent_id,omitempty"`
	Intent             string `json:"intent,omitempty"`
	ContinuesSessionID string `json:"continues_session_id,omitempty"`
}

func (c *Client) CallerContext(ctx context.Context, token string) (Attribution, error) {
	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/auth/context", nil)
	if err != nil {
		return Attribution{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Attribution{}, fmt.Errorf("caller attribution unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	var a Attribution
	if err != nil || len(raw) > 16384 || resp.StatusCode != 200 || json.Unmarshal(raw, &a) != nil {
		return Attribution{}, fmt.Errorf("caller attribution unavailable")
	}
	return a, nil
}
func (a Attribution) Matches(p Principal) bool {
	if !a.Verified || !a.SessionResolved || a.Source != "daemon" || !p.Verified || p.SessionID == "" || a.PrincipalID != p.ID || a.PrincipalKind != p.Kind || a.SessionID != p.SessionID {
		return false
	}
	for _, v := range []string{a.SessionID, a.AgentURN, a.WorkstreamID, a.TaskID, a.LaunchID, a.ProjectID, a.LogicalAgentID, a.ContinuesSessionID} {
		if len(v) > 512 {
			return false
		}
		for _, r := range v {
			if r <= 0x20 || r >= 0x7f {
				return false
			}
		}
	}
	return true
}

type attributionKey struct{}

func WithAttribution(ctx context.Context, a Attribution) context.Context {
	return context.WithValue(ctx, attributionKey{}, a)
}
func FromContext(ctx context.Context) (Attribution, bool) {
	a, ok := ctx.Value(attributionKey{}).(Attribution)
	return a, ok
}
