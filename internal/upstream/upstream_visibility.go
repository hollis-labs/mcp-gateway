package upstream

import "fmt"

func (p *ClientPool) unavailableError(id string, client upstreamClient) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.statuses[id]
	if s == nil || s.state != "connected" || s.client != client {
		state := "unavailable"
		if s != nil {
			state = s.state
		}
		return fmt.Errorf("upstream %q unavailable (%s); request was not sent; inspect mcp_gateway_status", id, state)
	}
	return nil
}
