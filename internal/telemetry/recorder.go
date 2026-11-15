// Package telemetry retains bounded, secret-free observations. It has no
// delegated Tether receipt authority and stores no arguments or result bodies.
package telemetry

import (
	"sync"

	"github.com/hollis-labs/mcp-gateway/internal/frontend"
)

const capacity = 1024

type Recorder struct {
	mu     sync.Mutex
	events []frontend.Event
	next   int
	total  uint64
}

func (r *Recorder) Record(e frontend.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	if e.Correlation.State != "resolved" {
		e.Correlation.ID = ""
	}
	if len(r.events) < capacity {
		r.events = append(r.events, e)
		return
	}
	r.events[r.next] = e
	r.next = (r.next + 1) % capacity
}

type Summary struct {
	Total      uint64 `json:"total"`
	Retained   int    `json:"retained"`
	Capacity   int    `json:"capacity"`
	Durability string `json:"durability"`
}

func (r *Recorder) Summary() Summary {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Summary{Total: r.total, Retained: len(r.events), Capacity: capacity, Durability: "process-memory"}
}

// Recent returns newest observations first. The endpoint caps limit at 100;
// copying the slice keeps callers independent of the ring's next overwrite.
func (r *Recorder) Recent(limit int) []frontend.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	limit = min(max(limit, 0), min(100, len(r.events)))
	out := make([]frontend.Event, 0, limit)
	next := len(r.events)
	if len(r.events) == capacity {
		next = r.next
	}
	for i := 0; i < limit; i++ {
		index := (next - 1 - i + len(r.events)) % len(r.events)
		out = append(out, r.events[index])
	}
	return out
}
