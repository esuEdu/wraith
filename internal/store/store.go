// Package store keeps captured flows in memory: the last max_flows of them, bodies cut at
// max_body_bytes (R5.1). Nothing here is ever written to disk; flows leave the process
// only through an export the user asks for (R5.2, S3.1).
package store

import (
	"net/http"
	"sync"
	"time"
)

// Kinds of flow.
const (
	KindHTTP   = "http"   // a request and its response, plain or decrypted
	KindTunnel = "tunnel" // a CONNECT tunnel passed through without decrypting
)

// Flow is one captured exchange.
type Flow struct {
	ID       uint64
	Kind     string
	Start    time.Time
	Duration time.Duration

	Source string // label of the process that made it, e.g. "sim iPhone 17 · Shop"
	Route  string // vpn, direct or failed (R3.5)

	Method string
	URL    string // full URL; for tunnels "host:port"
	Proto  string // HTTP/1.1, HTTP/2.0
	Status int    // 0 when no response arrived
	Err    string // why there is no response; never contains header values or bodies

	ReqHeader  http.Header
	RespHeader http.Header
	ReqBody    Body
	RespBody   Body
}

// Body is a captured body: at most the store's limit, with the full size alongside.
type Body struct {
	Data      []byte
	Size      int64 // bytes that went through, captured or not
	Truncated bool
}

// Store is a ring buffer of flows with live subscribers. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	max     int
	maxBody int64
	flows   []*Flow // oldest first
	nextID  uint64
	subs    map[chan Flow]struct{}
}

// New returns a store keeping maxFlows flows and maxBody bytes per body.
func New(maxFlows int, maxBody int64) *Store {
	if maxFlows < 1 {
		maxFlows = 1
	}
	return &Store{max: maxFlows, maxBody: maxBody, subs: map[chan Flow]struct{}{}}
}

// MaxBody is the per-body capture limit.
func (s *Store) MaxBody() int64 { return s.maxBody }

// Add stores a completed flow, assigning its ID, and hands a copy to every subscriber.
// A subscriber that is not keeping up misses flows rather than slowing the proxy.
func (s *Store) Add(f Flow) Flow {
	s.mu.Lock()
	s.nextID++
	f.ID = s.nextID
	cp := f
	s.flows = append(s.flows, &cp)
	if over := len(s.flows) - s.max; over > 0 {
		clear(s.flows[:over])
		s.flows = s.flows[over:]
	}
	for ch := range s.subs {
		select {
		case ch <- f:
		default:
		}
	}
	s.mu.Unlock()
	return f
}

// Flows returns the stored flows, oldest first.
func (s *Store) Flows() []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Flow, len(s.flows))
	for i, f := range s.flows {
		out[i] = *f
	}
	return out
}

// Get returns the flow with id, if still stored.
func (s *Store) Get(id uint64) (Flow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.flows {
		if f.ID == id {
			return *f, true
		}
	}
	return Flow{}, false
}

// Clear drops every stored flow.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.flows)
	s.flows = nil
}

// Subscribe returns a channel of flows added from now on, and a function to stop.
func (s *Store) Subscribe(buffer int) (<-chan Flow, func()) {
	ch := make(chan Flow, buffer)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subs, ch)
			s.mu.Unlock()
			close(ch)
		})
	}
}
