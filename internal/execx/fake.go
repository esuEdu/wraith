package execx

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Fake is a scripted Runner for tests. Replies are keyed by the full command line
// ("networksetup -getwebproxy Wi-Fi"); an unscripted call returns an error, so a test
// sees every command its code runs.
type Fake struct {
	mu      sync.Mutex
	replies map[string]FakeReply
	calls   []string
	// Handler, when set, answers calls that have no scripted reply.
	Handler func(tool string, args []string) ([]byte, error)
}

// FakeReply is one scripted answer.
type FakeReply struct {
	Out []byte
	Err error
}

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{replies: map[string]FakeReply{}} }

// On scripts the reply for one command line.
func (f *Fake) On(cmdline string, out string, err error) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[cmdline] = FakeReply{Out: []byte(out), Err: err}
	return f
}

// Run records the call and returns its scripted reply.
func (f *Fake) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{tool}, args...), " ")
	f.mu.Lock()
	f.calls = append(f.calls, line)
	r, ok := f.replies[line]
	h := f.Handler
	f.mu.Unlock()
	if ok {
		return r.Out, r.Err
	}
	if h != nil {
		return h(tool, args)
	}
	return nil, fmt.Errorf("execx.Fake: unscripted call %q", line)
}

// Calls returns every command line run so far, in order.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
