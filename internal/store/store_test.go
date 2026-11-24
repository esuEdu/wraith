package store

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestR5_1_KeepsTheLastMaxFlows(t *testing.T) {
	s := New(3, 10)
	for i := range 5 {
		s.Add(Flow{URL: string(rune('a' + i))})
	}
	got := s.Flows()
	if len(got) != 3 || got[0].URL != "c" || got[2].URL != "e" || got[2].ID != 5 {
		t.Fatalf("flows %+v", got)
	}
	if _, ok := s.Get(1); ok {
		t.Fatal("evicted flow still found")
	}
	if f, ok := s.Get(4); !ok || f.URL != "d" {
		t.Fatalf("Get(4) = %+v, %v", f, ok)
	}
	s.Clear()
	if len(s.Flows()) != 0 {
		t.Fatal("Clear left flows")
	}
	if f := s.Add(Flow{}); f.ID != 6 {
		t.Fatalf("IDs restarted after Clear: %d", f.ID)
	}
}

func TestR5_1_BodiesAreTruncatedButStreamedWhole(t *testing.T) {
	src := strings.Repeat("x", 25)
	var got Body
	c := NewCapture(io.NopCloser(strings.NewReader(src)), 10, func(b Body) { got = b })
	out, err := io.ReadAll(c)
	if err != nil || string(out) != src {
		t.Fatalf("passed through %d bytes, err %v; want all 25", len(out), err)
	}
	if string(got.Data) != strings.Repeat("x", 10) || got.Size != 25 || !got.Truncated {
		t.Fatalf("captured %+v", got)
	}

	var small Body
	c = NewCapture(io.NopCloser(bytes.NewReader([]byte("hi"))), 10, func(b Body) { small = b })
	_, _ = io.ReadAll(c)
	_ = c.Close() // done runs once
	if string(small.Data) != "hi" || small.Size != 2 || small.Truncated {
		t.Fatalf("captured %+v", small)
	}
}

func TestCaptureFinishesOnCloseWithoutEOF(t *testing.T) {
	calls := 0
	c := NewCapture(io.NopCloser(strings.NewReader("abcdef")), 100, func(b Body) {
		calls++
		if string(b.Data) != "ab" {
			t.Errorf("captured %q", b.Data)
		}
	})
	buf := make([]byte, 2)
	_, _ = c.Read(buf)
	_ = c.Close()
	_ = c.Close()
	if calls != 1 {
		t.Fatalf("done ran %d times", calls)
	}
	var empty Body
	_ = NewCapture(nil, 10, func(b Body) { empty = b }).Close()
	if empty.Size != 0 {
		t.Fatalf("nil body: %+v", empty)
	}
}

func TestSubscribersGetNewFlowsAndNeverBlockTheProxy(t *testing.T) {
	s := New(10, 10)
	ch, stop := s.Subscribe(1)
	s.Add(Flow{URL: "one"})
	s.Add(Flow{URL: "two"}) // buffer full: dropped for this subscriber, still stored
	select {
	case f := <-ch:
		if f.URL != "one" {
			t.Fatalf("got %q", f.URL)
		}
	case <-time.After(time.Second):
		t.Fatal("no flow delivered")
	}
	if len(s.Flows()) != 2 {
		t.Fatal("a slow subscriber lost a stored flow")
	}
	stop()
	stop()
	if _, open := <-ch; open {
		t.Fatal("channel open after stop")
	}
	s.Add(Flow{}) // no panic sending to a stopped subscriber
}
