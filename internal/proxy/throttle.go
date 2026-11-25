package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// A slow-network profile slows what the capture source sends and receives, to see an
// app's loading states and timeouts: each request (and each tunnel) waits Latency before
// going out, and all of the source's traffic shares Down and Up, as on a slow network.
// Traffic outside the source is never slowed.

// Throttle is a slow-network profile. Rates are bytes per second; 0 is unlimited.
type Throttle struct {
	Name     string
	Latency  time.Duration
	Down, Up int64
}

// Throttles are the profiles, roughly those of Xcode's Network Link Conditioner, slowest
// last.
var Throttles = []Throttle{
	{Name: "lte", Latency: 50 * time.Millisecond, Down: 12_000_000 / 8, Up: 5_000_000 / 8},
	{Name: "3g", Latency: 100 * time.Millisecond, Down: 780_000 / 8, Up: 330_000 / 8},
	{Name: "edge", Latency: 400 * time.Millisecond, Down: 240_000 / 8, Up: 200_000 / 8},
	{Name: "very-bad", Latency: 500 * time.Millisecond, Down: 1_000_000 / 8 / 10, Up: 1_000_000 / 8 / 10},
}

// ThrottleNamed returns the profile called name; "off" and "" are none.
func ThrottleNamed(name string) (Throttle, bool) {
	if name == "" || name == "off" {
		return Throttle{}, true
	}
	for _, t := range Throttles {
		if t.Name == name {
			return t, true
		}
	}
	return Throttle{}, false
}

// shaper applies one profile: its latency, and a bucket per direction shared by every
// connection of the source.
type shaper struct {
	Throttle
	down, up *bucket
}

// SetThrottle switches the profile for requests and tunnels from now on; a zero Throttle
// turns it off.
func (s *Server) SetThrottle(t Throttle) {
	if t.Name == "" {
		s.shaper.Store(nil)
		return
	}
	s.shaper.Store(&shaper{Throttle: t, down: newBucket(t.Down), up: newBucket(t.Up)})
}

// ThrottleName is the profile in use, or "" for none.
func (s *Server) ThrottleName() string {
	if sh := s.shaper.Load(); sh != nil {
		return sh.Name
	}
	return ""
}

// shaperFor is the profile for a request or tunnel in ctx: nil outside the source.
func (s *Server) shaperFor(ctx context.Context) *shaper {
	if !verdictOf(ctx).InSource {
		return nil
	}
	return s.shaper.Load()
}

// sleep waits d, or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// bucket paces bytes to a rate: each read is let through once the bytes before it
// would have arrived at that rate.
type bucket struct {
	rate int64
	mu   sync.Mutex
	next time.Time
}

func newBucket(rate int64) *bucket {
	if rate <= 0 {
		return nil
	}
	return &bucket{rate: rate}
}

// delay books n bytes and returns how long to wait until they are through.
func (b *bucket) delay(n int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.next.Before(now) {
		b.next = now
	}
	b.next = b.next.Add(time.Duration(int64(n) * int64(time.Second) / b.rate))
	return b.next.Sub(now)
}

// chunk is the most a single read takes at once, so bytes trickle rather than arrive in
// bursts a second apart.
func (b *bucket) chunk() int64 { return max(b.rate/20, 512) }

// slowReader reads through a bucket.
type slowReader struct {
	r   io.Reader
	b   *bucket
	ctx context.Context
}

func (r *slowReader) Read(p []byte) (int, error) {
	if c := r.b.chunk(); int64(len(p)) > c {
		p = p[:c]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		if serr := sleep(r.ctx, r.b.delay(n)); serr != nil && err == nil {
			err = serr
		}
	}
	return n, err
}

// slowBody is a request or response body read through a bucket.
type slowBody struct {
	slowReader
	c io.Closer
}

func (b *slowBody) Close() error { return b.c.Close() }

func slowed(rc io.ReadCloser, b *bucket, ctx context.Context) io.ReadCloser {
	if b == nil || rc == nil || rc == http.NoBody {
		return rc
	}
	return &slowBody{slowReader{rc, b, ctx}, rc}
}

// throttleTransport slows the source's requests by the profile in use.
type throttleTransport struct {
	s    *Server
	next http.RoundTripper
}

func (t *throttleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	sh := t.s.shaperFor(r.Context())
	if sh == nil {
		return t.next.RoundTrip(r)
	}
	if err := sleep(r.Context(), sh.Latency); err != nil {
		return nil, err
	}
	r.Body = slowed(r.Body, sh.up, r.Context())
	resp, err := t.next.RoundTrip(r)
	if err != nil || resp.StatusCode == http.StatusSwitchingProtocols {
		return resp, err // an upgraded connection's body must stay a ReadWriteCloser
	}
	resp.Body = slowed(resp.Body, sh.down, r.Context())
	return resp, nil
}

// slowConn is a tunnel's upstream, slowed both ways.
type slowConn struct {
	net.Conn
	down, up *bucket
	ctx      context.Context
}

func (c *slowConn) Read(p []byte) (int, error) {
	if c.down == nil {
		return c.Conn.Read(p)
	}
	return (&slowReader{c.Conn, c.down, c.ctx}).Read(p)
}

func (c *slowConn) Write(p []byte) (int, error) {
	if c.up == nil {
		return c.Conn.Write(p)
	}
	written := 0
	for len(p) > 0 {
		part := p
		if ch := c.up.chunk(); int64(len(part)) > ch {
			part = p[:ch]
		}
		if err := sleep(c.ctx, c.up.delay(len(part))); err != nil {
			return written, err
		}
		m, err := c.Conn.Write(part)
		written += m
		if err != nil {
			return written, err
		}
		p = p[len(part):]
	}
	return written, nil
}

func (c *slowConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
