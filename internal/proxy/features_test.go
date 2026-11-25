package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

func TestTimingShowsWhereTheTimeWent(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond) // the server working
		_, _ = io.WriteString(w, strings.Repeat("x", 1000))
	})
	e := startMITM(t, poolOf(ts.Certificate()), nil)
	c := e.client(poolOf(e.ca.Certificate()), false)
	for _, p := range []string{"/first", "/second"} {
		if _, _, err := get(t, c, ts.URL+p); err != nil {
			t.Fatal(err)
		}
	}
	first := e.waitFlow(t, "first", func(f store.Flow) bool { return strings.HasSuffix(f.URL, "/first") })
	tm := first.Timing
	if !tm.Known || tm.Reused || tm.Connect <= 0 || tm.TLS <= 0 || tm.Wait < 60*time.Millisecond {
		t.Fatalf("first request: %+v", tm)
	}
	if sum := tm.Blocked + tm.DNS + tm.Connect + tm.TLS + tm.Send + tm.Wait + tm.Receive; sum > first.Duration {
		t.Fatalf("phases add up to %s, more than the %s it took", sum, first.Duration)
	}
	second := e.waitFlow(t, "second", func(f store.Flow) bool { return strings.HasSuffix(f.URL, "/second") })
	if tm := second.Timing; !tm.Known || !tm.Reused || tm.Connect != 0 || tm.TLS != 0 {
		t.Fatalf("second request, on the same upstream connection: %+v", tm)
	}
}

func TestThrottleSlowsOnlyTheSource(t *testing.T) {
	body := strings.Repeat("x", 6000)
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
	var inSource atomic.Bool
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Classify = func(context.Context, net.Addr, net.Addr) Verdict {
			return Verdict{InSource: inSource.Load(), Decrypt: true, Label: "sim"}
		}
	})
	e.srv.SetThrottle(Throttle{Name: "test", Latency: 200 * time.Millisecond, Down: 10_000})
	if e.srv.ThrottleName() != "test" {
		t.Fatalf("throttle %q", e.srv.ThrottleName())
	}

	timed := func(roots bool) time.Duration {
		pool := poolOf(ts.Certificate())
		if roots {
			pool = poolOf(e.ca.Certificate())
		}
		start := time.Now()
		if _, got, err := get(t, e.client(pool, false), ts.URL+"/big"); err != nil || got != body {
			t.Fatalf("body %d bytes, err %v", len(got), err)
		}
		return time.Since(start)
	}
	if d := timed(false); d > 300*time.Millisecond {
		t.Fatalf("outside the source it took %s: it was slowed", d)
	}
	inSource.Store(true)
	// 200 ms latency, then 6000 bytes at 10 kB/s: at least 0.7 s.
	if d := timed(true); d < 700*time.Millisecond {
		t.Fatalf("inside the source it took only %s", d)
	}
	f := e.waitFlow(t, "throttled", func(f store.Flow) bool { return f.Kind == store.KindHTTP })
	if f.Throttle != "test" || f.Timing.Blocked < 200*time.Millisecond {
		t.Fatalf("flow: throttle %q, blocked %s", f.Throttle, f.Timing.Blocked)
	}

	e.srv.SetThrottle(Throttle{})
	if d := timed(true); d > 500*time.Millisecond || e.srv.ThrottleName() != "" {
		t.Fatalf("after turning it off it took %s", d)
	}
}

func TestBucketPacesToItsRate(t *testing.T) {
	b := newBucket(1000)
	var total time.Duration
	for range 10 {
		total = b.delay(100)
	}
	if total < 900*time.Millisecond || total > 1100*time.Millisecond {
		t.Fatalf("1000 bytes at 1000 B/s are through after %s", total)
	}
	if newBucket(0) != nil {
		t.Fatal("rate 0 is unlimited")
	}
	for _, name := range []string{"lte", "3g", "edge", "very-bad", "off", ""} {
		if _, ok := ThrottleNamed(name); !ok {
			t.Errorf("profile %q missing", name)
		}
	}
	if _, ok := ThrottleNamed("5g"); ok {
		t.Error("an unknown profile was accepted")
	}
}

func TestMockAnswersWithoutTheUpstream(t *testing.T) {
	var hits atomic.Int32
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "real")
	})
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Mock = func(r MockRequest) *MockResponse {
			method, url := r.Method, r.URL
			if method == "POST" && strings.HasSuffix(url, "/cart?x=1") && string(r.Body()) == `{"sku":7}` {
				return &MockResponse{Rule: "POST */cart", Status: 503, Header: http.Header{"Content-Type": {"application/json"}},
					Body: []byte(`{"error":"down"}`), Delay: 50 * time.Millisecond}
			}
			if strings.HasSuffix(url, "/broken") {
				return &MockResponse{Rule: "GET */broken", Err: "reading cart.json: no such file"}
			}
			return nil
		}
	})
	c := e.client(poolOf(e.ca.Certificate()), false)
	start := time.Now()
	resp, err := c.Post(ts.URL+"/cart?x=1", "application/json", strings.NewReader(`{"sku":7}`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 503 || string(got) != `{"error":"down"}` || resp.Header.Get("Content-Type") != "application/json" || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("mock answered %d %q %v", resp.StatusCode, got, resp.Header)
	}
	if _, body, _ := get(t, c, ts.URL+"/other"); body != "real" {
		t.Fatalf("an unmocked request got %q", body)
	}
	if resp, body, _ := get(t, c, ts.URL+"/broken"); resp.StatusCode != 502 || !strings.Contains(body, "no such file") {
		t.Fatalf("a mock that cannot be read answered %d %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("the upstream was asked %d times, want only for /other", hits.Load())
	}
	f := e.waitFlow(t, "mocked", func(f store.Flow) bool { return f.Method == "POST" })
	if f.Route != "mock" || f.Mock != "POST */cart" || f.Status != 503 || string(f.ReqBody.Data) != `{"sku":7}` ||
		string(f.RespBody.Data) != `{"error":"down"}` || f.Timing.Known {
		t.Fatalf("mocked flow: %+v", f)
	}
}

func TestMocksOnlyAnswerTheSource(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "real") })
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Classify = func(context.Context, net.Addr, net.Addr) Verdict { return Verdict{InSource: false} }
		o.Mock = func(MockRequest) *MockResponse { return &MockResponse{Body: []byte("mock")} }
	})
	if _, body, err := get(t, e.client(poolOf(ts.Certificate()), false), ts.URL+"/x"); err != nil || body != "real" {
		t.Fatalf("outside the source: %q %v", body, err)
	}
}

func TestAMockThatReadsTheBodyLeavesItWholeForTheUpstream(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b) // echo
	})
	var peeked atomic.Int32
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Mock = func(r MockRequest) *MockResponse {
			if strings.Contains(string(r.Body()), `"GetCart"`) {
				return &MockResponse{Body: []byte(`{"data":"mocked"}`)}
			}
			peeked.Add(1)
			return nil
		}
	})
	c := e.client(poolOf(e.ca.Certificate()), false)
	big := `{"operationName":"GetUser","query":"query GetUser { me }","pad":"` + strings.Repeat("x", 3<<20) + `"}` // past what is peeked
	resp, err := c.Post(ts.URL+"/graphql", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != big || peeked.Load() != 1 {
		t.Fatalf("the upstream got %d of %d bytes", len(got), len(big))
	}
	resp, err = c.Post(ts.URL+"/graphql", "application/json", strings.NewReader(`{"operationName":"GetCart","query":"query GetCart { cart }"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != `{"data":"mocked"}` {
		t.Fatalf("GetCart: %q", got)
	}
	f := e.waitFlow(t, "mocked GetCart", func(f store.Flow) bool { return f.Route == "mock" })
	if store.GraphQLLabel(f.GraphQL) != "query GetCart" {
		t.Fatalf("the mocked flow's operation: %v", f.GraphQL)
	}
	user := e.waitFlow(t, "GetUser", func(f store.Flow) bool { return f.Route != "mock" && f.Kind == store.KindHTTP })
	if user.ReqBody.Size != int64(len(big)) {
		t.Fatalf("recorded request body %d of %d bytes", user.ReqBody.Size, len(big))
	}
}
