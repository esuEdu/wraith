package proxy

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// Flows inside the source are recorded in Options.Store; flows outside it never are
// (R1.3). Bodies stream through store.Capture, which keeps at most the store's limit.

type flowKey struct{}

// flowRec collects one HTTP flow while the request and response stream through.
type flowRec struct {
	s    *Server
	mu   sync.Mutex
	f    store.Flow
	once sync.Once
}

func verdictOf(ctx context.Context) Verdict {
	v, ok := ctx.Value(verdictKey{}).(Verdict)
	if !ok {
		return Verdict{InSource: true}
	}
	return v
}

// beginFlow starts recording r, shown as displayURL, when a store is set and the request
// is inside the source. It returns r carrying the recorder.
func (s *Server) beginFlow(r *http.Request, displayURL, host string) *http.Request {
	v := verdictOf(r.Context())
	if s.opts.Store == nil || !v.InSource {
		return r
	}
	fr := &flowRec{s: s, f: store.Flow{
		Kind: store.KindHTTP, Start: time.Now(), Source: v.Label, Route: s.routeName(host, false),
		Method: r.Method, URL: displayURL, Proto: r.Proto, ReqHeader: r.Header.Clone(),
	}}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = store.NewCapture(r.Body, s.opts.Store.MaxBody(), func(b store.Body) {
			fr.mu.Lock()
			fr.f.ReqBody = b
			fr.mu.Unlock()
		})
	}
	return r.WithContext(context.WithValue(r.Context(), flowKey{}, fr))
}

func flowOf(ctx context.Context) *flowRec {
	fr, _ := ctx.Value(flowKey{}).(*flowRec)
	return fr
}

// response notes the response and records the flow once its body has been read.
func (fr *flowRec) response(resp *http.Response) {
	if fr == nil {
		return
	}
	fr.mu.Lock()
	fr.f.Status, fr.f.Proto, fr.f.RespHeader = resp.StatusCode, resp.Proto, resp.Header.Clone()
	fr.mu.Unlock()
	resp.Body = store.NewCapture(resp.Body, fr.s.opts.Store.MaxBody(), func(b store.Body) {
		fr.mu.Lock()
		fr.f.RespBody = b
		fr.mu.Unlock()
		fr.commit()
	})
}

// failed records a flow that got no response from the upstream.
func (fr *flowRec) failed(status int, route, why string) {
	if fr == nil {
		return
	}
	fr.mu.Lock()
	fr.f.Status, fr.f.Err = status, why
	if route != "" {
		fr.f.Route = route
	}
	fr.mu.Unlock()
	fr.commit()
}

func (fr *flowRec) commit() {
	fr.once.Do(func() {
		fr.mu.Lock()
		f := fr.f
		f.Duration = time.Since(f.Start)
		fr.mu.Unlock()
		f = fr.s.opts.Store.Add(f)
		fr.mu.Lock()
		fr.f = f // as stored, with its ID
		fr.mu.Unlock()
	})
}

// recordTunnel records a CONNECT tunnel passed through without decrypting (status 200),
// or one that could not be opened.
func (s *Server) recordTunnel(ctx context.Context, start time.Time, target string, status int, why string) {
	v := verdictOf(ctx)
	if s.opts.Store == nil || !v.InSource {
		return
	}
	s.opts.Store.Add(store.Flow{
		Kind: store.KindTunnel, Start: start, Duration: time.Since(start), Source: v.Label,
		Route: s.routeName(target, status != http.StatusOK), Method: http.MethodConnect,
		URL: target, Status: status, Err: why,
	})
}

// routeName is the route for host[:port] ("" without a Route function); a failed bypass
// is "failed" (R3.5).
func (s *Server) routeName(hostport string, failed bool) string {
	if s.opts.Route == nil {
		return ""
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	r := s.opts.Route(strings.Trim(host, "[]"))
	if failed && r == "direct" {
		r = "failed"
	}
	return r
}
