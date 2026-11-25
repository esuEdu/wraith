package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
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
	at   marks
}

// marks are the moments an upstream request passed through, from httptrace.
type marks struct {
	getConn, dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone time.Time
	gotConn, wrote, firstByte                                          time.Time
	reused                                                             bool
}

// trace notes the moments of the upstream request in fr.at.
func (fr *flowRec) trace() *httptrace.ClientTrace {
	mark := func(t *time.Time) {
		fr.mu.Lock()
		if t.IsZero() {
			*t = time.Now()
		}
		fr.mu.Unlock()
	}
	return &httptrace.ClientTrace{
		GetConn:      func(string) { mark(&fr.at.getConn) },
		DNSStart:     func(httptrace.DNSStartInfo) { mark(&fr.at.dnsStart) },
		DNSDone:      func(httptrace.DNSDoneInfo) { mark(&fr.at.dnsDone) },
		ConnectStart: func(string, string) { mark(&fr.at.connStart) },
		ConnectDone: func(string, string, error) {
			fr.mu.Lock()
			fr.at.connDone = time.Now() // the last attempt's end (happy eyeballs tries several)
			fr.mu.Unlock()
		},
		TLSHandshakeStart: func() { mark(&fr.at.tlsStart) },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { mark(&fr.at.tlsDone) },
		GotConn: func(i httptrace.GotConnInfo) {
			fr.mu.Lock()
			fr.at.gotConn, fr.at.reused = time.Now(), i.Reused
			fr.mu.Unlock()
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { mark(&fr.at.wrote) },
		GotFirstResponseByte: func() { mark(&fr.at.firstByte) },
	}
}

// timing turns the marks into phases, ending at end. The dial is wraith's router, which
// may resolve names itself: then DNS is not seen apart and counts as connect.
func (m marks) timing(start, end time.Time) store.Timing {
	if m.gotConn.IsZero() || m.firstByte.IsZero() {
		return store.Timing{}
	}
	span := func(a, b time.Time) time.Duration {
		if a.IsZero() || b.IsZero() || b.Before(a) {
			return 0
		}
		return b.Sub(a)
	}
	t := store.Timing{Known: true, Reused: m.reused}
	if !m.reused {
		t.DNS = span(m.dnsStart, m.dnsDone)
		t.TLS = span(m.tlsStart, m.tlsDone)
		t.Connect = span(m.connStart, m.connDone)
		if t.Connect == 0 { // the router dialed without telling: all of the dial but DNS
			dialEnd := m.tlsStart
			if dialEnd.IsZero() {
				dialEnd = m.gotConn
			}
			t.Connect = max(span(m.getConn, dialEnd)-t.DNS, 0)
		}
	}
	wrote := m.wrote
	if wrote.IsZero() {
		wrote = m.gotConn
	}
	t.Blocked = span(start, m.getConn)
	t.Send = span(m.gotConn, wrote)
	t.Wait = span(wrote, m.firstByte)
	t.Receive = span(m.firstByte, end)
	return t
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
		Throttle: s.ThrottleName(),
	}}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = store.NewCapture(r.Body, s.opts.Store.MaxBody(), func(b store.Body) {
			fr.mu.Lock()
			fr.f.ReqBody = b
			fr.mu.Unlock()
		})
	}
	ctx := httptrace.WithClientTrace(context.WithValue(r.Context(), flowKey{}, fr), fr.trace())
	return r.WithContext(ctx)
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
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// The upgraded connection is the body, and must stay a ReadWriteCloser. The flow is
		// recorded now; a WebSocket's messages are added to it as they pass.
		fr.commit()
		if rwc, ok := resp.Body.(io.ReadWriteCloser); ok && strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			resp.Body = tapWebSocket(rwc, fr, resp.Header)
		}
		return
	}
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
		end := time.Now()
		f.Duration = end.Sub(f.Start)
		if f.Status != 0 && f.Mock == "" {
			f.Timing = fr.at.timing(f.Start, end)
		}
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
		Kind: store.KindTunnel, Start: start, Duration: time.Since(start), Source: v.Label, Throttle: s.ThrottleName(),
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
