package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"sync"
	"time"
)

// tunnel handles the bytes after "200 Connection Established". Without a Leaf function,
// or when the first record is not a TLS ClientHello, or the host is pinned (R2.4) or
// excluded by Decrypt (R2.5), the bytes are spliced untouched. Otherwise the TLS session
// is terminated with a leaf for the host and the requests inside are forwarded.
func (s *Server) tunnel(ctx context.Context, start time.Time, client net.Conn, buffered *bufio.Reader, up net.Conn, target string) {
	v := verdictOf(ctx)
	passThrough := func(r io.Reader, why string) {
		s.recordTunnel(ctx, start, target, http.StatusOK, why)
		splice(client, r, up)
	}
	switch {
	case s.opts.Leaf == nil:
		passThrough(buffered, "")
		return
	case !v.InSource:
		passThrough(buffered, "") // never recorded anyway (R1.3)
		return
	case !v.Decrypt:
		passThrough(buffered, "passed through: this client is not decrypted (a Mac app, and the Mac does not trust the CA)")
		return
	}
	br := bufio.NewReaderSize(buffered, recordHeaderLen+1<<14)
	hello, why := s.peekHello(client, br)
	if why != "" {
		passThrough(br, "passed through: "+why)
		return
	}
	host, _, _ := net.SplitHostPort(target)
	name := host
	if hello.serverName != "" {
		name = hello.serverName
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if s.isPinned(v, name) {
		passThrough(br, "passed through: this client rejected wraith's certificate for it a moment ago (pinned, or the CA is not trusted yet); it is tried again soon")
		return
	}
	if s.opts.Decrypt != nil && !s.opts.Decrypt(name) {
		passThrough(br, "passed through: on no_decrypt")
		return
	}
	_ = up.Close() // the forwarding transport dials and verifies the upstream itself
	// The requests inside are named each by its own User-Agent, not the CONNECT's.
	s.serveDecrypted(&peekedConn{Conn: client, r: br}, name, target, s.verdictFor(ctx))
}

// peekHello reads, without consuming, the client's first TLS record. When the client
// speaks something else first, or nothing within ReadHeaderTimeout (a server-first
// protocol, or an idle preconnect), it returns why, and the tunnel is spliced.
func (s *Server) peekHello(client net.Conn, br *bufio.Reader) (clientHello, string) {
	_ = client.SetReadDeadline(time.Now().Add(s.opts.ReadHeaderTimeout))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	hdr, err := br.Peek(recordHeaderLen)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return clientHello{}, fmt.Sprintf("the client sent nothing for %s", s.opts.ReadHeaderTimeout)
	}
	if err != nil {
		return clientHello{}, "the client closed the tunnel before speaking"
	}
	n, err := helloRecordLen(hdr)
	if err != nil {
		return clientHello{}, "not TLS"
	}
	rec, err := br.Peek(recordHeaderLen + n)
	if err != nil {
		return clientHello{}, "incomplete TLS ClientHello"
	}
	hello, err := parseClientHello(rec)
	if err != nil {
		return clientHello{}, "unreadable TLS ClientHello"
	}
	return hello, ""
}

func (s *Server) serveDecrypted(c net.Conn, name, target string, v Verdict) {
	vctx := context.WithValue(context.Background(), verdictKey{}, v)
	tc := tls.Server(c, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.opts.Leaf(name) },
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.ReadHeaderTimeout)
	start := time.Now()
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = tc.Close()
		// Only a TLS alert from the client is a rejection (it pins, or does not trust the
		// CA yet); a client that just closes, or says nothing, is not.
		var oe *net.OpError
		if !errors.As(err, &oe) || oe.Op != "remote error" {
			return
		}
		wait := s.markPinned(v, name)
		s.recordTunnel(vctx, start, target, 0, fmt.Sprintf("rejected wraith's certificate (%v): the app pins, or the device does not trust the wraith CA yet; passed through for %s, then tried again", oe.Err, wait))
		return
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT inside a decrypted tunnel is not supported", http.StatusBadRequest)
			return
		}
		ctx := context.WithValue(context.WithValue(r.Context(), targetKey{}, target), verdictKey{}, s.withApp(v, r.UserAgent()))
		r = r.WithContext(ctx)
		host, _, _ := net.SplitHostPort(target)
		u := "https://" + r.Host + r.URL.RequestURI()
		r = s.beginFlow(r, u, host)
		if s.mock(w, r, u) {
			return
		}
		s.tlsRP.ServeHTTP(w, r)
	})
	// net/http serves HTTP/2 itself when the *tls.Conn it accepts negotiated "h2".
	l := newOneConnListener(tc)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: s.opts.ReadHeaderTimeout,
		IdleTimeout:       s.opts.IdleTimeout,
		MaxHeaderBytes:    s.opts.MaxHeaderBytes,
		ErrorLog:          s.http.ErrorLog,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 250}, // S5.1
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				l.finish()
			}
		},
	}
	_ = srv.Serve(l)
}

type targetKey struct{}

// newTLSReverseProxy forwards decrypted requests to their upstream over TLS, verifying
// the upstream's certificate against the system roots (or Options.RootCAs) with TLS 1.2
// at least (S2.3). Hosts in Options.InsecureUpstream skip verification (S2.4).
func (s *Server) newTLSReverseProxy() *httputil.ReverseProxy {
	base := func(cfg *tls.Config) *http.Transport {
		return &http.Transport{
			Proxy:                  nil,
			DialContext:            s.dialUpstream,
			TLSClientConfig:        cfg,
			ForceAttemptHTTP2:      true,
			MaxResponseHeaderBytes: int64(s.opts.MaxHeaderBytes),
			IdleConnTimeout:        s.opts.IdleTimeout,
			TLSHandshakeTimeout:    s.opts.DialTimeout,
			DisableCompression:     true,
		}
	}
	rt := &hostTransport{
		secure: base(&tls.Config{RootCAs: s.opts.RootCAs, MinVersion: tls.VersionTLS12}),
		insecure: base(&tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- allow: S2.4, only hosts the user named with --insecure-upstream
			MinVersion:         tls.VersionTLS12,
		}),
		insecureHosts: s.opts.InsecureUpstream,
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			target, _ := pr.In.Context().Value(targetKey{}).(string)
			host, port, _ := net.SplitHostPort(target)
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = target
			if port == "443" {
				pr.Out.URL.Host = hostForURL(host)
			}
			pr.Out.Host = pr.In.Host
			keepForwardedHeaders(pr)
		},
		Transport:     &throttleTransport{s: s, next: rt},
		FlushInterval: -1,
		ErrorLog:      s.http.ErrorLog,
		ModifyResponse: func(resp *http.Response) error {
			flowOf(resp.Request.Context()).response(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var verr *tls.CertificateVerificationError
			if errors.As(err, &verr) {
				flowOf(r.Context()).failed(http.StatusBadGateway, "", "upstream certificate rejected: "+verr.Err.Error())
			} else {
				flowOf(r.Context()).failed(http.StatusBadGateway, s.routeName(r.URL.Host, true), err.Error())
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

func hostForURL(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func keepForwardedHeaders(pr *httputil.ProxyRequest) {
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if v, ok := pr.In.Header[h]; ok {
			pr.Out.Header[h] = v
		}
	}
}

type hostTransport struct {
	secure, insecure http.RoundTripper
	insecureHosts    map[string]bool
}

func (t *hostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.insecureHosts[strings.ToLower(r.URL.Hostname())] {
		return t.insecure.RoundTrip(r)
	}
	return t.secure.RoundTrip(r)
}

// pinBackoff is how long a host is passed through for a client after it rejected
// wraith's certificate for the 1st, 2nd and 3rd time (R2.4). The first waits are short
// because the usual cause is a device that does not trust the CA yet; a host that keeps
// rejecting it pins its certificate, and stays passed through.
var pinBackoff = []time.Duration{30 * time.Second, 5 * time.Minute, 24 * time.Hour}

type pin struct {
	strikes int
	until   time.Time
}

// pinKey is per client, so one app or device that pins a host does not stop wraith from
// decrypting it for the others.
func pinKey(v Verdict, host string) string { return v.Label + "\x00" + host }

func (s *Server) isPinned(v Verdict, host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Before(s.pinned[pinKey(v, host)].until)
}

// markPinned records a rejection and returns how long the host is now passed through.
func (s *Server) markPinned(v Verdict, host string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pinned[pinKey(v, host)]
	wait := pinBackoff[min(p.strikes, len(pinBackoff)-1)]
	p.strikes++
	p.until = s.now().Add(wait)
	s.pinned[pinKey(v, host)] = p
	return wait
}

// Pinned returns the hosts some client is passing through now because it rejected
// wraith's certificate (R2.4), sorted.
func (s *Server) Pinned() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hosts []string
	for k, p := range s.pinned {
		_, h, _ := strings.Cut(k, "\x00")
		if s.now().Before(p.until) && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts)
	return hosts
}

// peekedConn reads through the buffered reader that holds the peeked ClientHello.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneConnListener hands one connection to an http.Server, unwrapped so the server sees
// the *tls.Conn and can speak HTTP/2, then reports closed once finish is called (from the
// server's ConnState hook, when that connection closes).
type oneConnListener struct {
	conn     net.Conn
	accepted sync.Once
	finished sync.Once
	done     chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.accepted.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) finish()        { l.finished.Do(func() { close(l.done) }) }
func (l *oneConnListener) Close() error   { l.finish(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
