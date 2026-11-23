package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
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
func (s *Server) tunnel(client net.Conn, buffered *bufio.Reader, up net.Conn, target string) {
	if s.opts.Leaf == nil {
		splice(client, buffered, up)
		return
	}
	br := bufio.NewReaderSize(buffered, recordHeaderLen+1<<14)
	hello, ok := s.peekHello(client, br)
	if !ok {
		splice(client, br, up)
		return
	}
	host, _, _ := net.SplitHostPort(target)
	name := host
	if hello.serverName != "" {
		name = hello.serverName
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if s.isPinned(name) || (s.opts.Decrypt != nil && !s.opts.Decrypt(name)) {
		splice(client, br, up)
		return
	}
	_ = up.Close() // the forwarding transport dials and verifies the upstream itself
	s.serveDecrypted(&peekedConn{Conn: client, r: br}, name, target)
}

// peekHello reads, without consuming, the client's first TLS record. It reports false
// when the client speaks something else first, or nothing within ReadHeaderTimeout
// (server-first protocols): those tunnels are spliced.
func (s *Server) peekHello(client net.Conn, br *bufio.Reader) (clientHello, bool) {
	_ = client.SetReadDeadline(time.Now().Add(s.opts.ReadHeaderTimeout))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	hdr, err := br.Peek(recordHeaderLen)
	if err != nil {
		return clientHello{}, false
	}
	n, err := helloRecordLen(hdr)
	if err != nil {
		return clientHello{}, false
	}
	rec, err := br.Peek(recordHeaderLen + n)
	if err != nil {
		return clientHello{}, false
	}
	hello, err := parseClientHello(rec)
	return hello, err == nil
}

func (s *Server) serveDecrypted(c net.Conn, name, target string) {
	tc := tls.Server(c, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.opts.Leaf(name) },
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.ReadHeaderTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		// The client refused wraith's certificate: it pins, or does not trust the CA.
		s.markPinned(name)
		s.opts.Logf("TLS %s: client rejected wraith's certificate (%v); passing %s through from now on", name, err, name)
		_ = tc.Close()
		return
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT inside a decrypted tunnel is not supported", http.StatusBadRequest)
			return
		}
		s.tlsRP.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), targetKey{}, target)))
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
		Transport:     rt,
		FlushInterval: -1,
		ErrorLog:      s.http.ErrorLog,
		ModifyResponse: func(resp *http.Response) error {
			s.opts.Logf("%s %s %d %s", resp.Request.Method, resp.Request.URL.Redacted(), resp.StatusCode, resp.Proto)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var verr *tls.CertificateVerificationError
			if errors.As(err, &verr) {
				s.opts.Logf("%s %s 502 upstream certificate rejected: %v", r.Method, r.URL.Redacted(), verr.Err)
			} else {
				s.opts.Logf("%s %s 502 %v", r.Method, r.URL.Redacted(), err)
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

func (s *Server) isPinned(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pinned[host]
}

func (s *Server) markPinned(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned[host] = true
}

// Pinned returns the hosts switched to pass-through this session because a client
// rejected wraith's certificate (R2.4), sorted.
func (s *Server) Pinned() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := make([]string, 0, len(s.pinned))
	for h := range s.pinned {
		hosts = append(hosts, h)
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
