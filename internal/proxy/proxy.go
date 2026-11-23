// Package proxy is wraith's HTTP proxy: a loopback-only listener that splices CONNECT
// tunnels and forwards plain HTTP requests. Decryption (M2), source filtering (M3) and
// bypass routing (M4) plug into it later; for now every connection passes through.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Limits from the Security spec, S5.1.
const (
	DefaultMaxHeaderBytes    = 1 << 20
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultIdleTimeout       = 90 * time.Second
	DefaultMaxConns          = 1024
	DefaultDialTimeout       = 10 * time.Second
)

// Dialer opens upstream connections. The bypass router (R3) will provide one that binds
// to the physical interface; the default is a plain net.Dialer.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Options configures a Server. Zero values take the defaults above.
type Options struct {
	Dialer            Dialer
	MaxHeaderBytes    int
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxConns          int
	DialTimeout       time.Duration
	// Logf receives one line per request and per refused connection. Nil discards.
	Logf func(format string, args ...any)

	// Leaf returns the certificate wraith shows a client for host. Nil turns decryption
	// off: every CONNECT tunnel is spliced.
	Leaf func(host string) (*tls.Certificate, error)
	// Decrypt reports whether a tunnel to host (its SNI name) is decrypted. Nil means
	// every host is, when Leaf is set. No-decrypt hosts are excluded here (R2.5).
	Decrypt func(host string) bool
	// RootCAs verifies upstream servers of decrypted tunnels; nil uses the system roots.
	RootCAs *x509.CertPool
	// InsecureUpstream lists hosts whose upstream certificate is not verified (S2.4).
	InsecureUpstream map[string]bool

	// Classify decides, once per client connection and on its first request, whether the
	// connection is inside the capture source and whether it may be decrypted. A
	// connection outside the source is passed through untouched and never logged (R1.3).
	// Nil puts every connection in the source, decryptable.
	Classify func(ctx context.Context, client, local net.Addr) Verdict

	// Route names how an upstream host is reached, for the log: "vpn" or "direct" (R3.5).
	// A failed "direct" dial is shown as "failed". Nil shows no route.
	Route func(host string) string
}

// routeTag returns " <route>" for host[:port] (or "" without a Route function); a failed
// bypass shows as "failed".
func (s *Server) routeTag(hostport string, failed bool) string {
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
	return " " + r
}

// Verdict is Classify's answer for one client connection.
type Verdict struct {
	InSource bool
	Decrypt  bool   // may be decrypted (still subject to Leaf and Decrypt(host))
	Label    string // shown in front of its log lines, e.g. "sim iPhone 17 · Shop"
}

type connKey struct{}
type verdictKey struct{}

// connInfo is stored in each connection's context; the verdict is computed lazily so a
// slow lookup never holds up the accept loop.
type connInfo struct {
	client, local net.Addr
	once          sync.Once
	v             Verdict
}

func (s *Server) verdictFor(ctx context.Context) Verdict {
	ci, ok := ctx.Value(connKey{}).(*connInfo)
	if !ok || s.opts.Classify == nil {
		return Verdict{InSource: true, Decrypt: true}
	}
	ci.once.Do(func() { ci.v = s.opts.Classify(ctx, ci.client, ci.local) })
	return ci.v
}

// logFlow logs a line about a request or tunnel, unless its connection is outside the
// source (R1.3: never shown). The verdict travels in the request's context.
func (s *Server) logFlow(ctx context.Context, format string, args ...any) {
	v, ok := ctx.Value(verdictKey{}).(Verdict)
	if !ok {
		v = Verdict{InSource: true}
	}
	if !v.InSource {
		return
	}
	if v.Label != "" {
		format = "[" + strings.ReplaceAll(v.Label, "%", "%%") + "] " + format
	}
	s.opts.Logf(format, args...)
}

func (o *Options) fill() {
	if o.Dialer == nil {
		o.Dialer = &net.Dialer{}
	}
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if o.ReadHeaderTimeout <= 0 {
		o.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.MaxConns <= 0 {
		o.MaxConns = DefaultMaxConns
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
}

// Server is a pass-through HTTP proxy. Create it with New, give it listeners from Listen,
// and stop it with Close.
type Server struct {
	opts  Options
	http  *http.Server
	rp    *httputil.ReverseProxy // plain http:// requests
	tlsRP *httputil.ReverseProxy // requests inside decrypted tunnels

	mu        sync.Mutex
	closed    bool
	clients   map[*clientConn]struct{} // counted against MaxConns
	upstreams map[net.Conn]struct{}    // tunnel upstreams, closed on Close
	selfPorts map[string]bool          // ports we listen on, for loop detection
	pinned    map[string]bool          // hosts whose clients rejected our certificate
}

// New returns a Server with opts, defaults filled in.
func New(opts Options) *Server {
	opts.fill()
	s := &Server{
		opts:      opts,
		clients:   map[*clientConn]struct{}{},
		upstreams: map[net.Conn]struct{}{},
		selfPorts: map[string]bool{},
		pinned:    map[string]bool{},
	}
	errLog := log.New(logfWriter(opts.Logf), "", 0)

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            s.dialUpstream,
		MaxResponseHeaderBytes: int64(opts.MaxHeaderBytes),
		IdleConnTimeout:        opts.IdleTimeout,
		DisableCompression:     true, // pass Accept-Encoding and bodies through as sent
	}
	s.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.Host = pr.In.Host
			// Rewrite strips X-Forwarded-*; a pass-through proxy keeps what the client sent
			// and adds nothing.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v, ok := pr.In.Header[h]; ok {
					pr.Out.Header[h] = v
				}
			}
		},
		Transport:     transport,
		FlushInterval: -1, // stream responses (SSE, long polls) without buffering
		ErrorLog:      errLog,
		ModifyResponse: func(resp *http.Response) error {
			s.logFlow(resp.Request.Context(), "%s %s %d%s", resp.Request.Method, resp.Request.URL.Redacted(), resp.StatusCode, s.routeTag(resp.Request.URL.Host, false))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logFlow(r.Context(), "%s %s 502%s %v", r.Method, r.URL.Redacted(), s.routeTag(r.URL.Host, true), err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		IdleTimeout:       opts.IdleTimeout,
		MaxHeaderBytes:    opts.MaxHeaderBytes,
		ErrorLog:          errLog,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, &connInfo{client: c.RemoteAddr(), local: c.LocalAddr()})
		},
	}
	s.tlsRP = s.newTLSReverseProxy()
	return s
}

// Listen opens the proxy's listeners on 127.0.0.1 and, when the Mac has IPv6 loopback,
// on ::1 at the same port. It takes no address: wraith never listens beyond loopback
// (S2.1, S2.2). Port 0 picks a free port.
func Listen(port int) ([]net.Listener, error) {
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	p := v4.Addr().(*net.TCPAddr).Port
	v6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(p)))
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			_ = v4.Close()
			return nil, fmt.Errorf("port %d is in use on ::1: %w", p, err)
		}
		return []net.Listener{v4}, nil // no IPv6 loopback on this Mac
	}
	return []net.Listener{v4, v6}, nil
}

// Serve accepts connections on ln until Close. It may be called once per listener, from
// separate goroutines. It returns http.ErrServerClosed after Close.
func (s *Server) Serve(ln net.Listener) error {
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		s.mu.Lock()
		s.selfPorts[strconv.Itoa(a.Port)] = true
		s.mu.Unlock()
	}
	return s.http.Serve(&guardListener{Listener: ln, s: s})
}

// Close stops the listeners and closes every open connection, tunnels included.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	err := s.http.Close()

	s.mu.Lock()
	conns := make([]io.Closer, 0, len(s.clients)+len(s.upstreams))
	for c := range s.clients {
		conns = append(conns, c)
	}
	for c := range s.upstreams {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return err
}

// ServeHTTP handles one proxy request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), verdictKey{}, s.verdictFor(r.Context())))
	if r.Method == http.MethodConnect {
		s.serveConnect(w, r)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "wraith is a proxy: send absolute-form http:// requests or CONNECT", http.StatusBadRequest)
		return
	}
	if s.isSelf(r.URL.Host, "80") {
		http.Error(w, "request loops back to wraith", http.StatusLoopDetected)
		return
	}
	s.rp.ServeHTTP(w, r)
}

func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	target := r.Host
	host, port, err := net.SplitHostPort(target)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || host == "" || n < 1 || n > 65535 {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	if s.isSelf(target, "") {
		http.Error(w, "CONNECT loops back to wraith", http.StatusLoopDetected)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.opts.DialTimeout)
	up, err := s.dialUpstream(ctx, "tcp", target)
	cancel()
	if err != nil {
		s.logFlow(r.Context(), "CONNECT %s 502%s %v", target, s.routeTag(target, true), err)
		http.Error(w, "cannot reach "+target, http.StatusBadGateway)
		return
	}
	s.trackUpstream(up, true)
	defer s.trackUpstream(up, false)

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_ = client.SetDeadline(time.Time{}) // drop the header-read deadline; tunnels can be long-lived
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = up.Close()
		return
	}
	s.logFlow(r.Context(), "CONNECT %s 200%s (%s)", target, s.routeTag(target, false), time.Since(start).Round(time.Millisecond))
	v, _ := r.Context().Value(verdictKey{}).(Verdict)
	s.tunnel(client, brw.Reader, up, target, v)
}

// dialUpstream dials through the configured Dialer, giving up after DialTimeout, for
// tunnels and both forwarding transports alike.
func (s *Server) dialUpstream(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.DialTimeout)
	defer cancel()
	return s.opts.Dialer.DialContext(ctx, network, addr)
}

// isSelf reports whether hostport points back at one of our listeners.
func (s *Server) isSelf(hostport, defaultPort string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, defaultPort
	}
	s.mu.Lock()
	ours := s.selfPorts[port]
	s.mu.Unlock()
	if !ours {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func (s *Server) trackUpstream(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.upstreams[c] = struct{}{}
	} else {
		delete(s.upstreams, c)
	}
}

// splice copies both ways until both directions finish, then closes both connections.
// clientR carries any bytes the HTTP server had already buffered from the client.
func splice(client net.Conn, clientR io.Reader, up net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, clientR)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, up)
		closeWrite(client)
	}()
	wg.Wait()
	_ = client.Close()
	_ = up.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// guardListener drops non-loopback peers (S2.1) and connections over MaxConns (S5.1)
// before the HTTP server reads a byte from them.
type guardListener struct {
	net.Listener
	s *Server
}

func (l *guardListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !isLoopback(c.RemoteAddr()) {
			l.s.opts.Logf("refused connection from non-loopback peer %s", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		cc, ok := l.s.admit(c)
		if !ok {
			l.s.opts.Logf("connection limit %d reached, closed %s", l.s.opts.MaxConns, c.RemoteAddr())
			_ = c.Close()
			continue
		}
		return cc, nil
	}
}

func isLoopback(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

func (s *Server) admit(c net.Conn) (*clientConn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.clients) >= s.opts.MaxConns {
		return nil, false
	}
	cc := &clientConn{Conn: c, s: s}
	s.clients[cc] = struct{}{}
	return cc, true
}

// clientConn releases its MaxConns slot when closed, whether the HTTP server or a
// tunnel closes it.
type clientConn struct {
	net.Conn
	s    *Server
	once sync.Once
}

func (c *clientConn) Close() error {
	c.once.Do(func() {
		c.s.mu.Lock()
		delete(c.s.clients, c)
		c.s.mu.Unlock()
	})
	return c.Conn.Close()
}

func (c *clientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type logfWriter func(format string, args ...any)

func (f logfWriter) Write(p []byte) (int, error) {
	f("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
