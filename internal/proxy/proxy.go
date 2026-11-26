// Package proxy is wraith's HTTP proxy: it splices CONNECT tunnels, forwards plain HTTP
// requests, decrypts the tunnels of the capture source and records what it sees. It
// listens on loopback; only with devices on does it also listen on one address of the
// local network, and then a peer there gets in only once the user allows it (S2.6).
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// Limits from the Security spec, S5.1.
const (
	DefaultMaxHeaderBytes    = 1 << 20
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultIdleTimeout       = 90 * time.Second
	DefaultMaxConns          = 1024
	DefaultDialTimeout       = 10 * time.Second
)

// Dialer opens upstream connections; the default is a plain net.Dialer.
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

	// Store receives every flow inside the source; nil records nothing.
	Store *store.Store

	// Admit decides how far a peer that is not on this Mac gets (S2.6). Nil refuses
	// every such peer (S2.1).
	Admit func(peer net.IP) Access
	// Unlock is called when a device opens the setup page with a key; it reports whether
	// the key was right, and then the device is Allowed from now on.
	Unlock func(peer net.IP, key, userAgent string) bool
	// CACert is the CA certificate (PEM) wraith hands out at /ca to allowed devices.
	CACert []byte
	// AppFromUserAgent names the app from a request's User-Agent, for verdicts with
	// ByUserAgent; nil names none.
	AppFromUserAgent func(userAgent string) string

	// Mock picks the mock that answers a request of the source instead of the upstream;
	// nil, or a nil answer, forwards it.
	Mock func(MockRequest) *MockResponse
}

// Access is how far a device on the network gets (S2.6).
type Access int

const (
	Refused   Access = iota // closed before a byte is read
	SetupOnly               // may open the setup page, nothing else
	Allowed                 // may use the proxy
)

// Verdict is Classify's answer for one client connection.
type Verdict struct {
	InSource bool
	Decrypt  bool   // may be decrypted (still subject to Leaf and Decrypt(host))
	Label    string // shown in front of its log lines, e.g. "sim iPhone 17 · Shop"
	// ByUserAgent adds the app each request names in its User-Agent to the label, through
	// Options.AppFromUserAgent: a physical device has no process to name (S2.6).
	ByUserAgent bool
}

// withApp is v for one request: with the app from its User-Agent in the label, when v
// asks for it and one is named.
func (s *Server) withApp(v Verdict, userAgent string) Verdict {
	if !v.ByUserAgent || s.opts.AppFromUserAgent == nil {
		return v
	}
	if app := s.opts.AppFromUserAgent(userAgent); app != "" {
		v.Label += " · " + app
	}
	return v
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
	selfIPs   map[string]bool          // non-loopback addresses we listen on, likewise
	pinned    map[string]pin           // client and host → its rejections of our certificate
	now       func() time.Time

	shaper  atomic.Pointer[shaper] // the slow-network profile in use; nil for none
	closing context.Context        // done once Close is called
	stop    context.CancelFunc
}

// New returns a Server with opts, defaults filled in.
func New(opts Options) *Server {
	opts.fill()
	s := &Server{
		opts:      opts,
		clients:   map[*clientConn]struct{}{},
		upstreams: map[net.Conn]struct{}{},
		selfPorts: map[string]bool{},
		selfIPs:   map[string]bool{},
		pinned:    map[string]pin{},
		now:       time.Now,
	}
	s.closing, s.stop = context.WithCancel(context.Background())
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
		Transport:     &throttleTransport{s: s, next: transport},
		FlushInterval: -1, // stream responses (SSE, long polls) without buffering
		ErrorLog:      errLog,
		ModifyResponse: func(resp *http.Response) error {
			flowOf(resp.Request.Context()).response(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			flowOf(r.Context()).failed(http.StatusBadGateway, err.Error())
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

// ListenDevice opens a listener on ip, one private address of the Mac on the local
// network, so devices there can use the proxy (S2.6). It never listens on every address:
// an unspecified, loopback or public ip is refused. Only peers Options.Admit allows get in.
func ListenDevice(ip net.IP, port int) (net.Listener, error) {
	if !ip.IsPrivate() {
		return nil, fmt.Errorf("%s is not a private address on the local network", ip)
	}
	network := "tcp4"
	if ip.To4() == nil {
		network = "tcp6"
	}
	return net.Listen(network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

// Serve accepts connections on ln until Close. It may be called once per listener, from
// separate goroutines. It returns http.ErrServerClosed after Close.
func (s *Server) Serve(ln net.Listener) error {
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		s.mu.Lock()
		s.selfPorts[strconv.Itoa(a.Port)] = true
		if !a.IP.IsLoopback() {
			s.selfIPs[a.IP.String()] = true
		}
		s.mu.Unlock()
	}
	return s.http.Serve(&guardListener{Listener: ln, s: s})
}

// Close stops the listeners and closes every open connection, tunnels included.
func (s *Server) Close() error {
	s.stop()
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
	peer, access := s.peer(r)
	own := !r.URL.IsAbs() && r.Method != http.MethodConnect || s.isSelf(r.URL.Host, "80")
	if own && s.serveOwn(w, r, peer, access) {
		return
	}
	if access != Allowed {
		http.Error(w, "this device may not use wraith yet: scan the QR code in wraith's window", http.StatusForbidden)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), verdictKey{}, s.withApp(s.verdictFor(r.Context()), r.UserAgent())))
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
	u := r.URL.Redacted()
	r = s.beginFlow(r, u, r.URL.Host)
	if s.mock(w, r, u) {
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

	sh := s.shaperFor(r.Context())
	if sh != nil && sleep(r.Context(), sh.Latency) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.opts.DialTimeout)
	up, err := s.dialUpstream(ctx, "tcp", target)
	cancel()
	if err != nil {
		s.recordTunnel(r.Context(), start, target, http.StatusBadGateway, err.Error())
		http.Error(w, "cannot reach "+target, http.StatusBadGateway)
		return
	}
	if sh != nil {
		up = &slowConn{Conn: up, down: sh.down, up: sh.up, ctx: s.closing}
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
	s.tunnel(r.Context(), start, client, brw.Reader, up, target)
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
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	ip := net.ParseIP(strings.Trim(h, "[]"))
	s.mu.Lock()
	ours := s.selfPorts[port] && (ip == nil || ip.IsLoopback() || ip.IsUnspecified() || s.selfIPs[ip.String()])
	s.mu.Unlock()
	if !ours {
		return false
	}
	return ip != nil || h == "localhost" || strings.HasSuffix(h, ".localhost")
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

// guardListener drops non-loopback peers the user has not allowed (S2.1, S2.6) and
// connections over MaxConns (S5.1) before the HTTP server reads a byte from them.
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
		if !FromThisMac(c.RemoteAddr(), c.LocalAddr()) && l.s.access(c.RemoteAddr()) == Refused {
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

// FromThisMac reports whether a connection came from this Mac: over loopback, or from
// the Mac's own network address to itself (a browser on the Mac opening the device
// page). Such a peer is a local process, not a device.
func FromThisMac(remote, local net.Addr) bool {
	r, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	l, ok := local.(*net.TCPAddr)
	return r.IP.IsLoopback() || ok && r.IP.Equal(l.IP)
}

// access asks Admit about a peer that is not on this Mac; without Admit it is refused
// and logged (S2.1). Admit reports its own refusals, once per peer.
func (s *Server) access(a net.Addr) Access {
	ta, ok := a.(*net.TCPAddr)
	if s.opts.Admit == nil || !ok {
		s.opts.Logf("refused connection from non-loopback peer %s", a)
		return Refused
	}
	return s.opts.Admit(ta.IP)
}

// peer is the device behind a request, and how far it gets; a request from this Mac is
// Allowed with a nil peer.
func (s *Server) peer(r *http.Request) (net.IP, Access) {
	ci, ok := r.Context().Value(connKey{}).(*connInfo)
	if !ok || FromThisMac(ci.client, ci.local) {
		return nil, Allowed
	}
	ip := ci.client.(*net.TCPAddr).IP
	return ip, s.access(ci.client)
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
