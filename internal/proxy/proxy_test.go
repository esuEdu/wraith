package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// startProxy runs a Server on loopback listeners and returns it with its IPv4 address.
func startProxy(t *testing.T, opts Options) (*Server, string) {
	t.Helper()
	s := New(opts)
	lns, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range lns {
		go func() { _ = s.Serve(ln) }()
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, lns[0].Addr().String()
}

func proxyClient(proxyAddr string, base *http.Transport) *http.Client {
	tr := base
	if tr == nil {
		tr = &http.Transport{}
	}
	tr.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// recordingDialer dials normally and records each address asked for.
type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
	err   error
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

func (d *recordingDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// rawStatus writes req on a fresh connection to the proxy and returns the response status.
func rawStatus(t *testing.T, proxyAddr, req string) int {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestConnectTunnelsTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello over tls")
	}))
	defer ts.Close()
	d := &recordingDialer{}
	_, addr := startProxy(t, Options{Dialer: d})

	client := proxyClient(addr, ts.Client().Transport.(*http.Transport).Clone())
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello over tls" {
		t.Fatalf("body = %q", body)
	}
	if got := d.dialed(); len(got) != 1 || got[0] != ts.Listener.Addr().String() {
		t.Fatalf("dialer saw %v, want one dial to %s", got, ts.Listener.Addr())
	}
}

func TestForwardsPlainHTTPUnchanged(t *testing.T) {
	var got http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.Copy(w, r.Body)
	}))
	defer ts.Close()
	_, addr := startProxy(t, Options{})

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/echo?q=1", strings.NewReader("ping"))
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "drop me")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := proxyClient(addr, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusTeapot || string(body) != "ping" || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("status %d body %q header %v", resp.StatusCode, body, resp.Header)
	}
	for _, h := range []string{"Proxy-Connection", "X-Hop"} {
		if v := got.Get(h); v != "" {
			t.Errorf("hop-by-hop header %s reached upstream: %q", h, v)
		}
	}
	if v := got.Values("X-Forwarded-For"); len(v) != 1 || v[0] != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %v, want the client's value only", v)
	}
	if v := got.Get("Accept-Encoding"); v != "identity" {
		t.Errorf("Accept-Encoding = %q, want it passed through", v)
	}
}

func TestConnectDialFailureIs502(t *testing.T) {
	_, addr := startProxy(t, Options{Dialer: &recordingDialer{err: errors.New("no route")}})
	status := rawStatus(t, addr, "CONNECT nowhere.invalid:443 HTTP/1.1\r\nHost: nowhere.invalid:443\r\n\r\n")
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
}

func TestConnectBadTargetIs400(t *testing.T) {
	_, addr := startProxy(t, Options{})
	for _, target := range []string{"example.com", "example.com:0", "example.com:99999", ":443"} {
		status := rawStatus(t, addr, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
		if status != http.StatusBadRequest {
			t.Errorf("CONNECT %s: status = %d, want 400", target, status)
		}
	}
}

func TestOriginFormRequestIs400(t *testing.T) {
	_, addr := startProxy(t, Options{})
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRequestsToItselfAreLoops(t *testing.T) {
	_, addr := startProxy(t, Options{})
	_, port, _ := net.SplitHostPort(addr)
	for _, req := range []string{
		fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr),
		fmt.Sprintf("CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port),
		fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr),
		fmt.Sprintf("GET http://[::1]:%s/ HTTP/1.1\r\nHost: [::1]:%s\r\n\r\n", port, port),
	} {
		if status := rawStatus(t, addr, req); status != http.StatusLoopDetected {
			t.Errorf("%q: status = %d, want 508", strings.SplitN(req, "\r\n", 2)[0], status)
		}
	}
}

func TestCloseEndsOpenTunnels(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	s, addr := startProxy(t, Options{})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	target := echo.Addr().String()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect}) // 2xx CONNECT has no body
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	fmt.Fprint(c, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through tunnel: %q %v", buf, err)
	}

	_ = s.Close()
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("after Close, read = %v, want EOF", err)
	}
}

func isReset(err error) bool {
	return err != nil && strings.Contains(err.Error(), "connection reset")
}

// fakeListener hands out the given connections, then blocks until closed.
type fakeListener struct {
	conns chan net.Conn
	done  chan struct{}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *fakeListener) Close() error   { close(l.done); return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func TestS2_1_RejectsNonLoopbackPeer(t *testing.T) {
	var logs []string
	s := New(Options{Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }})
	lanServer, lanClient := net.Pipe()
	loServer, loClient := net.Pipe()
	defer lanClient.Close()
	defer loClient.Close()
	fl := &fakeListener{conns: make(chan net.Conn, 2), done: make(chan struct{})}
	fl.conns <- addrConn{lanServer, &net.TCPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 50000}}
	fl.conns <- addrConn{loServer, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001}}
	gl := &guardListener{Listener: fl, s: s}

	c, err := gl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != "127.0.0.1:50001" {
		t.Fatalf("accepted %s, want the loopback peer", c.RemoteAddr())
	}
	_ = lanClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := lanClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("LAN peer read = %v, want closed", err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "non-loopback peer 192.168.1.20") {
		t.Fatalf("logs = %q", logs)
	}
}

func TestS2_2_ListensOnLoopbackOnly(t *testing.T) {
	lns, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}()
	port := lns[0].Addr().(*net.TCPAddr).Port
	for _, ln := range lns {
		a := ln.Addr().(*net.TCPAddr)
		if !a.IP.IsLoopback() || a.Port != port {
			t.Errorf("listening on %s, want loopback port %d", a, port)
		}
	}
}

func TestS5_1_Defaults(t *testing.T) {
	s := New(Options{})
	o := s.opts
	if o.MaxHeaderBytes != 1<<20 || o.ReadHeaderTimeout != 10*time.Second ||
		o.IdleTimeout != 90*time.Second || o.MaxConns != 1024 {
		t.Fatalf("defaults = %+v", o)
	}
	if s.http.MaxHeaderBytes != o.MaxHeaderBytes || s.http.ReadHeaderTimeout != o.ReadHeaderTimeout ||
		s.http.IdleTimeout != o.IdleTimeout {
		t.Fatalf("http.Server not configured from options")
	}
}

func TestS5_1_OversizedHeadersAre431(t *testing.T) {
	_, addr := startProxy(t, Options{MaxHeaderBytes: 4 << 10})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		_, _ = fmt.Fprintf(c, "GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nX-Big: %s\r\n\r\n",
			strings.Repeat("a", 64<<10))
	}()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}
}

func TestS5_1_SlowHeadersAreDropped(t *testing.T) {
	_, addr := startProxy(t, Options{ReadHeaderTimeout: 100 * time.Millisecond})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET http://example.invalid/ HTTP/1.1\r\n") // never finish the headers
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadAll(c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("proxy kept a connection with unfinished headers open")
	}
}

func TestS5_1_ConnectionLimitClosesExtraConnections(t *testing.T) {
	s, addr := startProxy(t, Options{MaxConns: 1})

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	// A full request and response proves the first connection holds the one slot.
	_, _ = io.WriteString(first, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(first), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("first connection: status %d", resp.StatusCode)
	}

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := second.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("second connection read = %v, want closed by the proxy", err)
	}

	_ = first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not released after the first connection closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err = http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("after a slot frees up: %v", err)
	}
	_ = resp.Body.Close()
}
