package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/ca"
	"github.com/esuEdu/wraith/internal/home"
)

func newCA(t *testing.T) *ca.CA {
	t.Helper()
	h, err := home.Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	c, _, err := ca.Load(h)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// upstreamServer starts a TLS server; h2 enables HTTP/2 on it.
func upstreamServer(t *testing.T, h2 bool, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = h2
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// logSink collects Logf lines.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
}

func (l *logSink) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type mitmEnv struct {
	ca   *ca.CA
	addr string
	srv  *Server
	log  *logSink
}

func startMITM(t *testing.T, upstreamRoots *x509.CertPool, tweak func(*Options)) *mitmEnv {
	t.Helper()
	e := &mitmEnv{ca: newCA(t), log: &logSink{}}
	opts := Options{Leaf: e.ca.Leaf, RootCAs: upstreamRoots, Logf: e.log.logf}
	if tweak != nil {
		tweak(&opts)
	}
	e.srv, e.addr = startProxy(t, opts)
	return e
}

// client returns an HTTP client using the proxy and trusting roots.
func (e *mitmEnv) client(roots *x509.CertPool, h2 bool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: e.addr}),
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			ForceAttemptHTTP2: h2,
		},
	}
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string, error) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, string(b), err
}

func TestDecryptsHTTP1(t *testing.T) {
	var sawProto string
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Proto
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	})
	e := startMITM(t, poolOf(ts.Certificate()), nil)

	resp, body, err := get(t, e.client(poolOf(e.ca.Certificate()), false), ts.URL+"/one")
	if err != nil {
		t.Fatal(err)
	}
	if body != "hello /one" || resp.Proto != "HTTP/1.1" || sawProto != "HTTP/1.1" {
		t.Fatalf("body %q client %s upstream %s", body, resp.Proto, sawProto)
	}
	if issuer := resp.TLS.PeerCertificates[0].Issuer.CommonName; !strings.HasPrefix(issuer, "wraith CA") {
		t.Fatalf("client saw a certificate from %q, want the wraith CA", issuer)
	}
	if !e.log.has("GET " + ts.URL + "/one 200") {
		t.Fatalf("decrypted request not logged:\n%s", e.log)
	}
}

func TestDecryptsHTTP2(t *testing.T) {
	var sawProto string
	ts := upstreamServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Proto
		_, _ = io.WriteString(w, "h2")
	})
	e := startMITM(t, poolOf(ts.Certificate()), nil)
	c := e.client(poolOf(e.ca.Certificate()), true)
	for i := range 3 { // several streams over one connection
		resp, body, err := get(t, c, fmt.Sprintf("%s/%d", ts.URL, i))
		if err != nil {
			t.Fatal(err)
		}
		if body != "h2" || resp.Proto != "HTTP/2.0" || sawProto != "HTTP/2.0" {
			t.Fatalf("body %q client %s upstream %s", body, resp.Proto, sawProto)
		}
	}
}

func TestR2_5_NoDecryptHostsAreSplicedUntouched(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "direct") })
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Decrypt = func(host string) bool { return host != "127.0.0.1" }
	})
	// The client trusts only the real upstream: it works only if wraith stays out of TLS.
	resp, body, err := get(t, e.client(poolOf(ts.Certificate()), false), ts.URL)
	if err != nil || body != "direct" {
		t.Fatalf("body %q err %v", body, err)
	}
	if resp.TLS.PeerCertificates[0].Equal(ts.Certificate()) == false {
		t.Fatal("client did not see the upstream's own certificate")
	}
}

func TestR2_4_RejectedCertificateSwitchesHostToPassThrough(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	e := startMITM(t, poolOf(ts.Certificate()), nil)
	pinning := e.client(poolOf(ts.Certificate()), false) // does not trust the wraith CA

	if _, _, err := get(t, pinning, ts.URL); err == nil {
		t.Fatal("first request through a rejected certificate succeeded")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !slices.Contains(e.srv.Pinned(), "127.0.0.1") {
		if time.Now().After(deadline) {
			t.Fatalf("host not marked pinned; log:\n%s", e.log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	pinning.CloseIdleConnections()
	resp, body, err := get(t, pinning, ts.URL)
	if err != nil || body != "ok" || !resp.TLS.PeerCertificates[0].Equal(ts.Certificate()) {
		t.Fatalf("second request: body %q err %v", body, err)
	}
	if !e.log.has("passing 127.0.0.1 through from now on") {
		t.Fatalf("log:\n%s", e.log)
	}
}

func TestS2_3_UpstreamCertificateIsVerified(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "secret") })
	e := startMITM(t, x509.NewCertPool(), nil) // upstream's certificate is not trusted
	resp, body, err := get(t, e.client(poolOf(e.ca.Certificate()), false), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway || body == "secret" {
		t.Fatalf("status %d body %q, want 502", resp.StatusCode, body)
	}
	if !e.log.has("upstream certificate rejected") {
		t.Fatalf("log:\n%s", e.log)
	}
}

func TestS2_3_UpstreamBelowTLS12IsRefused(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	ts.StartTLS()
	defer ts.Close()
	e := startMITM(t, poolOf(ts.Certificate()), nil)
	resp, _, err := get(t, e.client(poolOf(e.ca.Certificate()), false), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
}

func TestS2_4_InsecureUpstreamOnlyForNamedHosts(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "dev") })
	for _, tc := range []struct {
		hosts map[string]bool
		want  int
	}{
		{map[string]bool{"127.0.0.1": true}, http.StatusOK},
		{map[string]bool{"other.test": true}, http.StatusBadGateway},
	} {
		e := startMITM(t, x509.NewCertPool(), func(o *Options) { o.InsecureUpstream = tc.hosts })
		resp, _, err := get(t, e.client(poolOf(e.ca.Certificate()), false), ts.URL)
		if err != nil || resp.StatusCode != tc.want {
			t.Errorf("insecure %v: status %v err %v, want %d", tc.hosts, resp, err, tc.want)
		}
	}
}

func TestNonTLSTunnelsAreSpliced(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	e := startMITM(t, nil, nil)
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	target := echo.Addr().String()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	fmt.Fprint(c, "SSH-2.0-test\r\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "SSH-2.0-test\r\n" {
		t.Fatalf("echo through tunnel: %q %v", line, err)
	}
}

// captureHello returns the first TLS record Go's client sends for serverName.
func captureHello(t testing.TB, serverName string, alpn []string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		// Without a server name Go's client refuses to start unless verification is off;
		// nothing is verified here anyway, the handshake never gets past the hello.
		cfg := &tls.Config{ServerName: serverName, NextProtos: alpn, InsecureSkipVerify: serverName == ""}
		_ = tls.Client(a, cfg).Handshake()
	}()
	defer a.Close()
	defer b.Close()
	hdr := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	n, err := helloRecordLen(hdr)
	if err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, recordHeaderLen+n)
	copy(rec, hdr)
	if _, err := io.ReadFull(b, rec[recordHeaderLen:]); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestParseClientHello(t *testing.T) {
	h, err := parseClientHello(captureHello(t, "api.example.com", []string{"h2", "http/1.1"}))
	if err != nil || h.serverName != "api.example.com" || !slices.Equal(h.alpn, []string{"h2", "http/1.1"}) {
		t.Fatalf("parsed %+v, %v", h, err)
	}
	h, err = parseClientHello(captureHello(t, "", nil)) // no SNI (an IP target)
	if err != nil || h.serverName != "" || h.alpn != nil {
		t.Fatalf("no SNI: %+v, %v", h, err)
	}
	for _, bad := range [][]byte{nil, []byte("GET / HTTP/1.1\r\n"), {0x16, 3, 1, 0, 0}, {0x16, 3, 1, 0xff, 0xff}} {
		if _, err := parseClientHello(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	rec := captureHello(t, "x.test", nil)
	if _, err := parseClientHello(rec[:len(rec)-10]); err == nil {
		t.Error("truncated record accepted")
	}
}

// FuzzParseClientHello checks that no input makes the parser panic or report a name it
// did not see (S5.4). Run: go test -fuzz=FuzzParseClientHello ./internal/proxy
func FuzzParseClientHello(f *testing.F) {
	f.Add(captureHello(f, "api.example.com", []string{"h2", "http/1.1"}))
	f.Add(captureHello(f, "", nil))
	f.Add([]byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseClientHello(data)
		if err == nil && h.serverName != "" && !strings.Contains(string(data), h.serverName) {
			t.Fatalf("server name %q not in input", h.serverName)
		}
	})
}
