package cli

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/sim/simtest"
	"github.com/esuEdu/wraith/internal/source"
)

// fetch requests target through the proxy at addr, trusting roots.
func fetch(t *testing.T, addr, target string, roots *x509.CertPool) (*http.Response, string) {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func upstreamTLS(t *testing.T) (*httptest.Server, *x509.CertPool) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(ts.Close)
	p := x509.NewCertPool()
	p.AddCert(ts.Certificate())
	return ts, p
}

var curl = source.Origin{PID: 777, Chain: []source.Process{{PID: 777, Path: "/usr/bin/curl"}, {PID: 1}}}

func TestR1_3_ConnectionsOutsideTheSourceAreUntouchedAndUnseen(t *testing.T) {
	ts, upstreamRoots := upstreamTLS(t)
	e := newEnv(t)
	e.origin = curl // a Mac process; the default source is simulator
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	resp, body := fetch(t, addr, ts.URL+"/private", upstreamRoots)
	if body != "ok" || !resp.TLS.PeerCertificates[0].Equal(ts.Certificate()) {
		t.Fatalf("not passed through untouched: body %q", body)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if strings.Contains(e.stdout.String(), "private") || strings.Contains(e.stdout.String(), "CONNECT") {
		t.Fatalf("a connection outside the source was shown:\n%s", e.stdout)
	}
	if !strings.Contains(e.stderr.String(), "capturing simulator; everything else passes through untouched") {
		t.Fatalf("stderr:\n%s", e.stderr)
	}
}

func TestR1_4_UnidentifiedConnectionsAreOutsideTheSource(t *testing.T) {
	ts, upstreamRoots := upstreamTLS(t)
	e := newEnv(t)
	e.originErr = source.ErrUnknown
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--source", "all")
	if _, body := fetch(t, addr, ts.URL, upstreamRoots); body != "ok" {
		t.Fatalf("body %q", body)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if strings.TrimSpace(e.stdout.String()) != "" {
		t.Fatalf("an unidentified connection was shown:\n%s", e.stdout)
	}
}

func TestR1_1_MacAppsInTheSourceAreDecryptedOnlyWhenTheMacTrustsTheCA(t *testing.T) {
	ts, upstreamRoots := upstreamTLS(t)
	for _, trusted := range []bool{false, true} {
		e := newEnv(t)
		e.origin = curl
		e.macTrusts = trusted
		addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--source", "pid:777", "--insecure-upstream", "127.0.0.1")
		roots := upstreamRoots
		if trusted {
			roots = x509.NewCertPool()
			roots.AppendCertsFromPEM([]byte(readCAPEM(t, e)))
		}
		resp, body := fetch(t, addr, ts.URL+"/x", roots)
		issuer := resp.TLS.PeerCertificates[0].Issuer.CommonName
		e.sigs <- syscall.SIGTERM
		waitExit(t, done)
		decrypted := strings.HasPrefix(issuer, "wraith CA")
		if body != "ok" || decrypted != trusted {
			t.Fatalf("mac trusts %v: decrypted %v (issuer %q)", trusted, decrypted, issuer)
		}
		want := "[curl] CONNECT"
		if trusted {
			want = "[curl] GET " + ts.URL + "/x 200"
		}
		if !strings.Contains(e.stdout.String(), want) {
			t.Fatalf("mac trusts %v: want %q in\n%s", trusted, want, e.stdout)
		}
	}
}

func readCAPEM(t *testing.T, e *env) string {
	t.Helper()
	b, err := readFile(e.dir + "/ca/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func TestSimulatorNamesLoadInTheBackground(t *testing.T) {
	e := newEnv(t)
	sm, err := e.newSimManager()
	if err != nil {
		t.Fatal(err)
	}
	n := newSimNames(sm)
	if got := n.name(simtest.Booted); got != simtest.Booted[:8] {
		t.Fatalf("before loading: %q, want the UDID's start", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for n.name(simtest.Booted) != "iPhone 18 Pro Max" {
		if time.Now().After(deadline) {
			t.Fatal("name never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestR1_1_SimulatorByNameMatchesFromTheFirstConnection(t *testing.T) {
	ts, _ := upstreamTLS(t)
	e := newEnv(t) // the default origin is a simulator app on simtest.Booted
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--source", "simulator:iPhone 18 Pro Max", "--insecure-upstream", "127.0.0.1")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(readCAPEM(t, e)))
	resp, _ := fetch(t, addr, ts.URL+"/first", roots)
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if !strings.HasPrefix(resp.TLS.PeerCertificates[0].Issuer.CommonName, "wraith CA") ||
		!strings.Contains(e.stdout.String(), "[sim iPhone 18 Pro Max · Shop] GET "+ts.URL+"/first 200") {
		t.Fatalf("first connection not matched by name:\n%s", e.stdout)
	}
}
