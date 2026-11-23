package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestR1_3_OutsideTheSourcePassesThroughUnseen(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "upstream") })
	plain := httptestPlain(t)
	var calls atomic.Int32
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Classify = func(context.Context, net.Addr, net.Addr) Verdict {
			calls.Add(1)
			return Verdict{InSource: false}
		}
	})

	// HTTPS: the client trusts only the real upstream, so this works only if wraith
	// stays out of the TLS session.
	c := e.client(poolOf(ts.Certificate()), false)
	resp, body, err := get(t, c, ts.URL+"/secret")
	if err != nil || body != "upstream" || !resp.TLS.PeerCertificates[0].Equal(ts.Certificate()) {
		t.Fatalf("outside-source https: body %q err %v", body, err)
	}
	// Plain HTTP is forwarded too, but not shown either.
	if _, body, err := get(t, e.client(nil, false), plain+"/plain"); err != nil || body != "plain" {
		t.Fatalf("outside-source http: body %q err %v", body, err)
	}
	if out := e.log.String(); out != "" {
		t.Fatalf("connections outside the source were logged:\n%s", out)
	}
	if calls.Load() < 2 {
		t.Fatalf("Classify called %d times, want once per connection", calls.Load())
	}
}

func TestInsideTheSourceIsDecryptedAndLabeled(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Classify = func(context.Context, net.Addr, net.Addr) Verdict {
			return Verdict{InSource: true, Decrypt: true, Label: "sim iPhone 17 · Shop"}
		}
	})
	resp, _, err := get(t, e.client(poolOf(e.ca.Certificate()), false), ts.URL+"/x")
	if err != nil || !strings.HasPrefix(resp.TLS.PeerCertificates[0].Issuer.CommonName, "wraith CA") {
		t.Fatalf("not decrypted: %v", err)
	}
	if !e.log.has("[sim iPhone 17 · Shop] GET " + ts.URL + "/x 200") {
		t.Fatalf("log:\n%s", e.log)
	}
}

func TestInSourceButNotDecryptableIsSplicedAndShown(t *testing.T) {
	// A Mac app inside the source when the Mac does not trust the CA.
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Classify = func(context.Context, net.Addr, net.Addr) Verdict {
			return Verdict{InSource: true, Decrypt: false, Label: "Google Chrome"}
		}
	})
	resp, body, err := get(t, e.client(poolOf(ts.Certificate()), false), ts.URL)
	if err != nil || body != "ok" || !resp.TLS.PeerCertificates[0].Equal(ts.Certificate()) {
		t.Fatalf("body %q err %v", body, err)
	}
	if !e.log.has("[Google Chrome] CONNECT 127.0.0.1:") {
		t.Fatalf("tunnel not shown:\n%s", e.log)
	}
}

func httptestPlain(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return (&url.URL{Scheme: "http", Host: ln.Addr().String()}).String()
}

func TestR3_5_EachConnectionShowsItsRoute(t *testing.T) {
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) {
		o.Route = func(host string) string {
			if host == "127.0.0.1" {
				return "direct"
			}
			return "vpn"
		}
	})
	if _, _, err := get(t, e.client(poolOf(e.ca.Certificate()), false), ts.URL+"/r"); err != nil {
		t.Fatal(err)
	}
	if !e.log.has("CONNECT "+ts.Listener.Addr().String()+" 200 direct") || !e.log.has("GET "+ts.URL+"/r 200 HTTP/1.1 direct") {
		t.Fatalf("direct route not shown:\n%s", e.log)
	}

	failing := startMITM(t, nil, func(o *Options) {
		o.Dialer = hangingDialer{}
		o.DialTimeout = 50 * time.Millisecond
		o.Route = func(string) string { return "direct" }
	})
	if status := rawStatus(t, failing.addr, "CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n"); status != http.StatusBadGateway {
		t.Fatalf("status %d", status)
	}
	if !failing.log.has("CONNECT blocked.test:443 502 failed") {
		t.Fatalf("failed bypass not shown as failed:\n%s", failing.log)
	}
}
