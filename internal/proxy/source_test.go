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

	"github.com/esuEdu/wraith/internal/store"
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
	if out := e.log.String(); out != "" || len(e.store.Flows()) != 0 {
		t.Fatalf("connections outside the source were shown or stored:\n%s\n%+v", out, e.store.Flows())
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
	e.waitFlow(t, "labelled with its source", func(f store.Flow) bool {
		return f.Source == "sim iPhone 17 · Shop" && f.URL == ts.URL+"/x" && f.Status == 200
	})
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
	e.waitFlow(t, "for the tunnel", func(f store.Flow) bool {
		return f.Kind == store.KindTunnel && f.Source == "Google Chrome" && f.URL == ts.Listener.Addr().String() && f.Status == 200
	})
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
	e.waitFlow(t, "with route direct", func(f store.Flow) bool { return f.URL == ts.URL+"/r" && f.Route == "direct" })

	failing := startMITM(t, nil, func(o *Options) {
		o.Dialer = hangingDialer{}
		o.DialTimeout = 50 * time.Millisecond
		o.Route = func(string) string { return "direct" }
	})
	if status := rawStatus(t, failing.addr, "CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n"); status != http.StatusBadGateway {
		t.Fatalf("status %d", status)
	}
	failing.waitFlow(t, "for the failed bypass", func(f store.Flow) bool {
		return f.Kind == store.KindTunnel && f.URL == "blocked.test:443" && f.Status == 502 && f.Route == "failed"
	})
}

func TestR5_1_BodiesAreCapturedUpToTheLimitAndStreamedWhole(t *testing.T) {
	big := strings.Repeat("b", 100)
	ts := upstreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, big+string(got))
	})
	st := store.New(10, 16) // keep 16 bytes per body
	e := startMITM(t, poolOf(ts.Certificate()), func(o *Options) { o.Store = st })
	e.store = st
	c := e.client(poolOf(e.ca.Certificate()), false)
	resp, err := c.Post(ts.URL+"/up", "text/plain", strings.NewReader(strings.Repeat("q", 40)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if len(body) != 140 {
		t.Fatalf("client got %d bytes, want the whole 140", len(body))
	}
	f := e.waitFlow(t, "for the POST", func(f store.Flow) bool { return f.URL == ts.URL+"/up" })
	if f.ReqBody.Size != 40 || len(f.ReqBody.Data) != 16 || !f.ReqBody.Truncated ||
		f.RespBody.Size != 140 || len(f.RespBody.Data) != 16 || !f.RespBody.Truncated {
		t.Fatalf("captured req %+v resp %+v", f.ReqBody, f.RespBody)
	}
	if f.ReqHeader.Get("Content-Type") != "text/plain" || f.RespHeader.Get("Content-Length") == "" && f.RespHeader.Get("Date") == "" {
		t.Fatalf("headers not captured: %v %v", f.ReqHeader, f.RespHeader)
	}
}
