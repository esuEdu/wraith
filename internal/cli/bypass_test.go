package cli

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestR6_2_BypassCommandsEditTheConfigFile(t *testing.T) {
	e := newEnv(t)
	if code := e.run("bypass", "add", "*.Corp.Example.com", "api.partner.io"); code != ExitOK {
		t.Fatalf("add: exit %d stderr %q", code, e.stderr)
	}
	if code := e.run("bypass", "add", "api.partner.io"); code != ExitOK || !strings.Contains(e.stderr.String(), "already on the bypass list") {
		t.Fatalf("duplicate add: exit %d", code)
	}
	if code := e.run("bypass", "add", "https://x.com"); code != ExitUsage {
		t.Fatalf("bad pattern: exit %d", code)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"*.corp.example.com"`) || !strings.Contains(string(b), "# wraith configuration") {
		t.Fatalf("config.yaml:\n%s", b)
	}
	if code := e.run("bypass", "list"); code != ExitOK || e.stdout.String() != "*.corp.example.com\napi.partner.io\n" {
		t.Fatalf("list: exit %d stdout %q", code, e.stdout)
	}
	if code := e.run("bypass", "rm", "api.partner.io"); code != ExitOK {
		t.Fatalf("rm: exit %d", code)
	}
	if code := e.run("bypass", "rm", "api.partner.io"); code != ExitRuntime {
		t.Fatalf("rm of an absent entry: exit %d", code)
	}
	e.stdout = &syncBuffer{}
	if code := e.run("bypass", "list"); code != ExitOK || e.stdout.String() != "*.corp.example.com\n" {
		t.Fatalf("list after rm: %q", e.stdout)
	}
	if !strings.Contains(e.stderr.String(), "interface:") {
		t.Fatalf("list does not report the interface: %q", e.stderr)
	}
}

func TestBypassIsDeprecated(t *testing.T) {
	e := newEnv(t)
	if code := e.run("bypass", "list"); code != ExitOK {
		t.Fatalf("list: exit %d", code)
	}
	if !strings.Contains(e.stderr.String(), "warning: the VPN bypass is deprecated and will be removed in wraith v2.0.0") {
		t.Fatalf("bypass list does not warn: %q", e.stderr)
	}
	if code := e.run("bypass", "add", "api.partner.io"); code != ExitOK {
		t.Fatalf("add: exit %d", code)
	}
	e.stderr = &syncBuffer{}
	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if !strings.Contains(e.stderr.String(), "warning: config.yaml has a bypass list: the VPN bypass is deprecated") {
		t.Fatalf("start with a bypass list does not warn: %q", e.stderr)
	}
}

func TestR3_3_BypassAppliesToEveryConnectionAndFailsClosed(t *testing.T) {
	ts, upstreamRoots := upstreamTLS(t)
	_, port, _ := strings.Cut(strings.TrimPrefix(ts.URL, "https://127.0.0.1"), ":")
	bypassed := "https://localhost:" + port + "/"

	for _, inSource := range []bool{false, true} {
		e := newEnv(t)
		if !inSource {
			e.origin = curl // outside the default simulator source
		}
		if code := e.run("bypass", "add", "localhost"); code != ExitOK {
			t.Fatal("bypass add failed")
		}
		// The test env has no usable interface, so every bypass must fail, and never
		// reach the upstream the normal way (R3.4).
		addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--insecure-upstream", "127.0.0.1")
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		}}
		if resp, err := c.Get(bypassed); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("in source %v: bypassed host reached, status %d", inSource, resp.StatusCode)
		}
		roots := upstreamRoots // outside the source: spliced, the upstream's own certificate
		if inSource {          // inside: decrypted with the wraith CA
			roots = x509.NewCertPool()
			roots.AppendCertsFromPEM([]byte(readCAPEM(t, e)))
		}
		if _, body := fetch(t, addr, ts.URL, roots); body != "ok" {
			t.Fatalf("in source %v: other host: body %q", inSource, body)
		}
		e.sigs <- syscall.SIGTERM
		waitExit(t, done)
		if !strings.Contains(e.stderr.String(), "will fail, never use the VPN") {
			t.Fatalf("no bypass warning:\n%s", e.stderr)
		}
		shown := strings.Contains(e.stdout.String(), "CONNECT localhost:"+port+" 502 failed")
		if shown != inSource {
			t.Fatalf("in source %v: failed bypass shown %v:\n%s", inSource, shown, e.stdout)
		}
	}
}
