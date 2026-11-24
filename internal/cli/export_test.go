package cli

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shortDir is a home directory under /tmp, short enough for a Unix socket path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "wr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, "w")
}

func TestS3_5_ExportReadsTheRunningInstanceOverAPrivateSocket(t *testing.T) {
	ts, _ := upstreamTLS(t)
	e := newEnv(t)
	e.dir = shortDir(t)
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--insecure-upstream", "127.0.0.1")

	sock := filepath.Join(e.dir, "wraith.sock")
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", fi, err)
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}), TLSClientConfig: tlsConfig(caPool(t, e)),
	}}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/account?access_token=SECRETQ", nil)
	req.Header.Set("Authorization", "Bearer SECRETAUTH")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	waitUntil(t, "the flow to be stored", func() bool { return strings.Contains(e.stdout.String(), "/account") })

	out := filepath.Join(t.TempDir(), "flows.har")
	other := newEnvSharing(e)
	if code := other.run("export", "--har", out); code != ExitOK {
		t.Fatalf("export: exit %d stderr %q", code, other.stderr)
	}
	b, _ := os.ReadFile(out)
	fi, _ := os.Stat(out)
	if !strings.Contains(string(b), ts.URL+"/account") || strings.Contains(string(b), "SECRET") || fi.Mode().Perm() != 0o600 {
		t.Fatalf("export (mode %v):\n%s", fi.Mode().Perm(), b)
	}
	if code := other.run("export", "--har", out); code != ExitRuntime {
		t.Fatalf("export over an existing file: exit %d", code)
	}
	if code := other.run("export", "--har", out, "--force", "--no-redact"); code != ExitOK {
		t.Fatal("export --force --no-redact failed")
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "Bearer SECRETAUTH") {
		t.Fatal("--no-redact did not keep the header")
	}

	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("socket left after stop")
	}
	if code := other.run("export", "--har", filepath.Join(t.TempDir(), "x.har")); code != ExitRuntime ||
		!strings.Contains(other.stderr.String(), "not running") {
		t.Fatalf("export with nothing running: exit %d stderr %q", code, other.stderr)
	}
}
