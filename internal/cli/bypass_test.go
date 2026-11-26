package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTheBypassCommandsAreGone(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{{"bypass", "add", "api.partner.io"}, {"bypass", "list"}, {"bypass"}} {
		e.stderr = &syncBuffer{}
		if code := e.run(args...); code != ExitUsage || !strings.Contains(e.stderr.String(), "the VPN bypass was removed in wraith v2.0.0") {
			t.Fatalf("%v: exit %d stderr %q", args, code, e.stderr)
		}
	}
	e.stdout = &syncBuffer{}
	if code := e.run("--help"); code != ExitOK || strings.Contains(e.stdout.String(), "bypass") {
		t.Fatalf("help still lists bypass:\n%s", e.stdout)
	}
}

func TestAnOldBypassListIsIgnoredWithAWarning(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "config.yaml"), []byte("bypass: ['*.corp.example.com']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if !strings.Contains(e.stderr.String(), "warning: config.yaml still has a bypass list of 1 host(s), now ignored") {
		t.Fatalf("start does not warn about the old list:\n%s", e.stderr)
	}
}
