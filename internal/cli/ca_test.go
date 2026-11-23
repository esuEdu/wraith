package cli

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/sim/simtest"
)

// caSum returns the hex SHA-256 of the CA certificate stored in e's home directory.
func (e *env) caSum() string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "ca", "ca.pem"))
	if err != nil {
		e.t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	return simtest.HexSum(blk.Bytes)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestR2_2_StartDecryptPutsTheCAIntoSimulatorsOnly(t *testing.T) {
	e := newEnv(t)
	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	sum := e.caSum()
	waitUntil(t, "the booted simulator to get the CA", func() bool { return e.sims.Trusts(simtest.Booted, sum) })

	e.sims.SetState(simtest.Shutdown, "Booted") // R1.6: booted while wraith runs
	waitUntil(t, "the newly booted simulator to get the CA", func() bool { return e.sims.Trusts(simtest.Shutdown, sum) })

	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	for _, c := range e.fake.Calls() {
		if strings.HasPrefix(c, "security ") && !strings.HasPrefix(c, "security verify-cert ") {
			t.Fatalf("changed the Mac keychain: %q", c) // R2.2: reading trust state is all
		}
	}
	if !strings.Contains(e.stderr.String(), "the Mac does not trust the wraith CA") {
		t.Fatalf("start did not say whether the Mac trusts the CA (S1.5):\n%s", e.stderr)
	}
}

func TestR2_3_MacTrustOnlyWithExplicitConsent(t *testing.T) {
	adds := func(e *env) int {
		n := 0
		for _, c := range e.fake.Calls() {
			if strings.HasPrefix(c, "security add-trusted-cert") {
				n++
			}
		}
		return n
	}

	e := newEnv(t)
	if code := e.run("ca", "trust"); code != ExitUsage {
		t.Fatalf("trust without --mac: exit %d", code)
	}
	for _, answer := range []string{"", "n\n", "nope\n"} {
		e.stdin = answer
		if code := e.run("ca", "trust", "--mac"); code != ExitRuntime || adds(e) != 0 || e.macTrusts {
			t.Fatalf("answer %q: exit %d, %d add calls", answer, code, adds(e))
		}
	}
	if !strings.Contains(e.stderr.String(), "every app on this Mac") || !strings.Contains(e.stderr.String(), "[y/N]") {
		t.Fatalf("no warning or question (S1.5):\n%s", e.stderr)
	}

	e.stdin = "y\n"
	if code := e.run("ca", "trust", "--mac"); code != ExitOK || !e.macTrusts || adds(e) != 1 {
		t.Fatalf("after yes: exit %d trusted %v", code, e.macTrusts)
	}
	if code := e.run("ca", "trust", "--mac"); code != ExitOK || adds(e) != 1 || !strings.Contains(e.stderr.String(), "already trusts") {
		t.Fatalf("trust when already trusted: exit %d, %d adds", code, adds(e))
	}

	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	if !strings.Contains(e.stderr.String(), "the Mac trusts the wraith CA") {
		t.Fatalf("start did not show the Mac trusts the CA:\n%s", e.stderr)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)

	if code := e.run("ca", "untrust", "--mac"); code != ExitOK || e.macTrusts || !strings.Contains(e.stderr.String(), "no longer trusts") {
		t.Fatalf("untrust: exit %d trusted %v", code, e.macTrusts)
	}
	if code := e.run("ca", "untrust", "--mac"); code != ExitOK || !strings.Contains(e.stderr.String(), "did not trust") {
		t.Fatalf("second untrust: exit %d", code)
	}

	y := newEnv(t)
	if code := y.run("ca", "trust", "--mac", "--yes"); code != ExitOK || !y.macTrusts {
		t.Fatalf("--yes: exit %d trusted %v", code, y.macTrusts)
	}
}

func TestCAInstallExportRemove(t *testing.T) {
	e := newEnv(t)
	if code := e.run("ca", "install"); code != ExitOK || !strings.Contains(e.stderr.String(), "installed the wraith CA") {
		t.Fatalf("install: exit %d stderr %q", code, e.stderr)
	}
	sum := e.caSum()
	if !e.sims.Trusts(simtest.Booted, sum) || e.sims.Trusts(simtest.Shutdown, sum) {
		t.Fatal("install should reach the booted simulator only")
	}
	if code := e.run("ca", "install"); code != ExitOK || !strings.Contains(e.stderr.String(), "already trusts") {
		t.Fatalf("second install: exit %d stderr %q", code, e.stderr)
	}
	if code := e.run("ca", "install", "--sim", simtest.Shutdown); code != ExitRuntime {
		t.Fatalf("install into a shut-down simulator: exit %d", code)
	}
	if code := e.run("ca", "install", "--sim", "booted"); code != ExitUsage {
		t.Fatalf("bad --sim: exit %d", code)
	}

	out := filepath.Join(t.TempDir(), "wraith-ca.pem")
	if code := e.run("ca", "export", out); code != ExitOK {
		t.Fatalf("export: exit %d stderr %q", code, e.stderr)
	}
	if code := e.run("ca", "export", out); code != ExitRuntime {
		t.Fatalf("export over an existing file: exit %d", code)
	}
	if code := e.run("ca", "export", "--force", out); code != ExitOK {
		t.Fatalf("export --force: exit %d", code)
	}

	if err := e.sims.AddTrust(simtest.Shutdown, sum); err != nil { // trusted earlier, now shut down
		t.Fatal(err)
	}
	if code := e.run("ca", "remove"); code != ExitOK {
		t.Fatalf("remove: exit %d stderr %q", code, e.stderr)
	}
	if e.sims.Trusts(simtest.Booted, sum) || e.sims.Trusts(simtest.Shutdown, sum) {
		t.Fatal("CA left in a simulator after remove")
	}
	if !strings.Contains(e.stderr.String(), "restart the simulator") {
		t.Fatalf("no restart hint for the booted simulator: %q", e.stderr)
	}
	e.stderr = &syncBuffer{}
	if code := e.run("ca", "remove"); code != ExitOK || !strings.Contains(e.stderr.String(), "no simulator trusted") {
		t.Fatalf("second remove: exit %d stderr %q", code, e.stderr)
	}
}

func TestS1_3_ExportWritesTheCertificateNeverTheKey(t *testing.T) {
	e := newEnv(t)
	out := filepath.Join(t.TempDir(), "ca.pem")
	if code := e.run("ca", "export", out); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "BEGIN CERTIFICATE") || strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatalf("exported %q", b)
	}
}

func TestCARemoveWithoutACADoesNotCreateOne(t *testing.T) {
	e := newEnv(t)
	if code := e.run("ca", "remove"); code != ExitOK || !strings.Contains(e.stderr.String(), "nothing to remove") {
		t.Fatalf("exit %d stderr %q", code, e.stderr)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "ca", "ca.key")); err == nil {
		t.Fatal("ca remove created a CA")
	}
}

func TestS1_4_RotateReplacesTheCAInSimulators(t *testing.T) {
	e := newEnv(t)
	if code := e.run("ca", "install"); code != ExitOK {
		t.Fatal("install failed")
	}
	old := e.caSum()
	if code := e.run("ca", "rotate"); code != ExitOK {
		t.Fatalf("rotate: exit %d stderr %q", code, e.stderr)
	}
	fresh := e.caSum()
	if fresh == old || e.sims.Trusts(simtest.Booted, old) || !e.sims.Trusts(simtest.Booted, fresh) {
		t.Fatalf("after rotate: old trusted %v, new trusted %v", e.sims.Trusts(simtest.Booted, old), e.sims.Trusts(simtest.Booted, fresh))
	}

	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	if code := newEnvSharing(e).run("ca", "rotate"); code != ExitRuntime {
		t.Fatalf("rotate while running: exit %d, want %d", code, ExitRuntime)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
}

// newEnvSharing returns an env on the same home directory and fakes as e.
func newEnvSharing(e *env) *env {
	o := newEnv(e.t)
	o.dir, o.mac, o.sims, o.fake = e.dir, e.mac, e.sims, e.fake
	return o
}
