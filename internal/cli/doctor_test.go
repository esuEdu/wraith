package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/sysproxy"
)

func hasLine(out, status, text string) bool {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, status) && strings.Contains(l, text) {
			return true
		}
	}
	return false
}

func TestDoctorOnAHealthySetup(t *testing.T) {
	e := newEnv(t)
	if code := e.run("ca", "install"); code != ExitOK {
		t.Fatal("ca install failed")
	}
	e.stdout = &syncBuffer{}
	if code := e.run("doctor"); code != ExitOK {
		t.Fatalf("exit %d\n%s", code, e.stdout)
	}
	out := e.stdout.String()
	for _, want := range []struct{ status, text string }{
		{"ok", "config:"},
		{"info", "wraith is not running"},
		{"info", "system proxy: off"},
		{"ok", "CA: wraith CA"},
		{"info", "the Mac does not trust the CA"},
		{"ok", "iPhone 18 Pro Max"},
		{"warn", "interface:"}, // no usable interface in tests, and nothing to bypass
	} {
		if !hasLine(out, want.status, want.text) {
			t.Errorf("missing %q line with %q:\n%s", want.status, want.text, out)
		}
	}
	if strings.Contains(out, "bypass") {
		t.Errorf("doctor talks about the bypass with nothing to bypass:\n%s", out)
	}
}

func TestDoctorFindsProblems(t *testing.T) {
	e := newEnv(t)
	if code := e.run("bypass", "add", "api.example.test"); code != ExitOK {
		t.Fatal("bypass add failed")
	}
	h, err := home.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysproxy.New(e.fake, h, nil).Enable(context.Background(), 9090); err != nil { // then "crash"
		t.Fatal(err)
	}
	_ = h.Close()
	e.mac.Scutil = "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSPort : 9090\n  HTTPSProxy : 127.0.0.1\n}\n"

	e.stdout = &syncBuffer{}
	if code := e.run("doctor"); code != ExitState {
		t.Fatalf("exit %d, want %d\n%s", code, ExitState, e.stdout)
	}
	out := e.stdout.String()
	for _, want := range []string{
		"settings left by a run that did not exit cleanly",
		"points at wraith (127.0.0.1:9090) but wraith is not running",
		"interface:",
	} {
		if !hasLine(out, "fail", want) {
			t.Errorf("missing fail line with %q:\n%s", want, out)
		}
	}
	if !hasLine(out, "warn", "bypass: the VPN bypass is deprecated") {
		t.Errorf("no deprecation line for the bypass list:\n%s", out)
	}
	if !hasLine(out, "info", "CA: not created yet") {
		t.Errorf("no CA line:\n%s", out)
	}
}
