package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/esuEdu/wraith/internal/sim/simtest"
)

// complete is what the shell gets for `wraith args... <tab>`, the last arg being typed.
func (e *env) complete(args ...string) []string {
	e.t.Helper()
	before := len(e.stdout.String())
	if code := e.run(append([]string{"__complete"}, args...)...); code != ExitOK {
		e.t.Fatalf("__complete %v: exit %d\n%s", args, code, e.stderr)
	}
	var vals []string
	for _, line := range strings.Split(strings.TrimSpace(e.stdout.String()[before:]), "\n") {
		if !strings.HasPrefix(line, ":") {
			v, _, _ := strings.Cut(line, "\t")
			vals = append(vals, v)
		}
	}
	return vals
}

func TestTabCompletesCommandsFlagsAndValues(t *testing.T) {
	e := newEnv(t)
	if got := e.complete("st"); strings.Join(got, " ") != "start stop" {
		t.Fatalf("wraith st<tab>: %v", got)
	}
	if got := e.complete("start", "--dev"); strings.Join(got, " ") != "--device" {
		t.Fatalf("wraith start --dev<tab>: %v", got)
	}
	if got := e.complete("bypass", "rm", ""); len(got) != 0 {
		t.Fatalf("nothing bypassed yet, but offered %v", got)
	}
	if _, err := os.Stat(e.dir); !os.IsNotExist(err) {
		t.Fatalf("tab created %s (%v)", e.dir, err)
	}

	if code := e.run("bypass", "add", "api.partner.io", "*.cdn.test"); code != ExitOK {
		t.Fatalf("bypass add: %d\n%s", code, e.stderr)
	}
	if got := e.complete("bypass", "rm", "api"); strings.Join(got, " ") != "api.partner.io" {
		t.Fatalf("bypass rm api<tab>: %v", got)
	}
	if got := e.complete("doctor", "--host", ""); strings.Join(got, " ") != "api.partner.io" {
		t.Fatalf("doctor --host <tab> offers patterns: %v", got)
	}

	h := e.home()
	if err := saveDevices(h, []rememberedDevice{{IP: "192.168.15.2", Kind: "iPhone", Network: "192.168.15.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if got := e.complete("devices", "forget", ""); strings.Join(got, " ") != "all 192.168.15.2" {
		t.Fatalf("devices forget <tab>: %v", got)
	}

	src := e.complete("start", "--source", "")
	for _, want := range []string{"simulator", "all", "device", "simulator:" + simtest.Booted, "device:192.168.15.2"} {
		if !strings.Contains(" "+strings.Join(src, " ")+" ", " "+want+" ") {
			t.Errorf("start --source <tab> misses %q: %v", want, src)
		}
	}
	for _, v := range e.complete("start", "--source", "sim") {
		if !strings.HasPrefix(v, "sim") {
			t.Errorf("start --source sim<tab> offers %q", v)
		}
	}
	if got := e.complete("ca", "install", "--sim", ""); strings.Join(got, " ") != simtest.Booted {
		t.Fatalf("ca install --sim <tab>: %v", got)
	}
	if got := e.complete("start", "--iface", ""); len(got) == 0 || got[0] != "auto" {
		t.Fatalf("start --iface <tab>: %v", got)
	}
	if got := e.complete("version", ""); len(got) != 0 {
		t.Fatalf("version takes nothing, but tab offers %v", got)
	}
}
