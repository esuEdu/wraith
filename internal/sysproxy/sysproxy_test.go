package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
)

// fakeMac is a stateful networksetup + scutil that answers in the real tools' formats
// (see testdata/tools, recorded on a Mac).
type fakeMac struct {
	mu        sync.Mutex
	order     []string
	disabled  map[string]bool
	web       map[string]Setting
	secure    map[string]Setting
	pac       map[string]string // service -> PAC URL when enabled
	autodisc  map[string]bool
	scutil    string
	failOn    string // a command line prefix that fails
	beforeSet func() // called before the first set command
	setSeen   bool
}

func newFakeMac() *fakeMac {
	return &fakeMac{
		order:    []string{"USB 10/100/1000 LAN", "Thunderbolt Bridge", "Wi-Fi"},
		disabled: map[string]bool{"USB 10/100/1000 LAN": true},
		web: map[string]Setting{
			"Wi-Fi":               {Enabled: false, Server: "127.0.0.1", Port: 8888},
			"Thunderbolt Bridge":  {Enabled: true, Server: "proxy.corp.example", Port: 3128},
			"USB 10/100/1000 LAN": {},
		},
		secure: map[string]Setting{
			"Wi-Fi":               {Enabled: false, Server: "127.0.0.1", Port: 8888},
			"Thunderbolt Bridge":  {},
			"USB 10/100/1000 LAN": {},
		},
		pac:      map[string]string{},
		autodisc: map[string]bool{},
		scutil:   readFixture(nil, "scutil-proxy-none.txt"),
	}
}

func readFixture(t *testing.T, name string) string {
	b, err := os.ReadFile(filepath.Join("testdata", "tools", name))
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return string(b)
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func (f *fakeMac) run(tool string, args []string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(append([]string{tool}, args...), " ")
	if f.failOn != "" && strings.HasPrefix(line, f.failOn) {
		return nil, fmt.Errorf("fake failure: %s", line)
	}
	if tool == "scutil" && len(args) == 1 && args[0] == "--proxy" {
		return []byte(f.scutil), nil
	}
	if tool != "networksetup" || len(args) == 0 {
		return nil, fmt.Errorf("unexpected call %q", line)
	}
	verb := args[0]
	if verb == "-listallnetworkservices" {
		var b strings.Builder
		b.WriteString("An asterisk (*) denotes that a network service is disabled.\n")
		for _, s := range f.order {
			if f.disabled[s] {
				b.WriteString("*")
			}
			b.WriteString(s)
			b.WriteString("\n")
		}
		return []byte(b.String()), nil
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("unexpected call %q", line)
	}
	svc := args[1]
	if _, ok := f.web[svc]; !ok {
		return nil, fmt.Errorf("** Error: The parameters were not valid. (%s)", line)
	}
	if strings.HasPrefix(verb, "-set") && !f.setSeen {
		f.setSeen = true
		if f.beforeSet != nil {
			f.mu.Unlock()
			f.beforeSet()
			f.mu.Lock()
		}
	}
	pick := func(secure bool) map[string]Setting {
		if secure {
			return f.secure
		}
		return f.web
	}
	switch verb {
	case "-getwebproxy", "-getsecurewebproxy":
		s := pick(verb == "-getsecurewebproxy")[svc]
		auth := 0
		if s.Auth {
			auth = 1
		}
		return fmt.Appendf(nil, "Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: %d\n",
			yesNo(s.Enabled), s.Server, s.Port, auth), nil
	case "-setwebproxy", "-setsecurewebproxy":
		if len(args) != 4 {
			return nil, fmt.Errorf("unexpected call %q", line)
		}
		port, err := strconv.Atoi(args[3])
		if err != nil {
			return nil, err
		}
		m := pick(verb == "-setsecurewebproxy")
		s := m[svc]
		s.Server, s.Port, s.Enabled = args[2], port, true
		m[svc] = s
		return nil, nil
	case "-setwebproxystate", "-setsecurewebproxystate":
		m := pick(verb == "-setsecurewebproxystate")
		s := m[svc]
		s.Enabled = args[2] == "on"
		m[svc] = s
		return nil, nil
	case "-getautoproxyurl":
		if u, ok := f.pac[svc]; ok {
			return []byte("URL: " + u + "\nEnabled: Yes\n"), nil
		}
		return []byte(readFixture(nil, "getautoproxyurl-off.txt")), nil
	case "-getproxyautodiscovery":
		if f.autodisc[svc] {
			return []byte("Auto Proxy Discovery: On\n"), nil
		}
		return []byte(readFixture(nil, "getproxyautodiscovery-off.txt")), nil
	}
	return nil, fmt.Errorf("unexpected call %q", line)
}

func (f *fakeMac) settings() (map[string]Setting, map[string]Setting) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := func(m map[string]Setting) map[string]Setting {
		out := map[string]Setting{}
		maps.Copy(out, m)
		return out
	}
	return cp(f.web), cp(f.secure)
}

func setup(t *testing.T) (*Manager, *fakeMac, *home.Home) {
	t.Helper()
	h, err := home.Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	mac := newFakeMac()
	fake := execx.NewFake()
	fake.Handler = mac.run
	return New(fake, h, nil), mac, h
}

func stateExists(h *home.Home) bool {
	_, err := h.ReadFile(StateFile)
	return err == nil
}

func TestParsesRecordedToolOutput(t *testing.T) {
	list := parseServices([]byte(readFixture(t, "listallnetworkservices.txt")))
	if len(list) < 2 {
		t.Fatalf("services = %+v", list)
	}
	for _, s := range list {
		if strings.Contains(s.name, "asterisk") || strings.HasPrefix(s.name, "*") {
			t.Fatalf("header or marker kept in %+v", s)
		}
	}
	s, err := parseSetting([]byte(readFixture(t, "getwebproxy-disabled.txt")))
	if err != nil || s.Enabled || s.Server != "127.0.0.1" || s.Port != 8888 || s.Auth {
		t.Fatalf("disabled proxy parsed as %+v, %v", s, err)
	}
	s, err = parseSetting([]byte(readFixture(t, "getwebproxy-never-set.txt")))
	if err != nil || s != (Setting{}) {
		t.Fatalf("never-set proxy parsed as %+v, %v", s, err)
	}
	if _, err := parseSetting([]byte("** Error: The parameters were not valid.")); err == nil {
		t.Fatal("error output parsed as a setting")
	}
	if kv := parseScutilProxy(readFixture(t, "scutil-proxy-none.txt")); kv["HTTPEnable"] != "0" {
		t.Fatalf("scutil parsed as %v", kv)
	}
}

func TestR4_1_SettingsSavedBeforeAnyChange(t *testing.T) {
	m, mac, h := setup(t)
	var saved State
	mac.beforeSet = func() {
		b, err := h.ReadFile(StateFile)
		if err != nil {
			t.Errorf("first set command ran before state.json existed: %v", err)
			return
		}
		if err := json.Unmarshal(b, &saved); err != nil {
			t.Error(err)
		}
	}
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	want := []Service{
		{Name: "Thunderbolt Bridge", Web: Setting{Enabled: true, Server: "proxy.corp.example", Port: 3128}},
		{Name: "Wi-Fi", Web: Setting{Server: "127.0.0.1", Port: 8888}, Secure: Setting{Server: "127.0.0.1", Port: 8888}},
	}
	if !reflect.DeepEqual(saved.Services, want) || saved.Port != 9090 || saved.PID != os.Getpid() {
		t.Fatalf("saved = %+v", saved)
	}
	fi, err := os.Stat(filepath.Join(h.Path(), StateFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.json: %v %v", fi, err)
	}
}

func TestEnableSetsEnabledServicesOnly(t *testing.T) {
	m, mac, _ := setup(t)
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	web, secure := mac.settings()
	on := Setting{Enabled: true, Server: "127.0.0.1", Port: 9090}
	for _, svc := range []string{"Wi-Fi", "Thunderbolt Bridge"} {
		if web[svc] != on || secure[svc] != on {
			t.Errorf("%s: web %+v secure %+v, want %+v", svc, web[svc], secure[svc], on)
		}
	}
	if web["USB 10/100/1000 LAN"] != (Setting{}) {
		t.Errorf("disabled service changed: %+v", web["USB 10/100/1000 LAN"])
	}
	if err := m.Enable(context.Background(), 9090); !errors.Is(err, ErrAlreadySet) {
		t.Fatalf("second Enable: err = %v, want ErrAlreadySet", err)
	}
}

func TestR4_2_RestorePutsBackExactSettings(t *testing.T) {
	m, mac, h := setup(t)
	webBefore, secureBefore := mac.settings()
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	web, secure := mac.settings()
	if !reflect.DeepEqual(web, webBefore) {
		t.Errorf("web after restore = %+v\nwant %+v", web, webBefore)
	}
	// Thunderbolt's secure proxy never had a server: networksetup cannot clear the field,
	// so it is left as 127.0.0.1:9090 but disabled.
	wantSecure := secureBefore
	wantSecure["Thunderbolt Bridge"] = Setting{Enabled: false, Server: "127.0.0.1", Port: 9090}
	if !reflect.DeepEqual(secure, wantSecure) {
		t.Errorf("secure after restore = %+v\nwant %+v", secure, wantSecure)
	}
	if stateExists(h) {
		t.Fatal("state.json left after a successful restore")
	}
}

func TestR4_3_LeftoverStateIsRestoredOnNextStart(t *testing.T) {
	m, mac, h := setup(t)
	webBefore, _ := mac.settings()
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	// Crash: no Restore. A new process starts with the same home dir and Mac.
	next := New(m.run, h, nil)
	recovered, err := next.Recover(context.Background())
	if err != nil || !recovered {
		t.Fatalf("Recover = %v, %v; want true", recovered, err)
	}
	if web, _ := mac.settings(); !reflect.DeepEqual(web, webBefore) {
		t.Fatalf("web after recovery = %+v", web)
	}
	if recovered, err := next.Recover(context.Background()); err != nil || recovered {
		t.Fatalf("second Recover = %v, %v; want nothing to do", recovered, err)
	}
}

func TestR4_4_WarnsBeforeOverridingPACAndPushedProxies(t *testing.T) {
	m, mac, _ := setup(t)
	if w, err := m.Check(context.Background()); err != nil || len(w) != 0 {
		t.Fatalf("plain setup: warnings %q, %v", w, err)
	}

	mac.pac["Wi-Fi"] = "http://wpad.corp.example/proxy.pac"
	mac.autodisc["Thunderbolt Bridge"] = true
	w, err := m.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(w, "\n")
	if len(w) != 2 || !strings.Contains(joined, "PAC file (http://wpad.corp.example/proxy.pac)") ||
		!strings.Contains(joined, "Thunderbolt Bridge has proxy auto-discovery on") {
		t.Fatalf("warnings = %q", w)
	}

	m2, mac2, _ := setup(t)
	mac2.scutil = "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : 10.0.0.1\n  HTTPSPort : 8080\n}\n"
	w, err = m2.Check(context.Background())
	if err != nil || len(w) != 1 || !strings.Contains(w[0], "VPN or configuration profile") {
		t.Fatalf("pushed proxy: warnings %q, %v", w, err)
	}
}

func TestR4_6_RestoreIsSafeWithNothingToRestore(t *testing.T) {
	h, err := home.Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	fake := execx.NewFake() // no replies: any tool call fails the test
	if err := New(fake, h, nil).Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Fatalf("ran %q with no state to restore", calls)
	}
}

func TestFailedEnableRollsBack(t *testing.T) {
	m, mac, h := setup(t)
	webBefore, _ := mac.settings()
	mac.failOn = "networksetup -setsecurewebproxystate Wi-Fi on" // only Enable turns it on
	err := m.Enable(context.Background(), 9090)
	if err == nil || !strings.Contains(err.Error(), "fake failure") {
		t.Fatalf("err = %v", err)
	}
	mac.failOn = ""
	if web, _ := mac.settings(); !reflect.DeepEqual(web, webBefore) {
		t.Fatalf("web after rollback = %+v\nwant %+v", web, webBefore)
	}
	if stateExists(h) {
		t.Fatal("state.json left after rollback")
	}
}

func TestFailedRestoreKeepsStateForRetry(t *testing.T) {
	m, mac, h := setup(t)
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	mac.failOn = "networksetup -setwebproxystate Wi-Fi"
	if err := m.Restore(context.Background()); err == nil || !strings.Contains(err.Error(), "wraith stop") {
		t.Fatalf("err = %v", err)
	}
	if !stateExists(h) {
		t.Fatal("state.json removed although restore failed")
	}
	mac.failOn = ""
	if err := m.Restore(context.Background()); err != nil || stateExists(h) {
		t.Fatalf("retry: %v, state exists %v", err, stateExists(h))
	}
}

func TestAuthenticatedProxyIsLeftAlone(t *testing.T) {
	m, mac, h := setup(t)
	mac.web["Wi-Fi"] = Setting{Enabled: true, Server: "proxy.corp.example", Port: 8080, Auth: true}
	if err := m.Enable(context.Background(), 9090); !errors.Is(err, ErrAuthenticatedProxy) {
		t.Fatalf("err = %v, want ErrAuthenticatedProxy", err)
	}
	if stateExists(h) {
		t.Fatal("state.json written although nothing changed")
	}
}

func TestS4_3_TamperedServiceNamesAreNotPassedToNetworksetup(t *testing.T) {
	m, mac, h := setup(t)
	st := State{Version: stateVersion, Port: 9090, Services: []Service{
		{Name: "-setwebproxy", Web: Setting{Server: "evil", Port: 1}},
		{Name: "Not On This Mac", Web: Setting{Server: "x", Port: 1}},
		{Name: "Wi-Fi", Web: Setting{Server: "127.0.0.1", Port: 8888}},
	}}
	if err := m.writeState(st); err != nil {
		t.Fatal(err)
	}
	fake := m.run.(*execx.Fake)
	if err := m.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range fake.Calls() {
		if strings.Contains(c, "evil") || strings.Contains(c, "Not On This Mac") {
			t.Fatalf("ran %q", c)
		}
	}
	if web, _ := mac.settings(); web["Wi-Fi"].Port != 8888 {
		t.Fatalf("valid entry not restored: %+v", web["Wi-Fi"])
	}
	if stateExists(h) {
		t.Fatal("state.json kept")
	}
}

func TestCorruptStateIsReportedNotGuessed(t *testing.T) {
	m, _, h := setup(t)
	if err := h.WriteFile(StateFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(context.Background()); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("err = %v", err)
	}
}
