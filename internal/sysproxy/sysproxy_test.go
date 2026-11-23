package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/sysproxy/sysproxytest"
)

type fakeMac = sysproxytest.Mac

func readFixture(_ *testing.T, name string) string { return sysproxytest.Fixture(name) }

func toSettings(m map[string]sysproxytest.Proxy) map[string]Setting {
	out := map[string]Setting{}
	for k, v := range m {
		out[k] = Setting(v)
	}
	return out
}

// settings returns the fake's current settings as sysproxy Settings.
func settings(mac *fakeMac) (web, secure map[string]Setting) {
	w, s := mac.Settings()
	return toSettings(w), toSettings(s)
}

func setup(t *testing.T) (*Manager, *fakeMac, *home.Home) {
	t.Helper()
	h, err := home.Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	mac := sysproxytest.NewMac()
	fake := execx.NewFake()
	fake.Handler = mac.Run
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
	mac.BeforeSet = func() {
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
	web, secure := settings(mac)
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
	webBefore, secureBefore := settings(mac)
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	web, secure := settings(mac)
	if !reflect.DeepEqual(web, webBefore) {
		t.Errorf("web after restore = %+v\nwant %+v", web, webBefore)
	}
	// Includes Thunderbolt's secure proxy, which never had a server: it is cleared back to
	// an empty server and port 0, not left as 127.0.0.1:9090.
	if !reflect.DeepEqual(secure, secureBefore) {
		t.Errorf("secure after restore = %+v\nwant %+v", secure, secureBefore)
	}
	if stateExists(h) {
		t.Fatal("state.json left after a successful restore")
	}
}

func TestR4_3_LeftoverStateIsRestoredOnNextStart(t *testing.T) {
	m, mac, h := setup(t)
	webBefore, _ := settings(mac)
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	// Crash: no Restore. A new process starts with the same home dir and Mac.
	next := New(m.run, h, nil)
	recovered, err := next.Recover(context.Background())
	if err != nil || !recovered {
		t.Fatalf("Recover = %v, %v; want true", recovered, err)
	}
	if web, _ := settings(mac); !reflect.DeepEqual(web, webBefore) {
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

	mac.PAC["Wi-Fi"] = "http://wpad.corp.example/proxy.pac"
	mac.AutoDiscovery["Thunderbolt Bridge"] = true
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
	mac2.Scutil = "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : 10.0.0.1\n  HTTPSPort : 8080\n}\n"
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
	webBefore, _ := settings(mac)
	mac.SetFailOn("networksetup -setsecurewebproxystate Wi-Fi on") // only Enable turns it on
	err := m.Enable(context.Background(), 9090)
	if err == nil || !strings.Contains(err.Error(), "fake failure") {
		t.Fatalf("err = %v", err)
	}
	mac.SetFailOn("")
	if web, _ := settings(mac); !reflect.DeepEqual(web, webBefore) {
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
	mac.SetFailOn("networksetup -setwebproxystate Wi-Fi")
	if err := m.Restore(context.Background()); err == nil || !strings.Contains(err.Error(), "wraith stop") {
		t.Fatalf("err = %v", err)
	}
	if !stateExists(h) {
		t.Fatal("state.json removed although restore failed")
	}
	mac.SetFailOn("")
	if err := m.Restore(context.Background()); err != nil || stateExists(h) {
		t.Fatalf("retry: %v, state exists %v", err, stateExists(h))
	}
}

func TestAuthenticatedProxyIsLeftAlone(t *testing.T) {
	m, mac, h := setup(t)
	mac.Web["Wi-Fi"] = sysproxytest.Proxy{Enabled: true, Server: "proxy.corp.example", Port: 8080, Auth: true}
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
	if web, _ := settings(mac); web["Wi-Fi"].Port != 8888 {
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

func TestEffectiveHTTPSAndStateLeft(t *testing.T) {
	m, mac, _ := setup(t)
	mac.Scutil = "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSPort : 9090\n  HTTPSProxy : 127.0.0.1\n}\n"
	eff, err := m.EffectiveHTTPS(context.Background())
	if err != nil || !eff.Enabled || eff.Host != "127.0.0.1" || eff.Port != 9090 {
		t.Fatalf("EffectiveHTTPS = %+v, %v", eff, err)
	}
	if m.StateLeft() {
		t.Fatal("state reported before Enable")
	}
	if err := m.Enable(context.Background(), 9090); err != nil {
		t.Fatal(err)
	}
	if !m.StateLeft() {
		t.Fatal("state not reported after Enable")
	}
}
