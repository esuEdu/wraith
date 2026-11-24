package cli

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/proxy"
	"github.com/esuEdu/wraith/internal/source"
)

func TestS2_6_DevicesGetInOnlyWithTheSetupKey(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.0.0/24")
	var allowed, notices []string
	d := newDevices("192.168.0.12:9090", subnet, []net.IP{net.ParseIP("192.168.0.50")}, nil,
		func([]rememberedDevice) error { return nil },
		func(ip, _ string) { allowed = append(allowed, ip) },
		func(f string, a ...any) { notices = append(notices, fmt.Sprintf(f, a...)) })

	if d.Admit(net.ParseIP("192.168.0.50")) != proxy.Allowed {
		t.Fatal("a device given with --allow-device was not allowed")
	}
	phone := net.ParseIP("192.168.0.23")
	if d.Admit(phone) != proxy.SetupOnly {
		t.Fatal("a new device on the network may do more than open the setup page")
	}
	if d.Unlock(phone, "wrong", "") || d.Unlock(phone, "", "") || d.Admit(phone) != proxy.SetupOnly {
		t.Fatal("a wrong key let the device in")
	}
	if !d.Unlock(phone, d.key, "") || !d.Unlock(phone, d.key, "") || d.Admit(phone) != proxy.Allowed {
		t.Fatal("the setup key did not let the device in")
	}
	if !slices.Equal(allowed, []string{"192.168.0.23"}) {
		t.Fatalf("allowed notices %v, want the phone once", allowed)
	}
	off := net.ParseIP("10.8.0.4")
	if d.Admit(off) != proxy.Refused || d.Admit(off) != proxy.Refused || d.Unlock(off, d.key, "") {
		t.Fatal("a peer off the Mac's network got in")
	}
	if len(notices) != 1 {
		t.Fatalf("notices %q: an outside peer is reported once", notices)
	}
	if got := d.Allowed(); !slices.Equal(got, []string{"192.168.0.23", "192.168.0.50"}) {
		t.Fatalf("allowed = %v", got)
	}
	if u := d.SetupURL(); u != "http://192.168.0.12:9090/?key="+d.key || len(d.key) != 10 || newKey() == d.key {
		t.Fatalf("setup url %q", u)
	}
}

func TestFirewallWarning(t *testing.T) {
	for _, c := range []struct {
		state, blockAll, app, want string
	}{
		{"Firewall is disabled. (State = 0)", "", "", ""},
		{"Firewall is enabled. (State = 1)", "Firewall has block all state set to disabled.", "Incoming connection to /x/wraith is permitted.", ""},
		{"Firewall is enabled. (State = 1)", "Firewall has block all state set to enabled.", "", "blocks all incoming"},
		{"Firewall is enabled. (State = 1)", "Firewall has block all state set to disabled.", "Incoming connection to /x/wraith is blocked.", "blocks wraith"},
	} {
		f := execx.NewFake()
		f.Handler = func(tool string, args []string) ([]byte, error) {
			switch args[0] {
			case "--getglobalstate":
				return []byte(c.state), nil
			case "--getblockall":
				return []byte(c.blockAll), nil
			}
			return []byte(c.app), nil
		}
		got := firewallWarning(context.Background(), f, "/x/wraith")
		if c.want == "" && got != "" || !strings.Contains(got, c.want) {
			t.Errorf("%q / %q / %q: warning %q, want %q", c.state, c.blockAll, c.app, got, c.want)
		}
	}
}

func TestS2_6_AllowDeviceTakesPrivateAddressesOnly(t *testing.T) {
	if _, err := parseDeviceIPs([]string{"192.168.0.23", "10.0.0.7"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"8.8.8.8", "127.0.0.1", "0.0.0.0", "iphone"} {
		if _, err := parseDeviceIPs([]string{bad}); err == nil {
			t.Errorf("--allow-device %s accepted", bad)
		}
	}
}

func TestDeviceConnectionsAreClassifiedByAddress(t *testing.T) {
	var lookups atomic.Int32
	a := &app{d: Deps{Lookup: func(context.Context, int, int) (source.Origin, error) {
		lookups.Add(1)
		return curl, nil
	}}}
	var cur atomic.Pointer[source.Source]
	set := func(s string) {
		src, err := source.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		cur.Store(&src)
	}
	set("device")
	classify := a.classifier(&cur, nil, false)
	phone := &net.TCPAddr{IP: net.ParseIP("192.168.0.23"), Port: 50000}
	local := &net.TCPAddr{IP: net.ParseIP("192.168.0.12"), Port: 9090}
	v := classify(context.Background(), phone, local)
	if !v.InSource || !v.Decrypt || v.Label != "device 192.168.0.23" || lookups.Load() != 0 {
		t.Fatalf("device verdict %+v, %d process lookups", v, lookups.Load())
	}
	for _, mac := range []net.IP{net.IPv4(127, 0, 0, 1), local.IP} { // over loopback, or to its own Wi-Fi address
		if v := classify(context.Background(), &net.TCPAddr{IP: mac, Port: 50001}, local); v.InSource {
			t.Fatalf("a Mac process from %s is inside source device", mac)
		}
	}
	set("device:192.168.0.99")
	if v := classify(context.Background(), phone, local); v.InSource {
		t.Fatal("another device is inside device:192.168.0.99")
	}
	set("simulator")
	if v := classify(context.Background(), phone, local); v.InSource {
		t.Fatal("a device is inside source simulator")
	}
}

func TestS2_6_BadDeviceFlagsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"start", "--allow-device", "8.8.8.8"},
		{"start", "--device", "--source", "device:iphone"},
	} {
		e := newEnv(t)
		if code := e.run(args...); code != ExitUsage {
			t.Errorf("%q: exit %d, want %d; stderr %q", args, code, ExitUsage, e.stderr)
		}
	}
}

func TestS2_6_DevicesAreRememberedOnTheirNetwork(t *testing.T) {
	h := newEnv(t).home()
	_, subnet, _ := net.ParseCIDR("192.168.15.0/24")
	start := func(subnet *net.IPNet) *devices {
		known, err := loadDevices(h)
		if err != nil {
			t.Fatal(err)
		}
		return newDevices("192.168.15.3:9090", subnet, nil, known,
			func(l []rememberedDevice) error { return saveDevices(h, l) }, func(string, string) {}, func(string, ...any) {})
	}

	d := start(subnet)
	phone := net.ParseIP("192.168.15.2")
	if !d.Unlock(phone, d.key, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X)") {
		t.Fatal("unlock")
	}
	list, _ := loadDevices(h)
	if len(list) != 1 || list[0].IP != "192.168.15.2" || list[0].Kind != "iPhone" || list[0].Network != "192.168.15.0/24" {
		t.Fatalf("remembered %+v", list)
	}

	// The next run: the phone gets in without a key; another address still needs one.
	d = start(subnet)
	if d.Admit(phone) != proxy.Allowed {
		t.Fatal("a remembered phone needs the code again")
	}
	if d.Admit(net.ParseIP("192.168.15.7")) != proxy.SetupOnly {
		t.Fatal("an unknown device got in")
	}
	// At a new address it needs the QR code again.
	moved := net.ParseIP("192.168.15.4")
	if d.Admit(moved) != proxy.SetupOnly || !d.Unlock(moved, d.key, "") || d.Admit(moved) != proxy.Allowed {
		t.Fatal("the QR key does not let the phone in at its new address")
	}
	// On another network the same address is not trusted, and that network's list is kept.
	_, elsewhere, _ := net.ParseCIDR("192.168.15.0/25")
	d = start(elsewhere)
	if d.Admit(phone) != proxy.SetupOnly {
		t.Fatal("a device remembered on another network got in")
	}
	d.Unlock(net.ParseIP("192.168.15.9"), d.key, "")
	if list, _ := loadDevices(h); len(list) != 3 {
		t.Fatalf("remembered %+v: the other network's devices were lost", list)
	}
	// Not seen for 30 days: forgotten.
	list, _ = loadDevices(h)
	for i := range list {
		list[i].LastSeen = time.Now().Add(-31 * 24 * time.Hour)
	}
	_ = saveDevices(h, list)
	if d = start(subnet); d.Admit(phone) != proxy.SetupOnly {
		t.Fatal("a device not seen for 31 days got in")
	}
}

func TestDevicesListAndForget(t *testing.T) {
	e := newEnv(t)
	h := e.home()
	if err := saveDevices(h, []rememberedDevice{{IP: "192.168.15.2", Kind: "iPhone", Network: "192.168.15.0/24"}, {IP: "192.168.15.7", Kind: "iPad"}}); err != nil {
		t.Fatal(err)
	}
	if code := e.run("devices", "list"); code != 0 || !strings.Contains(e.stdout.String(), "192.168.15.2    iPhone") {
		t.Fatalf("list: %d %q", code, e.stdout)
	}
	if code := e.run("devices", "forget", "192.168.15.2"); code != 0 {
		t.Fatalf("forget: %d %q", code, e.stderr)
	}
	if list, _ := loadDevices(h); len(list) != 1 || list[0].Kind != "iPad" {
		t.Fatalf("after forget: %+v", list)
	}
	if code := e.run("devices", "forget", "10.0.0.1"); code != ExitUsage {
		t.Fatalf("forgetting an unknown device: %d", code)
	}
	if code := e.run("devices", "forget", "all"); code != 0 {
		t.Fatal("forget all")
	}
	if list, _ := loadDevices(h); len(list) != 0 {
		t.Fatalf("after forget all: %+v", list)
	}
}

// home opens the test's ~/.wraith.
func (e *env) home() *home.Home {
	e.t.Helper()
	h, err := home.Open(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = h.Close() })
	return h
}
