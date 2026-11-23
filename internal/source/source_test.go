package source

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
)

func TestR1_2_IdentifiesTheProcessThatConnected(t *testing.T) {
	r := NewResolver(execx.Default())
	got := make(chan Origin, 1)
	var lookupErr error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, port, _ := net.SplitHostPort(req.RemoteAddr)
		cp, _ := strconv.Atoi(port)
		sp := req.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr).Port
		o, err := r.Lookup(req.Context(), cp, sp)
		lookupErr = err
		got <- o
	}))
	defer ts.Close()

	cmd := exec.Command("/usr/bin/curl", "-s", "-o", "/dev/null", ts.URL)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	o := <-got
	if lookupErr != nil {
		t.Fatal(lookupErr)
	}
	if o.PID != cmd.Process.Pid || o.Chain[0].Path != "/usr/bin/curl" {
		t.Fatalf("origin pid %d path %q, want curl pid %d", o.PID, o.Chain[0].Path, cmd.Process.Pid)
	}
	if len(o.Chain) < 2 || o.Chain[1].PID != os.Getpid() {
		t.Fatalf("curl's parent should be this test (%d); chain %+v", os.Getpid(), o.Chain)
	}
	if o.Simulator() || o.Label() != "curl" {
		t.Fatalf("simulator %v label %q", o.Simulator(), o.Label())
	}
	if !(Source{Kind: "pid", PID: os.Getpid()}).Matches(o, nil) {
		t.Fatal("pid:<parent> should match its child's connection")
	}
}

func TestR1_4_UnidentifiedConnectionsAreOutsideEverySource(t *testing.T) {
	r := NewResolver(execx.Default())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if _, err := r.Lookup(context.Background(), port, 9); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unused port: err = %v, want ErrUnknown", err)
	}
	for _, s := range []string{"all", "simulator", "app:curl", "pid:1"} {
		src, _ := Parse(s)
		if src.Matches(Origin{}, nil) {
			t.Errorf("%s matched an unidentified connection", s)
		}
	}
}

// record builds one pcblist_n record of the given kind with u32/u16 fields set.
func record(kind uint32, set func(b []byte)) []byte {
	b := make([]byte, recordSize)
	binary.LittleEndian.PutUint32(b, recordSize)
	binary.LittleEndian.PutUint32(b[4:], kind)
	set(b)
	return b
}

func pcbList(conns ...[3]int) []byte { // lport, fport, last pid; e pid = 0
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf, 24)
	for _, c := range conns {
		buf = append(buf, record(kindInpcb, func(b []byte) {
			binary.BigEndian.PutUint16(b[inpcbLport:], uint16(c[0]))
			binary.BigEndian.PutUint16(b[inpcbFport:], uint16(c[1]))
		})...)
		buf = append(buf, record(kindSocket, func(b []byte) {
			binary.LittleEndian.PutUint32(b[socketLastPID:], uint32(c[2]))
		})...)
		buf = append(buf, record(0x020, func([]byte) {})...) // a tcpcb record to skip
	}
	return buf
}

func TestParsePCBList(t *testing.T) {
	buf := pcbList([3]int{9090, 52000, 111}, [3]int{52000, 9090, 222}, [3]int{52001, 9090, 333})
	if pid, err := parsePCBList(buf, 52000, 9090); err != nil || pid != 222 {
		t.Fatalf("client side: %d %v", pid, err)
	}
	if _, err := parsePCBList(buf, 52002, 9090); !errors.Is(err, ErrUnknown) {
		t.Fatalf("absent: %v", err)
	}
	delegated := pcbList([3]int{52000, 9090, 222})
	binary.LittleEndian.PutUint32(delegated[24+recordSize+socketEPID:], 777) // so_e_pid
	if pid, _ := parsePCBList(delegated, 52000, 9090); pid != 777 {
		t.Fatalf("delegated socket: pid %d, want the effective 777", pid)
	}
	bad := pcbList([3]int{52000, 9090, 222})
	binary.LittleEndian.PutUint32(bad[24:], recordSize+8) // a bigger xinpcb_n
	if _, err := parsePCBList(bad, 52000, 9090); err == nil {
		t.Fatal("changed layout not detected")
	}
	if _, err := parsePCBList(nil, 1, 2); !errors.Is(err, errLayout) {
		t.Fatalf("empty buffer: %v", err)
	}
}

func TestLsofFallback(t *testing.T) {
	f := execx.NewFake().On("lsof -nP -iTCP:52000 -sTCP:ESTABLISHED -Fpn",
		"p100\nn127.0.0.1:9090->127.0.0.1:52000\np222\nn127.0.0.1:52000->127.0.0.1:9090\n", nil)
	pid, err := ownerFromLsof(context.Background(), f, 52000, 9090, 100)
	if err != nil || pid != 222 {
		t.Fatalf("pid %d err %v", pid, err)
	}
	if _, err := ownerFromLsof(context.Background(), execx.NewFake(), 1, 2, 3); !errors.Is(err, ErrUnknown) {
		t.Fatalf("lsof failure: %v", err)
	}
}

func TestSimulatorUDIDAndOutermostApp(t *testing.T) {
	args := []string{"launchd_sim", "/Users/x/Library/Developer/CoreSimulator/Devices/196410f2-8977-4511-9257-c038a2ac78aa/data/var/run/launchd_bootstrap.plist"}
	if got := simUDID(args); got != "196410F2-8977-4511-9257-C038A2AC78AA" {
		t.Fatalf("udid %q", got)
	}
	if got := simUDID([]string{"launchd_sim"}); got != "unknown" {
		t.Fatalf("no udid: %q", got)
	}
	for path, want := range map[string]string{
		"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper": "/Applications/Google Chrome.app",
		"/Users/x/Library/Developer/CoreSimulator/Devices/U/data/Containers/Bundle/Application/A/Shop.app/Shop":                                                      "/Users/x/Library/Developer/CoreSimulator/Devices/U/data/Containers/Bundle/Application/A/Shop.app",
		"/usr/bin/curl":       "",
		"/Applications/X.app": "/Applications/X.app",
	} {
		if got := outermostApp(path); got != want {
			t.Errorf("outermostApp(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestBundleIDFromInfoPlist(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ app, plist string }{
		{"Mac.app", filepath.Join("Mac.app", "Contents", "Info.plist")}, // macOS layout
		{"Phone.app", filepath.Join("Phone.app", "Info.plist")},         // iOS layout
	} {
		p := filepath.Join(dir, tc.plist)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		xml := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.` + tc.app[:len(tc.app)-4] + `</string></dict></plist>`
		if err := os.WriteFile(p, []byte(xml), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := NewResolver(execx.Default())
	if got := r.bundleID(context.Background(), filepath.Join(dir, "Mac.app")); got != "com.example.Mac" {
		t.Errorf("macOS bundle id %q", got)
	}
	if got := r.bundleID(context.Background(), filepath.Join(dir, "Phone.app")); got != "com.example.Phone" {
		t.Errorf("iOS bundle id %q", got)
	}
	if got := r.bundleID(context.Background(), filepath.Join(dir, "Missing.app")); got != "" {
		t.Errorf("missing bundle id %q", got)
	}
}

func TestR1_1_SourcesParseAndMatch(t *testing.T) {
	for _, bad := range []string{"", "sim", "app:", "pid:", "pid:x", "pid:0", "simulator:"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	simApp := Origin{PID: 10, Chain: []Process{{PID: 10}, {PID: 9}}, SimUDID: "196410F2-8977-4511-9257-C038A2AC78AA",
		AppPath: "/x/Shop.app", AppName: "Shop", BundleID: "com.example.shop"}
	chrome := Origin{PID: 20, Chain: []Process{{PID: 20}, {PID: 19}}, AppPath: "/Applications/Google Chrome.app",
		AppName: "Google Chrome", BundleID: "com.google.Chrome"}
	tool := Origin{PID: 30, Chain: []Process{{PID: 30, Path: "/usr/bin/curl"}, {PID: 29}}}
	names := func(udid string) string {
		if udid == simApp.SimUDID {
			return "iPhone 17"
		}
		return ""
	}
	cases := []struct {
		source              string
		sim, chromeM, toolM bool
	}{
		{"all", true, true, true},
		{"simulator", true, false, false},
		{"simulator:196410f2-8977-4511-9257-c038a2ac78aa", true, false, false},
		{"simulator:iphone 17", true, false, false},
		{"simulator:iPhone 18", false, false, false},
		{"app:com.google.chrome", false, true, false},
		{"app:Google Chrome", false, true, false},
		{"app:Shop", true, false, false}, // an app inside a simulator
		{"app:curl", false, false, true}, // a command-line tool, by executable name
		{"app:Shop.app", false, false, false},
		{"pid:19", false, true, false}, // a parent's pid covers its children
		{"pid:30", false, false, true},
	}
	for _, c := range cases {
		s, err := Parse(c.source)
		if err != nil {
			t.Fatal(err)
		}
		if s.String() != c.source {
			t.Errorf("String() = %q, want %q", s.String(), c.source)
		}
		for _, o := range []struct {
			name string
			o    Origin
			want bool
		}{{"simulator app", simApp, c.sim}, {"chrome", chrome, c.chromeM}, {"curl", tool, c.toolM}} {
			if got := s.Matches(o.o, names); got != o.want {
				t.Errorf("%s matches %s = %v, want %v", c.source, o.name, got, o.want)
			}
		}
	}
}

// BenchmarkOwnerLookup measures the kernel socket-list lookup (budget: p95 under 5 ms).
func BenchmarkOwnerLookup(b *testing.B) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	lport, fport := c.LocalAddr().(*net.TCPAddr).Port, ln.Addr().(*net.TCPAddr).Port
	for b.Loop() {
		if _, err := ownerFromPCBList(lport, fport); err != nil {
			b.Fatal(err)
		}
	}
}
