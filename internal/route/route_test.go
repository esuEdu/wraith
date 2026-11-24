package route

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
)

func TestR3_1_MostSpecificRuleWins(t *testing.T) {
	r := NewRules([]string{"*.example.com", "*.api.example.com", "login.api.example.com", "partner.io"})
	for host, want := range map[string]string{
		"www.example.com":        "*.example.com",
		"v2.api.example.com":     "*.api.example.com",
		"login.api.example.com":  "login.api.example.com",
		"LOGIN.API.EXAMPLE.COM.": "login.api.example.com",
		"partner.io":             "partner.io",
		"example.com":            "", // *.x is subdomains only
		"x.partner.io":           "",
		"notexample.com":         "",
	} {
		got, ok := r.Match(host)
		if got != want || ok != (want != "") {
			t.Errorf("Match(%q) = %q, %v; want %q", host, got, ok, want)
		}
	}
	if !NewRules(nil).Empty() || r.Empty() {
		t.Fatal("Empty is wrong")
	}
}

// recordingDialer stands in for the normal path and records every use.
type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// loopbackRouter bypasses *.test through lo0, with DNS answered by answers.
func loopbackRouter(t *testing.T, answers []net.IP, dnsErr error) (*Router, *recordingDialer) {
	t.Helper()
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	direct := &recordingDialer{}
	r := &Router{
		iface:  Iface{Name: "lo0", Index: lo.Index},
		direct: direct,
		lookup: func(context.Context, string) ([]net.IP, error) { return answers, dnsErr },
	}
	r.SetRules([]string{"*.test"})
	return r, direct
}

func listen(t *testing.T, network, addr string) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("%s %s unavailable: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return ln, port
}

// boundIndex reads IP_BOUND_IF / IPV6_BOUND_IF back from a connection's socket.
func boundIndex(t *testing.T, c net.Conn) int {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var idx int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		if c.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
			idx, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF)
		} else {
			idx, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF)
		}
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return idx
}

func TestR3_2_BypassIsBoundToTheInterfaceIPv6First(t *testing.T) {
	_, port := listen(t, "tcp6", "[::1]:0")
	// The same port on IPv4 may be taken; IPv4 must not even be tried when IPv6 works.
	r, direct := loopbackRouter(t, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil)
	c, err := r.DialContext(context.Background(), "tcp", "api.example.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ip := c.RemoteAddr().(*net.TCPAddr).IP; !ip.Equal(net.IPv6loopback) {
		t.Fatalf("connected to %s, want IPv6 first", ip)
	}
	if got := boundIndex(t, c); got != r.iface.Index {
		t.Fatalf("socket bound to interface %d, want lo0 (%d)", got, r.iface.Index)
	}
	if len(direct.addrs) != 0 {
		t.Fatalf("a bypassed host went the normal way: %v", direct.addrs)
	}
	if route, rule := r.Route("api.example.test"); route != RouteDirect || rule != "*.test" {
		t.Fatalf("Route = %s %s", route, rule)
	}
}

func TestBypassFallsBackToIPv4OnTheInterface(t *testing.T) {
	_, port := listen(t, "tcp4", "127.0.0.1:0")
	r, _ := loopbackRouter(t, []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}, nil)
	c, err := r.DialContext(context.Background(), "tcp", "api.example.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ip := c.RemoteAddr().(*net.TCPAddr).IP; ip.To4() == nil || boundIndex(t, c) != r.iface.Index {
		t.Fatalf("connected to %s, want bound IPv4 after IPv6 failed", ip)
	}
}

func TestR3_4_FailedBypassNeverTakesTheNormalPath(t *testing.T) {
	_, port := listen(t, "tcp4", "127.0.0.1:0")
	_ = port
	closed := "1" // nothing listens on port 1
	for name, tc := range map[string]struct {
		answers []net.IP
		dnsErr  error
		iface   error
	}{
		"nothing answers": {answers: []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}},
		"DNS fails":       {dnsErr: errors.New("no answer")},
		"no interface":    {iface: ErrNoInterface},
	} {
		r, direct := loopbackRouter(t, tc.answers, tc.dnsErr)
		r.ifaceErr = tc.iface
		_, err := r.DialContext(context.Background(), "tcp", "api.example.test:"+closed)
		if !errors.Is(err, ErrBypassFailed) || !strings.Contains(err.Error(), "api.example.test") {
			t.Errorf("%s: err = %v, want ErrBypassFailed naming the host", name, err)
		}
		if len(direct.addrs) != 0 {
			t.Errorf("%s: fell back to the normal path: %v", name, direct.addrs)
		}
	}
}

func TestS2_5_BypassDNSOnlyUsesTheInterfaceResolvers(t *testing.T) {
	// A real Router's lookup: every server is unreachable through lo0, so it must fail,
	// and must not fall back to the system resolver.
	lo, _ := net.InterfaceByName("lo0")
	r := &Router{iface: Iface{Name: "lo0", Index: lo.Index}, servers: []string{"127.0.0.1"}}
	_, err := r.boundLookup(context.Background(), "bypass-test.wraith.invalid")
	if err == nil {
		t.Fatal("bypass lookup answered without a DNS server: it used the system resolver")
	}
}

func TestOtherHostsTakeTheNormalPath(t *testing.T) {
	_, port := listen(t, "tcp4", "127.0.0.1:0")
	r, direct := loopbackRouter(t, nil, nil)
	c, err := r.DialContext(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(direct.addrs) != 1 {
		t.Fatalf("normal path used %d times, want 1", len(direct.addrs))
	}
	if route, _ := r.Route("example.com"); route != RouteVPN {
		t.Fatalf("Route = %s", route)
	}
}

func TestDetectIfaceUsesScopedDefaultRoutes(t *testing.T) {
	ifs, _ := net.Interfaces()
	var name string
	for _, i := range ifs {
		if physical.MatchString(i.Name) && i.Flags&net.FlagUp != 0 {
			if a, _ := i.Addrs(); len(a) > 0 {
				name = i.Name
				break
			}
		}
	}
	if name == "" {
		t.Skip("no en* interface up on this machine")
	}
	f := execx.NewFake()
	f.Handler = func(tool string, args []string) ([]byte, error) {
		if args[len(args)-2] == name {
			return []byte("   route to: default\n  interface: " + name + "\n"), nil
		}
		return nil, errors.New("route: writing to routing socket: not in table")
	}
	got, err := DetectIface(context.Background(), f, "auto")
	if err != nil || got.Name != name || got.Index == 0 {
		t.Fatalf("DetectIface = %+v, %v; want %s", got, err, name)
	}
	none := execx.NewFake() // no scoped route anywhere
	if _, err := DetectIface(context.Background(), none, "auto"); !errors.Is(err, ErrNoInterface) {
		t.Fatalf("no routes: err = %v", err)
	}
	if _, err := DetectIface(context.Background(), f, "en0; ls"); err == nil {
		t.Fatal("bad interface name accepted")
	}
}

func TestProbeReportsBothPathsPerFamily(t *testing.T) {
	_, port := listen(t, "tcp6", "[::1]:0")
	r, _ := loopbackRouter(t, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil)
	probes, err := r.Probe(context.Background(), "probe.test", port)
	if err != nil || len(probes) != 2 {
		t.Fatalf("probes %+v err %v", probes, err)
	}
	v6, v4 := probes[0], probes[1]
	if v6.Family != "IPv6" || v6.Default.Err != nil || v6.Bound.Err != nil || v6.Bound.Via != "lo0" || v6.Default.Via != "lo0" {
		t.Fatalf("IPv6 probe %+v", v6)
	}
	if v4.Family != "IPv4" || v4.Default.Err == nil || v4.Bound.Err == nil { // nothing listens on IPv4
		t.Fatalf("IPv4 probe %+v", v4)
	}

	r.ifaceErr = ErrNoInterface
	probes, _ = r.Probe(context.Background(), "probe.test", port)
	if !errors.Is(probes[0].Bound.Err, ErrNoInterface) || probes[0].Default.Err != nil {
		t.Fatalf("without an interface: %+v", probes[0])
	}
}

func TestRulesChangeWhileRunning(t *testing.T) {
	r, _ := loopbackRouter(t, nil, nil)
	if route, _ := r.Route("api.partner.io"); route != RouteVPN {
		t.Fatal("not on the list yet")
	}
	r.SetRules([]string{"*.test", "api.partner.io"})
	if route, rule := r.Route("api.partner.io"); route != RouteDirect || rule != "api.partner.io" {
		t.Fatalf("after SetRules: %s %s", route, rule)
	}
}
