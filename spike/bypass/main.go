// Spike M0.2: can a socket bound to the physical interface escape the VPN?
//
// Run it with the VPN connected. It prints the routing state, then reaches -host three
// ways, for IPv4 and IPv6 separately:
//
//  1. the normal way (follows the VPN's routes),
//  2. bound to -iface with IP_BOUND_IF / IPV6_BOUND_IF, using addresses from the system
//     resolver (so a DNS problem cannot hide a routing result),
//  3. DNS bound to -iface, against the interface's DHCP resolver and two public ones.
//
// It ends with a verdict per address family. Throwaway code.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// macOS socket options (netinet/in.h, netinet6/in6.h).
const (
	ipBoundIF   = 25  // IP_BOUND_IF
	ipv6BoundIF = 125 // IPV6_BOUND_IF
)

type result struct {
	ok    bool
	local net.IP
	note  string
}

func main() {
	host := flag.String("host", "", "host to reach outside the VPN (required)")
	port := flag.String("port", "443", "TCP port")
	iface := flag.String("iface", "en0", "physical interface to bind to")
	flag.Parse()
	if *host == "" {
		flag.Usage()
		os.Exit(2)
	}
	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "interface %s: %v\n", *iface, err)
		os.Exit(1)
	}
	ifAddrs := addrsOf(ifi)

	section("environment")
	fmt.Printf("  %s (index %d): %v\n", ifi.Name, ifi.Index, ifAddrs)
	printTunnels()
	show("default route v4", "route", "-n", "get", "default")
	show("default route v6", "route", "-n", "get", "-inet6", "default")
	show("scoped route v4 on "+ifi.Name, "route", "-n", "get", "-ifscope", ifi.Name, "default")
	show("scoped route v6 on "+ifi.Name, "route", "-n", "get", "-inet6", "-ifscope", ifi.Name, "default")
	show("VPN services", "scutil", "--nc", "list")

	section("system DNS")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", *host)
	cancel()
	if err != nil {
		fmt.Printf("  FAIL %v\n", err)
	}
	v4, v6 := split(ips)
	fmt.Printf("  v4 %v\n  v6 %v\n", v4, v6)

	plain := &net.Dialer{Timeout: 8 * time.Second}
	bound := boundDialer(ifi.Index)
	verdict := map[string][2]result{}
	for _, fam := range []struct {
		name string
		ips  []net.IP
	}{{"v4", v4}, {"v6", v6}} {
		if len(fam.ips) == 0 {
			continue
		}
		section("default route, " + fam.name)
		d := try(plain, fam.ips[0], *host, *port, ifAddrs)
		section("bound to " + ifi.Name + ", " + fam.name)
		b := try(bound, fam.ips[0], *host, *port, ifAddrs)
		verdict[fam.name] = [2]result{d, b}
	}

	section("DNS bound to " + ifi.Name)
	servers := []string{}
	if out, err := exec.Command("ipconfig", "getoption", ifi.Name, "domain_name_server").Output(); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			servers = append(servers, s)
		}
	}
	servers = append(servers, "1.1.1.1", "2606:4700:4700::1111")
	for _, s := range servers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return bound.DialContext(ctx, network, net.JoinHostPort(s, "53"))
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		got, err := r.LookupIP(ctx, "ip", *host)
		cancel()
		if err != nil {
			fmt.Printf("  %-22s FAIL %v\n", s, short(err))
		} else {
			fmt.Printf("  %-22s ok   %v (%s)\n", s, got, time.Since(start).Round(time.Millisecond))
		}
	}

	section("verdict")
	for _, fam := range []string{"v4", "v6"} {
		r, ok := verdict[fam]
		if !ok {
			fmt.Printf("  %s: host has no %s address\n", fam, fam)
			continue
		}
		d, b := r[0], r[1]
		switch {
		case d.ok && onIface(d.local, ifAddrs):
			fmt.Printf("  %s: already outside the VPN (default route uses %s); bypass not needed\n", fam, ifi.Name)
		case b.ok && onIface(b.local, ifAddrs):
			fmt.Printf("  %s: BYPASS WORKS (bound connection left via %s, TLS ok)\n", fam, ifi.Name)
		case b.ok:
			fmt.Printf("  %s: bound connection worked but local address %s is not on %s; check\n", fam, b.local, ifi.Name)
		default:
			fmt.Printf("  %s: BYPASS BLOCKED (%s)\n", fam, b.note)
		}
	}
}

func try(d *net.Dialer, ip net.IP, host, port string, ifAddrs []net.IP) result {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		fmt.Printf("  TCP  FAIL %v\n", short(err))
		return result{note: "TCP: " + short(err)}
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.TCPAddr).IP
	where := "via VPN or other interface"
	if onIface(local, ifAddrs) {
		where = "via the physical interface"
	}
	fmt.Printf("  TCP  ok   local %s -> %s (%s, %s)\n", conn.LocalAddr(), conn.RemoteAddr(), time.Since(start).Round(time.Millisecond), where)
	if port != "443" {
		return result{ok: true, local: local}
	}
	start = time.Now()
	tc := tls.Client(conn, &tls.Config{ServerName: host})
	if err := tc.HandshakeContext(ctx); err != nil {
		fmt.Printf("  TLS  FAIL %v\n", short(err))
		return result{local: local, note: "TLS: " + short(err)}
	}
	fmt.Printf("  TLS  ok   %s (%s)\n", tls.VersionName(tc.ConnectionState().Version), time.Since(start).Round(time.Millisecond))
	return result{ok: true, local: local}
}

func boundDialer(index int) *net.Dialer {
	return &net.Dialer{
		Timeout: 8 * time.Second,
		Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if strings.HasSuffix(network, "6") {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, index)
				} else {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, index)
				}
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
}

func addrsOf(ifi *net.Interface) []net.IP {
	addrs, _ := ifi.Addrs()
	var ips []net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

func onIface(ip net.IP, ifAddrs []net.IP) bool {
	for _, a := range ifAddrs {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

func split(ips []net.IP) (v4, v6 []net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return v4, v6
}

func printTunnels() {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if !strings.HasPrefix(i.Name, "utun") && !strings.HasPrefix(i.Name, "ipsec") && !strings.HasPrefix(i.Name, "ppp") {
			continue
		}
		var shown []string
		for _, ip := range addrsOf(&i) {
			if !ip.IsLinkLocalUnicast() {
				shown = append(shown, ip.String())
			}
		}
		if len(shown) > 0 {
			fmt.Printf("  tunnel %s: %v\n", i.Name, shown)
		}
	}
}

func show(title, name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	fmt.Printf("  -- %s\n", title)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "gateway") || strings.HasPrefix(l, "interface") || strings.HasPrefix(l, "route to") ||
			strings.HasPrefix(l, "*") || strings.Contains(l, "Connected") || strings.Contains(l, "not in table") ||
			strings.Contains(l, "bad address") {
			fmt.Printf("     %s\n", l)
		}
	}
	if err != nil && len(out) == 0 {
		fmt.Printf("     (%v)\n", err)
	}
}

func section(s string) { fmt.Printf("\n== %s\n", s) }

func short(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		return s[i+2:]
	}
	return s
}
