// Spike M0.2: can a socket bound to the physical interface escape the VPN?
//
// Resolves and connects to -host twice: once the normal way (follows the
// VPN's routes) and once with IP_BOUND_IF set to -iface, including the DNS
// lookup. Prints the local address of each connection and whether a TLS
// handshake succeeds. If the bound connection's local address belongs to
// -iface and TLS works, the bypass design holds for this VPN.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// macOS socket options (netinet/in.h, netinet6/in6.h).
const (
	ipBoundIF   = 25  // IP_BOUND_IF
	ipv6BoundIF = 125 // IPV6_BOUND_IF
)

func main() {
	host := flag.String("host", "", "host to reach outside the VPN (required)")
	port := flag.String("port", "443", "TCP port")
	iface := flag.String("iface", "en0", "physical interface to bind to")
	dns := flag.String("dns", "1.1.1.1:53", "DNS server used for the bound lookup")
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
	addrs, _ := ifi.Addrs()
	fmt.Printf("interface %s (index %d): %v\n\n", ifi.Name, ifi.Index, addrs)

	fmt.Println("== default route (through the VPN, if it captures this host)")
	try(&net.Dialer{Timeout: 8 * time.Second}, net.DefaultResolver, *host, *port)

	fmt.Printf("\n== bound to %s, DNS via %s\n", ifi.Name, *dns)
	d := boundDialer(ifi.Index)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, *dns)
		},
	}
	try(d, r, *host, *port)
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

func try(d *net.Dialer, r *net.Resolver, host, port string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		fmt.Printf("  DNS    FAIL %v\n", err)
		return
	}
	fmt.Printf("  DNS    ok   %v (%s)\n", ips, time.Since(start).Round(time.Millisecond))

	start = time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ips[0], port))
	if err != nil {
		fmt.Printf("  TCP    FAIL %v\n", err)
		return
	}
	defer conn.Close()
	fmt.Printf("  TCP    ok   local %s -> %s (%s)\n", conn.LocalAddr(), conn.RemoteAddr(), time.Since(start).Round(time.Millisecond))

	if port != "443" {
		return
	}
	start = time.Now()
	tc := tls.Client(conn, &tls.Config{ServerName: host})
	if err := tc.HandshakeContext(ctx); err != nil {
		fmt.Printf("  TLS    FAIL %v\n", err)
		return
	}
	fmt.Printf("  TLS    ok   %s (%s)\n", tls.VersionName(tc.ConnectionState().Version), time.Since(start).Round(time.Millisecond))
}
