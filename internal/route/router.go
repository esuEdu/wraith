package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
)

// macOS socket options (netinet/in.h, netinet6/in6.h).
const (
	ipBoundIF   = 25  // IP_BOUND_IF
	ipv6BoundIF = 125 // IPV6_BOUND_IF
)

// Routes as shown in the log (R3.5).
const (
	RouteVPN    = "vpn"    // the normal path: through the VPN if it captures the host
	RouteDirect = "direct" // bypassed, on the physical interface
)

// ErrBypassFailed is wrapped by every failed bypass dial. A bypassed host is never dialed
// the normal way instead (R3.4, S2.5).
var ErrBypassFailed = errors.New("bypass failed")

// Public resolvers tried, bound to the interface, after its own DHCP resolver. IPv6
// first: on a VPN that captures IPv4, the IPv6 one is often the one that answers (M0).
var publicDNS = []string{"2606:4700:4700::1111", "1.1.1.1"}

// Router is a proxy.Dialer: bypassed hosts go out on the physical interface, everything
// else the normal way.
type Router struct {
	rules    Rules
	iface    Iface
	ifaceErr error
	servers  []string
	direct   interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	// lookup resolves a bypassed host; tests replace it.
	lookup func(ctx context.Context, host string) ([]net.IP, error)
}

// New builds a Router for the bypass patterns, detecting the interface (ifaceName: "auto"
// or a name). A detection failure is kept: bypassed hosts then fail closed with it, and
// everything else still works.
func New(ctx context.Context, run execx.Runner, patterns []string, ifaceName string) *Router {
	r := &Router{rules: NewRules(patterns), direct: &net.Dialer{}}
	r.iface, r.ifaceErr = DetectIface(ctx, run, ifaceName)
	if r.ifaceErr == nil {
		if out, err := run.Run(ctx, "ipconfig", "getoption", r.iface.Name, "domain_name_server"); err == nil {
			if ip := net.ParseIP(strings.TrimSpace(string(out))); ip != nil {
				r.servers = append(r.servers, ip.String())
			}
		}
	}
	r.servers = append(r.servers, publicDNS...)
	r.lookup = r.boundLookup
	return r
}

// Iface returns the interface used for bypassed hosts, or why there is none.
func (r *Router) Iface() (Iface, error) { return r.iface, r.ifaceErr }

// Route returns how host is reached, and the bypass rule it matched.
func (r *Router) Route(host string) (route, rule string) {
	if rule, ok := r.rules.Match(host); ok {
		return RouteDirect, rule
	}
	return RouteVPN, ""
}

// DialContext dials addr ("host:port"), around the VPN when host is on the bypass list.
func (r *Router) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if route, _ := r.Route(host); route != RouteDirect {
		return r.direct.DialContext(ctx, network, addr)
	}
	return r.dialBypass(ctx, host, port)
}

// dialBypass resolves host over the interface and dials it bound to the interface, IPv6
// addresses first, then IPv4 (M0 decision). It never falls back to the normal path.
func (r *Router) dialBypass(ctx context.Context, host, port string) (net.Conn, error) {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s via %s: %s", ErrBypassFailed, host, r.ifaceName(), fmt.Sprintf(format, args...))
	}
	if r.ifaceErr != nil {
		return nil, fail("%v", r.ifaceErr)
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		var err error
		if ips, err = r.lookup(ctx, host); err != nil {
			return nil, fail("DNS: %v", err)
		}
	}
	var v6, v4 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	var errs []string
	for _, ip := range append(v6, v4...) {
		network := "tcp6"
		if ip.To4() != nil {
			network = "tcp4"
		}
		conn, err := r.bound().DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, fail("no address")
	}
	return nil, fail("%s", strings.Join(errs, "; "))
}

func (r *Router) ifaceName() string {
	if r.ifaceErr != nil {
		return "the physical interface"
	}
	return r.iface.Name
}

// bound returns a dialer whose sockets are bound to the interface: macOS then uses that
// interface's scoped route instead of the VPN's.
func (r *Router) bound() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: bindControl(r.iface.Index)}
}

func bindControl(index int) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
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
	}
}

// boundLookup asks each resolver in turn, over the interface, never the system resolver:
// the VPN's DNS may hide or redirect a bypassed host (S2.5). Go's resolver still reads
// /etc/hosts first, which is local and not the VPN's.
func (r *Router) boundLookup(ctx context.Context, host string) ([]net.IP, error) {
	var errs []string
	for _, server := range r.servers {
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return r.bound().DialContext(ctx, network, net.JoinHostPort(server, "53"))
			},
		}
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := res.LookupIP(qctx, "ip", host)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", server, err))
	}
	return nil, errors.New(strings.Join(errs, "; "))
}
