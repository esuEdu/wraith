package route

import (
	"context"
	"net"
)

// Probe is what `wraith doctor` learns about one address family of a test host.
type Probe struct {
	Family  string // "IPv6" or "IPv4"
	Addr    net.IP // the address tried
	Default Leg    // the normal path
	Bound   Leg    // bound to the physical interface (the bypass)
}

// Leg is one dial attempt.
type Leg struct {
	Local net.IP // our local address, when connected
	Via   string // the interface that address belongs to (en0, utun6, ...)
	Err   error
}

// Probe resolves host over the interface (falling back to the system resolver so the
// normal path can still be shown) and, for each family, dials it the normal way and
// bound to the interface, IPv6 first. It returns the resolution error, if any, and one
// Probe per family that has an address.
func (r *Router) Probe(ctx context.Context, host, port string) ([]Probe, error) {
	ips, dnsErr := r.lookup(ctx, host)
	if dnsErr != nil {
		sys, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, dnsErr
		}
		ips = sys
	}
	var v6, v4 net.IP
	for _, ip := range ips {
		if ip.To4() == nil && v6 == nil {
			v6 = ip
		} else if ip.To4() != nil && v4 == nil {
			v4 = ip
		}
	}
	var probes []Probe
	for _, p := range []struct {
		family, network string
		ip              net.IP
	}{{"IPv6", "tcp6", v6}, {"IPv4", "tcp4", v4}} {
		if p.ip == nil {
			continue
		}
		addr := net.JoinHostPort(p.ip.String(), port)
		pr := Probe{Family: p.family, Addr: p.ip}
		pr.Default = leg(ctx, &net.Dialer{}, p.network, addr)
		if r.ifaceErr != nil {
			pr.Bound = Leg{Err: r.ifaceErr}
		} else {
			pr.Bound = leg(ctx, r.bound(), p.network, addr)
		}
		probes = append(probes, pr)
	}
	return probes, dnsErr
}

func leg(ctx context.Context, d *net.Dialer, network, addr string) Leg {
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return Leg{Err: err}
	}
	defer func() { _ = c.Close() }()
	local := c.LocalAddr().(*net.TCPAddr).IP
	return Leg{Local: local, Via: interfaceOf(local)}
}

// interfaceOf names the interface that owns ip, or "?".
func interfaceOf(ip net.IP) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return "?"
	}
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return i.Name
			}
		}
	}
	return "?"
}
