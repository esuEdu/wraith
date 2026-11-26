// Package netif finds the Mac's physical network interface: the Wi-Fi or Ethernet
// one that --device listens on.
package netif

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/esuEdu/wraith/internal/execx"
)

// Iface is the physical interface: Wi-Fi or Ethernet, not a VPN tunnel.
type Iface struct {
	Name  string
	Index int
	Addrs []net.IP // global unicast addresses
}

// ErrNoInterface means no physical interface with its own default route is up.
var ErrNoInterface = errors.New("no physical network interface with a default route")

var physical = regexp.MustCompile(`^en[0-9]+$`)

// DetectIface returns the physical interface. name is the configured value: "auto" (or
// "") picks the first en* interface that is up, has a global address and its own scoped
// default route, which macOS keeps even while a VPN owns the main one; anything else
// must name such an interface.
func DetectIface(ctx context.Context, run execx.Runner, name string) (Iface, error) {
	if name != "" && name != "auto" {
		if err := execx.CheckInterface(name); err != nil {
			return Iface{}, err
		}
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return Iface{}, fmt.Errorf("interface %s: %w", name, err)
		}
		it, ok := usable(ctx, run, ifi)
		if !ok {
			return Iface{}, fmt.Errorf("interface %s is down, has no address or no default route", name)
		}
		return it, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return Iface{}, err
	}
	for i := range ifs {
		if !physical.MatchString(ifs[i].Name) {
			continue
		}
		if it, ok := usable(ctx, run, &ifs[i]); ok {
			return it, nil
		}
	}
	return Iface{}, ErrNoInterface
}

func usable(ctx context.Context, run execx.Runner, ifi *net.Interface) (Iface, bool) {
	if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
		return Iface{}, false
	}
	it := Iface{Name: ifi.Name, Index: ifi.Index}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() {
			it.Addrs = append(it.Addrs, n.IP)
		}
	}
	if len(it.Addrs) == 0 {
		return Iface{}, false
	}
	if !hasScopedDefault(ctx, run, ifi.Name, false) && !hasScopedDefault(ctx, run, ifi.Name, true) {
		return Iface{}, false
	}
	return it, true
}

// hasScopedDefault asks `route` for the interface's own default route, which macOS keeps
// even while a VPN owns the main one.
func hasScopedDefault(ctx context.Context, run execx.Runner, name string, v6 bool) bool {
	args := []string{"-n", "get"}
	if v6 {
		args = append(args, "-inet6")
	}
	args = append(args, "-ifscope", name, "default")
	out, err := run.Run(ctx, "route", args...)
	return err == nil && strings.Contains(string(out), "interface: "+name)
}

// HasV4 and HasV6 report the families the interface has addresses for.
func (i Iface) HasV4() bool { return i.has(true) }
func (i Iface) HasV6() bool { return i.has(false) }

func (i Iface) has(v4 bool) bool {
	for _, a := range i.Addrs {
		if (a.To4() != nil) == v4 {
			return true
		}
	}
	return false
}
