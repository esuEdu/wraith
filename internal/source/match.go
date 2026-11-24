package source

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// Source is a parsed --source value (R1.1).
type Source struct {
	Kind string // all, simulator, app, pid, device
	Arg  string // simulator UDID or name, app name or bundle id, device address; empty for all, simulator and device
	PID  int
}

// Parse reads all, simulator, simulator:<udid|name>, app:<name|bundle-id>, pid:<pid>,
// device or device:<ip>.
func Parse(s string) (Source, error) {
	kind, arg, has := strings.Cut(s, ":")
	switch {
	case s == "all", s == "simulator", s == "device":
		return Source{Kind: s}, nil
	case kind == "device" && has:
		if ip := net.ParseIP(arg); ip != nil {
			return Source{Kind: kind, Arg: ip.String()}, nil
		}
	case (kind == "simulator" || kind == "app") && has && arg != "":
		return Source{Kind: kind, Arg: arg}, nil
	case kind == "pid" && has:
		if n, err := strconv.Atoi(arg); err == nil && n > 0 {
			return Source{Kind: kind, PID: n}, nil
		}
	}
	return Source{}, fmt.Errorf("source %q must be all, simulator, simulator:<udid|name>, app:<name|bundle-id>, pid:<pid>, device or device:<ip>", s)
}

func (s Source) String() string {
	switch s.Kind {
	case "pid":
		return "pid:" + strconv.Itoa(s.PID)
	case "all", "simulator", "device":
		if s.Arg == "" {
			return s.Kind
		}
	}
	return s.Kind + ":" + s.Arg
}

// Matches reports whether a connection from o is inside the source. simName returns a
// simulator's device name for its UDID ("" if unknown); it is only called for
// simulator:<name>. A device matches all, device and its own device:<ip>. An unidentified
// origin (zero PID) matches nothing (R1.4).
func (s Source) Matches(o Origin, simName func(udid string) string) bool {
	if o.Device != "" {
		return s.Kind == "all" || s.Kind == "device" && (s.Arg == "" || s.Arg == o.Device)
	}
	if o.PID == 0 {
		return false
	}
	switch s.Kind {
	case "all":
		return true
	case "simulator":
		if !o.Simulator() {
			return false
		}
		if s.Arg == "" || strings.EqualFold(s.Arg, o.SimUDID) {
			return true
		}
		return simName != nil && strings.EqualFold(s.Arg, simName(o.SimUDID))
	case "app":
		if o.AppPath != "" {
			return strings.EqualFold(s.Arg, o.BundleID) || strings.EqualFold(s.Arg, o.AppName)
		}
		// Not in a bundle (a command-line tool): match the executable's name.
		return len(o.Chain) > 0 && strings.EqualFold(s.Arg, filepath.Base(o.Chain[0].Path))
	case "pid":
		for _, p := range o.Chain {
			if p.PID == s.PID {
				return true // the process or one of its children
			}
		}
	}
	return false
}
