package execx

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Validators for values that end up as tool arguments (S4.3). Each returns nil or an
// error saying what was wrong; callers check before calling Run.

var (
	udidRe      = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	interfaceRe = regexp.MustCompile(`^[a-z]+[0-9]+$`)
)

// CheckUDID accepts a simulator UDID (a UUID).
func CheckUDID(s string) error {
	if !udidRe.MatchString(s) {
		return fmt.Errorf("%q is not a simulator UDID", s)
	}
	return nil
}

// CheckInterface accepts a BSD interface name such as en0 or utun3.
func CheckInterface(s string) error {
	if !interfaceRe.MatchString(s) {
		return fmt.Errorf("%q is not an interface name like en0", s)
	}
	return nil
}

// CheckPort accepts a TCP port, 1 to 65535.
func CheckPort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d is not between 1 and 65535", p)
	}
	return nil
}

// CheckService accepts a network service name only if it is one of known, the list
// `networksetup -listallnetworkservices` returned. A name that starts with "-" is
// refused even if listed, so it can never be read as an option.
func CheckService(name string, known []string) error {
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "\x00\n\r") {
		return fmt.Errorf("%q is not a usable network service name", name)
	}
	if !slices.Contains(known, name) {
		return fmt.Errorf("network service %q is not on this Mac", name)
	}
	return nil
}
