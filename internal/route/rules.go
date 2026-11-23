// Package route decides how wraith reaches an upstream host: the normal way (through the
// VPN, if one captures it) or around the VPN on the physical interface, for hosts on the
// bypass list (R3).
package route

import (
	"slices"
	"strings"
)

// Rules is the bypass list: exact hosts and "*.domain" wildcards (subdomains only), as
// config.NormalizeHostPattern produces them.
type Rules struct {
	exact    map[string]bool
	suffixes []string // ".domain" for "*.domain", longest first
}

// NewRules indexes patterns.
func NewRules(patterns []string) Rules {
	r := Rules{exact: map[string]bool{}}
	for _, p := range patterns {
		if d, ok := strings.CutPrefix(p, "*."); ok {
			r.suffixes = append(r.suffixes, "."+d)
		} else {
			r.exact[p] = true
		}
	}
	slices.SortFunc(r.suffixes, func(a, b string) int { return len(b) - len(a) })
	return r
}

// Match returns the rule that host falls under, the most specific one when several do
// (R3.1): an exact host beats any wildcard, a longer wildcard beats a shorter one.
func (r Rules) Match(host string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if r.exact[h] {
		return h, true
	}
	for _, s := range r.suffixes {
		if strings.HasSuffix(h, s) {
			return "*" + s, true
		}
	}
	return "", false
}

// Empty reports whether there are no rules.
func (r Rules) Empty() bool { return len(r.exact) == 0 && len(r.suffixes) == 0 }
