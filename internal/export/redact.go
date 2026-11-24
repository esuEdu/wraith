// Package export turns captured flows into files people share: HAR and curl commands.
// Secrets are redacted by default (R5.3): headers matching the configured patterns, and
// query parameters with matching names.
package export

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Redacted replaces a secret value.
const Redacted = "REDACTED"

// DefaultPatterns are the header (and query parameter) name patterns redacted by
// default; * matches any run of characters, and matching ignores case.
var DefaultPatterns = []string{"Authorization", "Cookie", "Set-Cookie", "*token*"}

// Redactor hides values whose names match its patterns. The zero value hides nothing.
type Redactor struct{ patterns []string }

// NewRedactor returns a Redactor for patterns; nil or empty redacts nothing.
func NewRedactor(patterns []string) Redactor {
	lower := make([]string, len(patterns))
	for i, p := range patterns {
		lower[i] = strings.ToLower(p)
	}
	return Redactor{patterns: lower}
}

// Matches reports whether name should be hidden.
func (r Redactor) Matches(name string) bool {
	n := strings.ToLower(name)
	for _, p := range r.patterns {
		if ok, _ := path.Match(p, n); ok {
			return true
		}
	}
	return false
}

// Header returns a copy of h with matching values replaced.
func (r Redactor) Header(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := append([]string(nil), vs...)
		if r.Matches(k) {
			for i := range cp {
				cp[i] = Redacted
			}
		}
		out[k] = cp
	}
	return out
}

// URL returns u with the values of matching query parameters replaced.
func (r Redactor) URL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.RawQuery == "" {
		return u
	}
	q := parsed.Query()
	changed := false
	for k := range q {
		if r.Matches(k) {
			for i := range q[k] {
				q[k][i] = Redacted
			}
			changed = true
		}
	}
	if !changed {
		return u
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
