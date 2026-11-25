package source

import (
	"net/url"
	"strings"
)

// AppFromUserAgent names the app behind a request from a physical device, where wraith
// sees no process, from its User-Agent header:
//
//	Shop/2.3.1 CFNetwork/3826.400.110 Darwin/26.0.0          → Shop
//	My%20Bank/7 CFNetwork/3826 Darwin/26.0                   → My Bank
//	Shop/2.3 (com.example.shop; build:41; iOS 26.1) Alamofire → Shop
//	Mozilla/5.0 (iPhone…) … Version/26.1 Mobile/… Safari/604  → Safari
//	Mozilla/5.0 (iPhone…) … Mobile/15E148                      → web view
//
// It is a hint, not proof: an app may send any User-Agent. "" when there is none to
// read.
func AppFromUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ""
	}
	if strings.HasPrefix(ua, "Mozilla/") {
		if strings.Contains(ua, " Safari/") && strings.Contains(ua, "Version/") {
			return "Safari"
		}
		return "web view"
	}
	name, _, _ := strings.Cut(strings.Fields(ua)[0], "/")
	if n, err := url.PathUnescape(name); err == nil {
		name = n
	}
	switch strings.ToLower(name) {
	case "cfnetwork", "darwin", "":
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		if r == ' ' || r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r > 127 {
			b.WriteRune(r)
		}
	}
	s := strings.TrimSpace(b.String())
	if len([]rune(s)) > 32 {
		s = string([]rune(s)[:32])
	}
	return s
}
