package sysproxy

import (
	"context"
	"fmt"
	"strings"
)

// Check returns warnings to show before Enable overrides something the user or their
// VPN set up (R4.4): a PAC file, proxy auto-discovery, or a proxy pushed by a VPN or
// configuration profile, which shows in `scutil --proxy` but on no network service.
func (m *Manager) Check(ctx context.Context) ([]string, error) {
	services, err := m.Services(ctx)
	if err != nil {
		return nil, err
	}
	snap, err := m.Snapshot(ctx, services)
	if err != nil {
		return nil, err
	}

	var warnings []string
	anyPAC, anyWeb, anySecure := false, false, false
	for _, s := range snap {
		anyWeb = anyWeb || s.Web.Enabled
		anySecure = anySecure || s.Secure.Enabled

		out, err := m.run.Run(ctx, "networksetup", "-getautoproxyurl", s.Name)
		if err != nil {
			return nil, err
		}
		kv := parseColonPairs(string(out))
		if kv["Enabled"] == "Yes" {
			anyPAC = true
			warnings = append(warnings, fmt.Sprintf("%s uses a PAC file (%s); wraith's proxy takes precedence while it runs", s.Name, kv["URL"]))
		}

		out, err = m.run.Run(ctx, "networksetup", "-getproxyautodiscovery", s.Name)
		if err != nil {
			return nil, err
		}
		if parseColonPairs(string(out))["Auto Proxy Discovery"] == "On" {
			warnings = append(warnings, fmt.Sprintf("%s has proxy auto-discovery on; wraith's proxy takes precedence while it runs", s.Name))
		}
	}

	out, err := m.run.Run(ctx, "scutil", "--proxy")
	if err != nil {
		return nil, err
	}
	eff := parseScutilProxy(string(out))
	pushed := (eff["ProxyAutoConfigEnable"] == "1" && !anyPAC) ||
		(eff["HTTPEnable"] == "1" && !anyWeb) ||
		(eff["HTTPSEnable"] == "1" && !anySecure)
	if pushed {
		warnings = append(warnings, "a proxy is set by a VPN or configuration profile (see `scutil --proxy`); it may override wraith, or wraith may break access it provides")
	}
	return warnings, nil
}

// parseColonPairs reads "Key: value" lines.
func parseColonPairs(out string) map[string]string {
	kv := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return kv
}

// parseScutilProxy reads the top-level "Key : value" pairs of `scutil --proxy`.
func parseScutilProxy(out string) map[string]string {
	kv := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		k, v, ok := strings.Cut(line, " : ")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return kv
}
