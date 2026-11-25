package sysproxy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Check returns warnings to show before Enable overrides something the user or their
// VPN set up (R4.4): a PAC file, proxy auto-discovery, or a proxy pushed by a VPN or
// configuration profile, which shows in `scutil --proxy` but on no network service.
func (m *Manager) Check(ctx context.Context) ([]string, error) {
	_, snap, err := m.read(ctx)
	if err != nil {
		return nil, err
	}
	return m.check(ctx, snap)
}

// CheckAndEnable is Check then Enable, reading each service's settings once. The
// warnings are returned even when Enable fails, to be shown with its error.
func (m *Manager) CheckAndEnable(ctx context.Context, port int) ([]string, error) {
	if err := m.canEnable(port); err != nil {
		return nil, err
	}
	services, snap, err := m.read(ctx)
	if err != nil {
		return nil, err
	}
	warnings, err := m.check(ctx, snap)
	if err != nil {
		return nil, err
	}
	return warnings, m.enable(ctx, port, services, snap)
}

// check reads each service's PAC and auto-discovery settings, all services at once, and
// the effective proxy from scutil.
func (m *Manager) check(ctx context.Context, snap []Service) ([]string, error) {
	type found struct {
		pac, discovery bool
		url            string
	}
	per := make([]found, len(snap))
	err := each(len(snap), func(i int) error {
		out, err := m.run.Run(ctx, "networksetup", "-getautoproxyurl", snap[i].Name)
		if err != nil {
			return err
		}
		kv := parseColonPairs(string(out))
		per[i].pac, per[i].url = kv["Enabled"] == "Yes", kv["URL"]
		out, err = m.run.Run(ctx, "networksetup", "-getproxyautodiscovery", snap[i].Name)
		if err != nil {
			return err
		}
		per[i].discovery = parseColonPairs(string(out))["Auto Proxy Discovery"] == "On"
		return nil
	})
	if err != nil {
		return nil, err
	}

	var warnings []string
	anyPAC, anyWeb, anySecure := false, false, false
	for i, s := range snap {
		anyWeb = anyWeb || s.Web.Enabled
		anySecure = anySecure || s.Secure.Enabled
		if per[i].pac {
			anyPAC = true
			warnings = append(warnings, fmt.Sprintf("%s uses a PAC file (%s); wraith's proxy takes precedence while it runs", s.Name, per[i].url))
		}
		if per[i].discovery {
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

// Effective is the HTTPS proxy macOS is using right now, from `scutil --proxy`.
type Effective struct {
	Enabled bool
	Host    string
	Port    int
}

// EffectiveHTTPS reads the HTTPS proxy in effect, whoever set it.
func (m *Manager) EffectiveHTTPS(ctx context.Context) (Effective, error) {
	out, err := m.run.Run(ctx, "scutil", "--proxy")
	if err != nil {
		return Effective{}, err
	}
	kv := parseScutilProxy(string(out))
	port, _ := strconv.Atoi(kv["HTTPSPort"])
	return Effective{Enabled: kv["HTTPSEnable"] == "1", Host: kv["HTTPSProxy"], Port: port}, nil
}

// StateLeft reports whether state.json exists: wraith set the proxy and has not
// restored it yet (it is running, or it crashed).
func (m *Manager) StateLeft() bool {
	_, err := m.home.ReadFile(StateFile)
	return err == nil
}
