package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/ca"
	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/keychain"
	"github.com/esuEdu/wraith/internal/route"
	"github.com/esuEdu/wraith/internal/sysproxy"
)

// report prints one line per check and remembers whether anything failed.
type report struct {
	a      *app
	failed int
}

func (r *report) line(status, format string, args ...any) {
	if status == "fail" {
		r.failed++
	}
	_, _ = fmt.Fprintf(r.a.d.Stdout, "%-5s %s\n", status, fmt.Sprintf(format, args...))
}

func (a *app) doctorCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the system proxy, CA, simulators, interface and bypass",
		Long: "Checks what wraith depends on and prints ok, info, warn or fail for each.\n" +
			"The bypass check dials a test host the normal way and bound to the physical\n" +
			"interface, for IPv4 and IPv6 separately, so a VPN that blocks one shows.\n" +
			"Exits 3 if any check fails.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.doctor(cmd.Context(), host) },
	}
	cmd.Flags().StringVar(&host, "host", "", "test host for the bypass check (default: the first exact host on the bypass list, else example.com)")
	return cmd
}

func (a *app) doctor(ctx context.Context, host string) error {
	r := &report{a: a}
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()

	cfg, _, err := config.Load(h)
	if err != nil {
		r.line("fail", "config: %v", err)
		cfg = config.Default()
	} else {
		r.line("ok", "config: %s/%s", h.Path(), config.FileName)
	}

	running := a.doctorInstance(r, h)
	a.doctorProxy(ctx, r, h, cfg, running)
	a.doctorCA(ctx, r, h)
	a.doctorBypass(ctx, r, cfg, host)

	if r.failed > 0 {
		return fail(ExitState, "%d check(s) failed", r.failed)
	}
	return nil
}

func (a *app) doctorInstance(r *report, h *home.Home) bool {
	lock, err := h.Lock()
	var le *home.LockedError
	switch {
	case errors.As(err, &le):
		r.line("info", "wraith is running (pid %d)", le.PID)
		return true
	case err != nil:
		r.line("warn", "lock: %v", err)
		return false
	}
	_ = lock.Unlock()
	r.line("info", "wraith is not running")
	return false
}

func (a *app) doctorProxy(ctx context.Context, r *report, h *home.Home, cfg config.Config, running bool) {
	sp := sysproxy.New(a.d.Runner, h, nil)
	if sp.StateLeft() && !running {
		r.line("fail", "system proxy: settings left by a run that did not exit cleanly; run `wraith stop`")
	}
	eff, err := sp.EffectiveHTTPS(ctx)
	switch {
	case err != nil:
		r.line("warn", "system proxy: %v", err)
	case !eff.Enabled:
		r.line("info", "system proxy: off")
	case isLoopback(eff.Host) && eff.Port == cfg.Port && !running:
		r.line("fail", "system proxy points at wraith (%s:%d) but wraith is not running: HTTPS will fail; run `wraith stop`", eff.Host, eff.Port)
	case isLoopback(eff.Host) && eff.Port == cfg.Port:
		r.line("ok", "system proxy points at wraith (%s:%d)", eff.Host, eff.Port)
	default:
		r.line("info", "system proxy: %s:%d (not wraith)", eff.Host, eff.Port)
	}
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func (a *app) doctorCA(ctx context.Context, r *report, h *home.Home) {
	cert, err := ca.Peek(h)
	if errors.Is(err, fs.ErrNotExist) {
		r.line("info", "CA: not created yet (`wraith start` or `wraith ca install` creates it)")
		return
	}
	if err != nil {
		r.line("fail", "CA: %v", err)
		return
	}
	fp := sha256.Sum256(cert.Raw)
	left := time.Until(cert.NotAfter)
	switch {
	case left < 0:
		r.line("fail", "CA expired on %s; run `wraith ca rotate`", cert.NotAfter.Format("2006-01-02"))
	case left < ca.WarnBefore:
		r.line("warn", "CA expires on %s; run `wraith ca rotate`", cert.NotAfter.Format("2006-01-02"))
	default:
		r.line("ok", "CA: %s, SHA-256 %X…, valid until %s", cert.Subject.CommonName, fp[:6], cert.NotAfter.Format("2006-01-02"))
	}

	if k, err := keychain.New(a.d.Runner); err == nil {
		if trusted, err := k.Trusted(ctx, certPath(h)); err != nil {
			r.line("warn", "Mac keychain: %v", err)
		} else if trusted {
			r.line("info", "the Mac trusts the CA: Mac apps in the source are decrypted")
		} else {
			r.line("info", "the Mac does not trust the CA (default): Mac apps are passed through")
		}
	}

	sm, err := a.simManager()
	if err != nil {
		r.line("warn", "simulators: %v", err)
		return
	}
	booted, err := sm.BootedDevices(ctx)
	if err != nil {
		r.line("warn", "simulators: %v", err)
		return
	}
	if len(booted) == 0 {
		r.line("info", "no simulator is booted")
	}
	for _, d := range booted {
		if ok, err := sm.Installed(ctx, d, fp); err != nil {
			r.line("warn", "%s: %v", d, err)
		} else if ok {
			r.line("ok", "%s trusts the CA", d)
		} else {
			r.line("warn", "%s does not trust the CA; run `wraith ca install` (wraith start does it too)", d)
		}
	}
}

func (a *app) doctorBypass(ctx context.Context, r *report, cfg config.Config, host string) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	router := route.New(rctx, a.d.Runner, cfg.Bypass, cfg.Interface)
	cancel()
	ifi, err := router.Iface()
	if err != nil {
		status := "warn"
		if len(cfg.Bypass) > 0 {
			status = "fail"
		}
		r.line(status, "interface: %v; bypassed hosts cannot work, so the bypass check is skipped", err)
		return
	}
	addrs := make([]string, 0, len(ifi.Addrs))
	for _, ip := range ifi.Addrs {
		addrs = append(addrs, ip.String())
	}
	r.line("ok", "interface: %s (%s)", ifi.Name, strings.Join(addrs, ", "))

	if host == "" {
		host = "example.com"
		for _, p := range cfg.Bypass {
			if !strings.HasPrefix(p, "*.") {
				host = p
				break
			}
		}
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	probes, dnsErr := router.Probe(pctx, host, "443")
	if dnsErr != nil {
		r.line("warn", "bypass DNS for %s over %s failed: %v", host, ifi.Name, dnsErr)
	}
	if len(probes) == 0 {
		r.line("fail", "bypass check: could not resolve %s", host)
		return
	}
	var works []string
	for _, p := range probes {
		r.line("info", "%s %s: normal path %s; bypass %s", p.Family, p.Addr, describeLeg(p.Default, ifi.Name), describeLeg(p.Bound, ifi.Name))
		if p.Bound.Err == nil {
			works = append(works, p.Family)
		}
	}
	if len(works) == 0 {
		r.line("fail", "bypass is blocked on this network for %s: the VPN refuses connections bound to %s", host, ifi.Name)
		return
	}
	r.line("ok", "bypass works for %s over %s", host, strings.Join(works, " and "))
}

func describeLeg(l route.Leg, physical string) string {
	if l.Err != nil {
		msg := l.Err.Error()
		if i := strings.LastIndex(msg, ": "); i >= 0 && len(msg) > 80 {
			msg = msg[i+2:]
		}
		return "fails (" + msg + ")"
	}
	where := "via " + l.Via
	if l.Via != physical && strings.HasPrefix(l.Via, "utun") {
		where += " (a VPN tunnel)"
	}
	return where + " from " + l.Local.String()
}
