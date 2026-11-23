// Package cli is wraith's command line: start, stop and version for now; the rest of the
// spec's commands arrive with their milestones. Main returns the process exit code
// (R6.3): 0 ok, 1 runtime error, 2 usage error, 3 system-state error (proxy or CA).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/ca"
	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/keychain"
	"github.com/esuEdu/wraith/internal/proxy"
	"github.com/esuEdu/wraith/internal/sim"
	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/sysproxy"
	"github.com/esuEdu/wraith/internal/version"
)

// Exit codes (R6.3).
const (
	ExitOK      = 0
	ExitRuntime = 1
	ExitUsage   = 2
	ExitState   = 3
)

// Deps are the outside world the CLI touches. Zero fields take the real thing; tests
// replace them.
type Deps struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	Runner         execx.Runner
	HomeDir        string
	Geteuid        func() int
	// Signals returns a channel of shutdown signals and a function that stops delivery.
	Signals func() (<-chan os.Signal, func())
	Kill    func(pid int, sig syscall.Signal) error
	// Ready, if set, is called once start is serving (and the system proxy is set).
	Ready func(addr string)
	// StopTimeout is how long `wraith stop` waits for a running instance to exit.
	StopTimeout time.Duration
	// SimDevicesDir is CoreSimulator's device folder; "" means the user's.
	SimDevicesDir string
	// SimPoll is how often start looks for newly booted simulators (R1.6).
	SimPoll time.Duration
	// Lookup identifies the process behind a client connection; nil uses source.Resolver.
	Lookup func(ctx context.Context, clientPort, proxyPort int) (source.Origin, error)
}

func (d *Deps) fill() {
	if d.Stdout == nil {
		d.Stdout = os.Stdout
	}
	if d.Stderr == nil {
		d.Stderr = os.Stderr
	}
	if d.Stdin == nil {
		d.Stdin = os.Stdin
	}
	if d.Runner == nil {
		d.Runner = execx.Default()
	}
	if d.Geteuid == nil {
		d.Geteuid = os.Geteuid
	}
	if d.Signals == nil {
		d.Signals = func() (<-chan os.Signal, func()) {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
			return ch, func() { signal.Stop(ch) }
		}
	}
	if d.Kill == nil {
		d.Kill = syscall.Kill
	}
	if d.StopTimeout <= 0 {
		d.StopTimeout = 10 * time.Second
	}
	if d.SimPoll <= 0 {
		d.SimPoll = 2 * time.Second
	}
}

// exitError carries an exit code through cobra.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

// Main runs wraith with args (without the program name) and returns the exit code.
func Main(ctx context.Context, args []string, d Deps) int {
	d.fill()
	a := &app{d: d}
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetOut(d.Stdout)
	root.SetErr(d.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	_, _ = fmt.Fprintln(d.Stderr, "wraith:", err)
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return ExitUsage // cobra's own errors: unknown command or flag, bad flag value
}

type app struct{ d Deps }

func (a *app) info(format string, args ...any) {
	_, _ = fmt.Fprintf(a.d.Stderr, "wraith: "+format+"\n", args...)
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "wraith",
		Short:         "Inspect traffic from one source and route chosen domains around the VPN",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(a.startCmd(), a.stopCmd(), a.versionCmd(), a.caCmd())
	for _, p := range []struct{ name, short, milestone string }{
		{"bypass", "add | rm | list hosts that skip the VPN", "M4"},
		{"doctor", "check proxy, CA and bypass", "M4"},
		{"export", "save captured flows as HAR", "M5"},
	} {
		root.AddCommand(&cobra.Command{
			Use:                p.name,
			Short:              p.short + " (planned, " + p.milestone + ")",
			DisableFlagParsing: true,
			RunE: func(*cobra.Command, []string) error {
				return fail(ExitUsage, "%s is not implemented yet (milestone %s)", p.name, p.milestone)
			},
		})
	}
	return root
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build info",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(a.d.Stdout, "wraith %s (%s, %s)\n", version.Version, version.Commit, version.Date)
			return err
		},
	}
}

// openHome refuses root (S4.1), then opens and checks the home directory.
func (a *app) openHome() (*home.Home, error) {
	if a.d.Geteuid() == 0 {
		return nil, fail(ExitUsage, "do not run wraith as root (or with sudo); run it as your user, and macOS will ask for admin rights itself if it needs them")
	}
	dir := a.d.HomeDir
	if dir == "" {
		var err error
		if dir, err = home.Dir(); err != nil {
			return nil, fail(ExitRuntime, "%v", err)
		}
	}
	h, err := home.Open(dir)
	if err != nil {
		return nil, fail(ExitRuntime, "%v", err)
	}
	return h, nil
}

func (a *app) startCmd() *cobra.Command {
	var (
		port          int
		source, iface string
		maxFlows      int
		maxBody       int64
		noSystemProxy bool
		logMode       bool
		noDecrypt     bool
		insecure      []string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Set the system proxy and start the proxy",
		Long: "Set the system proxy and start the proxy. Until the live view arrives (M5),\n" +
			"start prints one line per request, as with --log.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var o config.Overrides
			f := cmd.Flags()
			if f.Changed("port") {
				o.Port = &port
			}
			if f.Changed("source") {
				o.Source = &source
			}
			if f.Changed("iface") {
				o.Interface = &iface
			}
			if f.Changed("max-flows") {
				o.MaxFlows = &maxFlows
			}
			if f.Changed("max-body") {
				o.MaxBodyBytes = &maxBody
			}
			_ = logMode // the only mode until M5
			if len(insecure) > 0 && noDecrypt {
				return fail(ExitUsage, "--insecure-upstream does not apply with --no-decrypt")
			}
			return a.start(cmd.Context(), o, startOpts{noSystemProxy: noSystemProxy, decrypt: !noDecrypt, insecure: insecure})
		},
	}
	f := cmd.Flags()
	f.IntVar(&port, "port", 9090, "proxy port on 127.0.0.1 and ::1")
	f.StringVar(&source, "source", "simulator", "capture source: all, simulator[:udid|name], app:<name|bundle-id>, pid:<pid>")
	f.StringVar(&iface, "iface", "auto", "physical interface for bypassed hosts (bypass arrives in M4)")
	f.IntVar(&maxFlows, "max-flows", 5000, "flows kept in memory")
	f.Int64Var(&maxBody, "max-body", 1<<20, "bodies above this many bytes are truncated")
	f.BoolVar(&noSystemProxy, "no-system-proxy", false, "listen only; leave the system proxy settings alone")
	f.BoolVar(&logMode, "log", false, "print one line per request instead of the live view")
	f.BoolVar(&noDecrypt, "no-decrypt", false, "pass HTTPS through without decrypting it")
	f.StringArrayVar(&insecure, "insecure-upstream", nil, "do not verify this host's certificate, e.g. a local dev server (repeatable)")
	return cmd
}

type startOpts struct {
	noSystemProxy bool
	decrypt       bool
	insecure      []string
}

func (a *app) start(ctx context.Context, o config.Overrides, so startOpts) (err error) {
	noSystemProxy := so.noSystemProxy
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()

	lock, err := h.Lock()
	if err != nil {
		var le *home.LockedError
		if errors.As(err, &le) && le.PID > 0 {
			return fail(ExitRuntime, "wraith is already running (pid %d); stop it with `wraith stop`", le.PID)
		}
		return fail(ExitRuntime, "%v", err)
	}
	defer func() { _ = lock.Unlock() }()

	cfg, created, err := config.Load(h)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if created {
		a.info("created %s/%s with default settings", h.Path(), config.FileName)
	}
	if cfg, err = cfg.With(o); err != nil {
		return fail(ExitUsage, "%v", err)
	}

	sp := sysproxy.New(a.d.Runner, h, func(f string, args ...any) { a.info(f, args...) })
	recovered, err := sp.Recover(ctx)
	if err != nil {
		return fail(ExitState, "%v", err)
	}
	if recovered {
		a.info("the last run did not exit cleanly; its system proxy settings have been restored")
	}

	lns, err := proxy.Listen(cfg.Port)
	if err != nil {
		return fail(ExitRuntime, "cannot listen on port %d: %v", cfg.Port, err)
	}
	popts := proxy.Options{Logf: func(f string, args ...any) {
		_, _ = fmt.Fprintf(a.d.Stdout, time.Now().Format("15:04:05")+" "+f+"\n", args...)
	}}
	sm, smErr := a.simManager()
	macTrusted := false
	stopSimWatch := func() {}
	if so.decrypt {
		c, trusted, err := a.setupDecryption(h, cfg, so.insecure, &popts)
		macTrusted = trusted
		if err != nil {
			for _, ln := range lns {
				_ = ln.Close()
			}
			return err
		}
		if smErr != nil {
			a.info("simulators: %v", smErr)
		} else {
			watchCtx, cancel := context.WithCancel(ctx)
			watchDone := make(chan struct{})
			go func() {
				defer close(watchDone)
				sm.Watch(watchCtx, a.d.SimPoll, certPath(h), c.SHA256(), a.info)
			}()
			stopSimWatch = func() { cancel(); <-watchDone }
		}
	}
	src, err := source.Parse(cfg.Source)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	popts.Classify = a.classifier(src, sm, macTrusted)
	a.info("capturing %s; everything else passes through untouched", src)
	srv := proxy.New(popts)
	for _, ln := range lns {
		go func() { _ = srv.Serve(ln) }()
	}

	systemSet := false
	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() {
			stopSimWatch()
			_ = srv.Close()
			if systemSet {
				cleanupErr = sp.Restore(context.WithoutCancel(ctx))
			}
		})
		return cleanupErr
	}
	// S3.4: whatever happens below, put the system proxy back first.
	defer func() {
		if r := recover(); r != nil {
			_ = cleanup()
			a.info("internal error; system proxy settings restored")
			panic(r)
		}
		if cerr := cleanup(); cerr != nil && err == nil {
			err = fail(ExitState, "%v", cerr)
		}
	}()

	if !noSystemProxy {
		warnings, err := sp.Check(ctx)
		if err != nil {
			return fail(ExitState, "reading proxy settings: %v", err)
		}
		for _, w := range warnings {
			a.info("warning: %s", w)
		}
		if err := sp.Enable(ctx, cfg.Port); err != nil {
			return fail(ExitState, "setting the system proxy: %v", err)
		}
		systemSet = true
	}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.Port))
	if noSystemProxy {
		a.info("listening on %s (system proxy untouched); Ctrl-C to stop", addr)
	} else {
		a.info("listening on %s and set as the system proxy; Ctrl-C to stop and restore", addr)
	}
	sigs, stopSignals := a.d.Signals()
	defer stopSignals()
	if a.d.Ready != nil {
		a.d.Ready(addr)
	}
	select {
	case s := <-sigs:
		a.info("received %s, shutting down", s)
	case <-ctx.Done():
	}
	if err := cleanup(); err != nil { // sysproxy logs "system proxy settings restored"
		return fail(ExitState, "%v", err)
	}
	return nil
}

func (a *app) stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop a running wraith and restore the system proxy settings",
		Long: "Stop a running wraith and restore the system proxy settings. Safe to run at any\n" +
			"time: with no instance running it restores settings left by a crash, if any (R4.6).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.stop(cmd.Context()) },
	}
}

func (a *app) stop(ctx context.Context) error {
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()

	stopped := 0
	lock, err := h.Lock()
	var le *home.LockedError
	if errors.As(err, &le) {
		if le.PID <= 0 {
			return fail(ExitRuntime, "a wraith instance is running but its pid is unknown; stop it with Ctrl-C")
		}
		if kerr := a.d.Kill(le.PID, syscall.SIGTERM); kerr != nil && !errors.Is(kerr, syscall.ESRCH) {
			return fail(ExitRuntime, "signalling wraith (pid %d): %v", le.PID, kerr)
		}
		deadline := time.Now().Add(a.d.StopTimeout)
		for {
			if lock, err = h.Lock(); err == nil {
				break
			}
			if !errors.Is(err, home.ErrLocked) || time.Now().After(deadline) {
				return fail(ExitRuntime, "wraith (pid %d) did not stop within %s", le.PID, a.d.StopTimeout)
			}
			time.Sleep(50 * time.Millisecond)
		}
		stopped = le.PID
	} else if err != nil {
		return fail(ExitRuntime, "%v", err)
	}
	defer func() { _ = lock.Unlock() }()

	recovered, err := sysproxy.New(a.d.Runner, h, nil).Recover(ctx)
	if err != nil {
		return fail(ExitState, "%v", err)
	}
	switch {
	case stopped > 0:
		a.info("stopped wraith (pid %d)", stopped)
		if recovered {
			a.info("it had not restored the system proxy; restored now")
		}
	case recovered:
		a.info("restored system proxy settings left by an earlier run")
	default:
		a.info("not running; nothing to restore")
	}
	return nil
}

// setupDecryption loads (or creates) the CA and points the proxy at it. Hosts on the
// config's no_decrypt list stay spliced (R2.5).
func (a *app) setupDecryption(h *home.Home, cfg config.Config, insecure []string, popts *proxy.Options) (*ca.CA, bool, error) {
	c, created, err := ca.Load(h)
	if err != nil {
		return nil, false, fail(ExitState, "CA: %v", err)
	}
	if created {
		a.info("created the wraith CA in %s/%s (fingerprint %s)", h.Path(), ca.Dir, c.Fingerprint())
	}
	if soon, when := c.ExpiresSoon(); soon {
		a.info("warning: the wraith CA expires on %s; run `wraith ca rotate`", when.Format("2006-01-02"))
	}
	hosts := map[string]bool{}
	for _, raw := range insecure {
		host, err := config.NormalizeHostPattern(raw)
		if err != nil || strings.HasPrefix(host, "*.") {
			return nil, false, fail(ExitUsage, "--insecure-upstream %q: give one exact host", raw)
		}
		hosts[host] = true
		a.info("warning: not verifying the upstream certificate of %s (--insecure-upstream)", host)
	}
	macTrusted := false
	if k, err := keychain.New(a.d.Runner); err == nil {
		if trusted, err := k.Trusted(context.Background(), certPath(h)); err == nil && trusted {
			macTrusted = true
			a.info("the Mac trusts the wraith CA: HTTPS from Mac apps in the source is decrypted too")
		} else if err == nil {
			a.info("the Mac does not trust the wraith CA (the default): Mac apps in the source are passed through, not decrypted; see `wraith ca trust --mac`")
		}
	}
	noDecrypt := cfg.NoDecrypt
	popts.Leaf = c.Leaf
	popts.Decrypt = func(host string) bool { return !config.MatchesAny(noDecrypt, host) }
	popts.InsecureUpstream = hosts
	return c, macTrusted, nil
}

// classifier builds the proxy's per-connection decision (R1): identify the process,
// match it against the source, and allow decryption for simulator processes, or for Mac
// processes when the Mac trusts the CA.
func (a *app) classifier(src source.Source, sm *sim.Manager, macTrusted bool) func(context.Context, net.Addr, net.Addr) proxy.Verdict {
	lookup := a.d.Lookup
	if lookup == nil {
		lookup = source.NewResolver(a.d.Runner).Lookup
	}
	names := newSimNames(sm)
	return func(ctx context.Context, client, local net.Addr) proxy.Verdict {
		c, ok1 := client.(*net.TCPAddr)
		l, ok2 := local.(*net.TCPAddr)
		if !ok1 || !ok2 {
			return proxy.Verdict{}
		}
		o, err := lookup(ctx, c.Port, l.Port)
		if err != nil || !src.Matches(o, names.name) {
			return proxy.Verdict{} // R1.3, R1.4: outside the source, untouched and unseen
		}
		label := o.Label()
		if o.Simulator() {
			label = "sim " + names.name(o.SimUDID) + " · " + label
		}
		return proxy.Verdict{InSource: true, Decrypt: o.Simulator() || macTrusted, Label: label}
	}
}

// simNames maps simulator UDIDs to device names for labels and simulator:<name>,
// refreshing from simctl at most every 30 seconds.
type simNames struct {
	sm    *sim.Manager
	mu    sync.Mutex
	names map[string]string
	at    time.Time
}

func newSimNames(sm *sim.Manager) *simNames { return &simNames{sm: sm, names: map[string]string{}} }

func (n *simNames) name(udid string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if name, ok := n.names[udid]; ok {
		return name
	}
	if n.sm != nil && time.Since(n.at) > 30*time.Second {
		n.at = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if devs, err := n.sm.Devices(ctx); err == nil {
			for _, d := range devs {
				n.names[d.UDID] = d.Name
			}
		}
	}
	if name, ok := n.names[udid]; ok {
		return name
	}
	if len(udid) > 8 {
		return udid[:8]
	}
	return udid
}
