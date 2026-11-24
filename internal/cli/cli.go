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
	"sync/atomic"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/ca"
	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/control"
	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/export"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/keychain"
	"github.com/esuEdu/wraith/internal/proxy"
	"github.com/esuEdu/wraith/internal/route"
	"github.com/esuEdu/wraith/internal/sim"
	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/store"
	"github.com/esuEdu/wraith/internal/sysproxy"
	"github.com/esuEdu/wraith/internal/tui"
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
	// IsTerminal reports whether stdout is a terminal (the live view); nil checks os.Stdout.
	IsTerminal func() bool
	// OnActions, if set, receives the running instance's live actions (tests use it).
	OnActions func(tui.Actions)
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
	if d.IsTerminal == nil {
		d.IsTerminal = func() bool { return isTerminal(os.Stdout) }
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

type app struct {
	d  Deps
	ui atomic.Pointer[tea.Program] // the live view, while it runs
}

// notice reports something that happens while wraith runs: in the live view's status line
// when it is on screen, on stderr otherwise.
func (a *app) notice(format string, args ...any) {
	if p := a.ui.Load(); p != nil {
		p.Send(tui.NoticeMsg(fmt.Sprintf(format, args...)))
		return
	}
	a.info(format, args...)
}

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
	root.AddCommand(a.startCmd(), a.stopCmd(), a.versionCmd(), a.caCmd(), a.bypassCmd(), a.doctorCmd(), a.exportCmd())
	for _, p := range []struct{ name, short, milestone string }{} {
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
		jsonLog       bool
		noDecrypt     bool
		insecure      []string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Set the system proxy and start the proxy",
		Long: "Set the system proxy, start the proxy and show the live view. Traffic from the\n" +
			"capture source is decrypted and shown; everything else passes through untouched.\n" +
			"With --log, or when stdout is not a terminal, it prints one line per request.\n" +
			"Ctrl-C (or q in the live view) stops it and restores the system proxy.",
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
			if len(insecure) > 0 && noDecrypt {
				return fail(ExitUsage, "--insecure-upstream does not apply with --no-decrypt")
			}
			return a.start(cmd.Context(), o, startOpts{noSystemProxy: noSystemProxy, decrypt: !noDecrypt, insecure: insecure, logMode: logMode, jsonLog: jsonLog})
		},
	}
	f := cmd.Flags()
	f.IntVar(&port, "port", 9090, "proxy port on 127.0.0.1 and ::1")
	f.StringVar(&source, "source", "simulator", "capture source: all, simulator[:udid|name], app:<name|bundle-id>, pid:<pid>")
	f.StringVar(&iface, "iface", "auto", "physical interface for bypassed hosts: auto, or en0, en1, ...")
	f.IntVar(&maxFlows, "max-flows", 5000, "flows kept in memory")
	f.Int64Var(&maxBody, "max-body", 1<<20, "bodies above this many bytes are truncated")
	f.BoolVar(&noSystemProxy, "no-system-proxy", false, "listen only; leave the system proxy settings alone")
	f.BoolVar(&logMode, "log", false, "print one line per request instead of the live view (the default when stdout is not a terminal)")
	f.BoolVar(&jsonLog, "json", false, "with --log: one JSON object per line")
	f.BoolVar(&noDecrypt, "no-decrypt", false, "pass HTTPS through without decrypting it")
	f.StringArrayVar(&insecure, "insecure-upstream", nil, "do not verify this host's certificate, e.g. a local dev server (repeatable)")
	return cmd
}

type startOpts struct {
	logMode       bool
	jsonLog       bool
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

	// Catch Ctrl-C and SIGTERM before anything changes on the Mac: a signal during
	// start-up is delivered once start-up is done, and the shutdown below restores the
	// system proxy. Without this, Go's default action would exit with it still set.
	sigs, stopSignals := a.d.Signals()
	defer stopSignals()

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
	// Flows go to the store (memory only, R5.2); the proxy's own notices go to stderr.
	flows := store.New(cfg.Capture.MaxFlows, cfg.Capture.MaxBodyBytes)
	popts := proxy.Options{Store: flows, Logf: a.notice}
	sm, smErr := a.simManager()
	macTrusted := false
	var caFP *[32]byte
	stopSimWatch := func() {}
	if so.decrypt {
		c, trusted, err := a.setupDecryption(h, cfg, so.insecure, &popts)
		macTrusted = trusted
		if c != nil {
			fp := c.SHA256()
			caFP = &fp
		}
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
				sm.Watch(watchCtx, a.d.SimPoll, certPath(h), c.SHA256(), a.notice)
			}()
			stopSimWatch = func() { cancel(); <-watchDone }
		}
	}
	src, err := source.Parse(cfg.Source)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}

	// R3.3: every connection is dialed through the router, whatever its source.
	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	router := route.New(rctx, a.d.Runner, cfg.Bypass, cfg.Interface)
	rcancel()
	live := newLiveState(h, cfg, src, flows, router)
	if smErr == nil {
		live.sims = sm
	}
	live.caFP, live.macTrusted = caFP, macTrusted
	if popts.Leaf != nil {
		popts.Decrypt = live.decrypt
	}
	popts.Classify = a.classifier(&live.src, sm, macTrusted)
	popts.Dialer = router
	popts.Route = func(host string) string { r, _ := router.Route(host); return r }
	if len(cfg.Bypass) > 0 {
		if ifi, err := router.Iface(); err != nil {
			a.info("warning: bypass: %v; the %d bypassed host(s) will fail, never use the VPN", err, len(cfg.Bypass))
		} else {
			a.info("bypassing %d host(s) on %s, IPv6 first", len(cfg.Bypass), ifi.Name)
		}
	}
	a.info("capturing %s; everything else passes through untouched", src)
	srv := proxy.New(popts)
	useTUI := !so.logMode && !so.jsonLog && a.d.IsTerminal()
	printed, stopPrinting := (<-chan struct{})(closedChan()), func() {}
	if !useTUI {
		printed, stopPrinting = a.printFlows(flows, so.jsonLog, export.NewRedactor(cfg.Export.RedactHeaders))
	}
	ctl, err := control.Listen(h, flows, cfg.Export.RedactHeaders)
	if err != nil {
		a.info("warning: `wraith export` will not reach this instance: %v", err)
	}
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
			if ctl != nil {
				_ = ctl.Close()
			}
			stopPrinting()
			<-printed
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
	actions := liveActions{live}
	if a.d.OnActions != nil {
		a.d.OnActions(actions)
	}
	var ui *tea.Program
	uiDone := make(chan struct{})
	if useTUI {
		ui = a.runTUI(ctx, actions, addr, flows, cfg.Theme, uiDone)
	}
	if a.d.Ready != nil {
		a.d.Ready(addr)
	}
	select {
	case s := <-sigs:
		if ui != nil {
			ui.Quit()
			<-uiDone
		}
		a.info("received %s, shutting down", s)
	case <-uiDone:
		a.info("shutting down")
	case <-ctx.Done():
		if ui != nil {
			ui.Quit()
			<-uiDone
		}
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
			"time: with no instance running it restores settings left by a crash, if any.",
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
func (a *app) classifier(cur *atomic.Pointer[source.Source], sm *sim.Manager, macTrusted bool) func(context.Context, net.Addr, net.Addr) proxy.Verdict {
	src := *cur.Load()
	lookup := a.d.Lookup
	if lookup == nil {
		lookup = source.NewResolver(a.d.Runner).Lookup
	}
	names := newSimNames(sm)
	if src.Kind == "simulator" && src.Arg != "" {
		names.load() // simulator:<name> needs the names before the first connection
	} else {
		names.mu.Lock()
		names.refreshing, names.lastTry = true, time.Now()
		names.mu.Unlock()
		go names.load()
	}
	return func(ctx context.Context, client, local net.Addr) proxy.Verdict {
		c, ok1 := client.(*net.TCPAddr)
		l, ok2 := local.(*net.TCPAddr)
		if !ok1 || !ok2 {
			return proxy.Verdict{}
		}
		o, err := lookup(ctx, c.Port, l.Port)
		if err != nil || !cur.Load().Matches(o, names.name) { // R1.5: the source as of now
			return proxy.Verdict{} // R1.3, R1.4: outside the source, untouched and unseen
		}
		label := o.Label()
		if o.Simulator() {
			label = "sim " + names.name(o.SimUDID) + " · " + label
		}
		return proxy.Verdict{InSource: true, Decrypt: o.Simulator() || macTrusted, Label: label}
	}
}

// simNames maps simulator UDIDs to device names for labels and simulator:<name>. It
// refreshes from simctl in the background, so a slow simctl (a simulator still booting)
// never holds up a connection; until a name is known the label shows the UDID's start.
type simNames struct {
	sm         *sim.Manager
	mu         sync.Mutex
	names      map[string]string
	lastTry    time.Time
	refreshing bool
}

func newSimNames(sm *sim.Manager) *simNames { return &simNames{sm: sm, names: map[string]string{}} }

// load refreshes the names now, waiting for simctl (up to 15 s).
func (n *simNames) load() {
	if n.sm == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	devs, err := n.sm.Devices(ctx)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.refreshing = false
	if err == nil {
		for _, d := range devs {
			n.names[d.UDID] = d.Name
		}
	}
}

func (n *simNames) name(udid string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if name, ok := n.names[udid]; ok {
		return name
	}
	if n.sm != nil && !n.refreshing && time.Since(n.lastTry) > 2*time.Second {
		n.refreshing, n.lastTry = true, time.Now()
		go n.load()
	}
	if len(udid) > 8 {
		return udid[:8]
	}
	return udid
}

// printFlows prints each flow added to the store as a log line (or JSON object), until
// stop is called; done closes once the last line is out.
func (a *app) printFlows(flows *store.Store, asJSON bool, r export.Redactor) (done <-chan struct{}, stop func()) {
	ch, stop := flows.Subscribe(4096)
	d := make(chan struct{})
	go func() {
		defer close(d)
		for f := range ch {
			f.URL = r.URL(f.URL) // tokens in query strings stay out of scrollback and log files
			line := formatFlow(f)
			if asJSON {
				line = formatFlowJSON(f)
			}
			_, _ = fmt.Fprintln(a.d.Stdout, line)
		}
	}()
	return d, stop
}

// runTUI starts the live view; done closes when it exits (q, ctrl+c, or Quit).
func (a *app) runTUI(ctx context.Context, actions tui.Actions, addr string, flows *store.Store, theme string, done chan struct{}) *tea.Program {
	ch, stopSub := flows.Subscribe(4096) // before the snapshot: the model drops repeats
	model := tui.New(actions, addr, flows.Flows())
	if err := model.SetTheme(theme); err != nil {
		a.info("warning: %v; using %s", err, tui.DefaultTheme)
	}
	opts := []tea.ProgramOption{tea.WithContext(ctx), tea.WithInput(a.d.Stdin), tea.WithOutput(a.d.Stdout)}
	if f, ok := a.d.Stdout.(*os.File); !ok || !isTerminal(f) {
		opts = append(opts, tea.WithWindowSize(120, 30)) // no terminal to ask (tests)
	}
	p := tea.NewProgram(model, opts...)
	a.ui.Store(p)
	go func() {
		for f := range ch {
			p.Send(tui.FlowMsg(f))
		}
	}()
	go func() {
		defer close(done)
		_, err := p.Run()
		a.ui.Store(nil)
		if err != nil && !errors.Is(err, tea.ErrProgramKilled) {
			a.info("live view: %v", err)
		}
		stopSub()
	}()
	return p
}

func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
