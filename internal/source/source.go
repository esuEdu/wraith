// Package source answers "which process opened this proxied connection?" and whether it
// belongs to the capture source the user chose (R1). It needs no cgo and no lsof: the
// owning PID comes from the kernel's TCP socket list (sysctl net.inet.tcp.pcblist_n), the
// parent chain and executable paths from kern.proc and kern.procargs2.
package source

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/esuEdu/wraith/internal/execx"
)

// ErrUnknown means the connection's process could not be identified. Such a connection
// is outside every source (R1.4).
var ErrUnknown = errors.New("connection's process not identified")

// Process is one process in an origin's parent chain.
type Process struct {
	PID  int
	PPID int
	Path string   // executable path; the short command name when the path is unreadable
	Args []string // kept for launchd_sim only
}

// Origin describes where a connection came from.
type Origin struct {
	PID   int
	Chain []Process // the connecting process first, then its parents up to launchd

	SimUDID  string // set when the process runs inside a simulator (R1.2)
	Device   string // the address of a physical device on the network (S2.6); no process then
	AppPath  string // outermost .app bundle on the path, if any
	BundleID string
	AppName  string // the bundle's name without .app
}

// Simulator reports whether the origin is a simulator process.
func (o Origin) Simulator() bool { return o.SimUDID != "" }

// Label is a short name for logs: the app, or the executable's name.
func (o Origin) Label() string {
	switch {
	case o.Device != "":
		return "device " + o.Device
	case o.AppName != "":
		return o.AppName
	case len(o.Chain) > 0:
		return filepath.Base(o.Chain[0].Path)
	}
	return "unknown"
}

// Resolver looks origins up. It caches processes and bundles briefly; safe for concurrent use.
type Resolver struct {
	run  execx.Runner
	self int
	now  func() time.Time

	mu      sync.Mutex
	procs   map[int]cachedProc
	bundles map[string]string // app path -> bundle id
	// owner finds a socket's PID; replaced in tests.
	owner func(ctx context.Context, lport, fport int) (int, error)
	// pcb reads the kernel's socket list (ownerFromPCBList); replaced in tests.
	pcb func(lport, fport int) (int, error)
	// scoped is set once the kernel's list proved to hold only wraith's own sockets
	// (macOS 27.2 and later): from then on, lsof answers directly.
	scoped atomic.Bool
}

type cachedProc struct {
	p  Process
	at time.Time
}

const procCacheTTL = 10 * time.Second

// NewResolver returns a Resolver. run executes plutil (bundle ids) and lsof, when the
// kernel's socket list cannot answer.
func NewResolver(run execx.Runner) *Resolver {
	r := &Resolver{
		run: run, self: os.Getpid(), now: time.Now,
		procs: map[int]cachedProc{}, bundles: map[string]string{},
		pcb: ownerFromPCBList,
	}
	r.owner = r.ownerOf
	return r
}

// ownerOf finds the PID owning a client socket: from the kernel's socket list, which is
// fast, else from lsof. Since macOS 27.2 the list holds only the caller's own sockets, so
// a client is never in it; the first time lsof finds one the list missed, the list is
// skipped from then on.
func (r *Resolver) ownerOf(ctx context.Context, lport, fport int) (int, error) {
	if !r.scoped.Load() {
		pid, err := r.pcb(lport, fport)
		switch {
		case err == nil:
			return pid, nil
		case errors.Is(err, ErrUnknown): // not in the list: a scoped list, or a socket already gone
			pid, err := ownerFromLsof(ctx, r.run, lport, fport, r.self)
			if err == nil {
				r.scoped.Store(true)
			}
			return pid, err
		case !errors.Is(err, errLayout):
			return 0, err
		}
	}
	return ownerFromLsof(ctx, r.run, lport, fport, r.self)
}

// Lookup identifies the process behind a client connection to the proxy: clientPort is
// the client's local port (the remote port of the accepted socket), proxyPort the port it
// connected to. It returns ErrUnknown when no process is found (R1.4).
func (r *Resolver) Lookup(ctx context.Context, clientPort, proxyPort int) (Origin, error) {
	pid, err := r.owner(ctx, clientPort, proxyPort)
	if err != nil {
		return Origin{}, err
	}
	if pid == r.self {
		return Origin{}, ErrUnknown // our own accepted socket, never a client
	}
	o := Origin{PID: pid}
	for p := pid; p > 1 && len(o.Chain) < 32; {
		proc, err := r.process(p)
		if err != nil {
			if len(o.Chain) == 0 {
				return Origin{}, ErrUnknown // gone already
			}
			break
		}
		o.Chain = append(o.Chain, proc)
		if filepath.Base(proc.Path) == "launchd_sim" {
			o.SimUDID = simUDID(proc.Args)
			break // its parents are the Mac's launchd
		}
		p = proc.PPID
	}
	// The app is taken from the connecting process's own path only: a helper inside an app
	// bundle belongs to it, but a command-line tool started from a terminal app does not.
	if app := outermostApp(o.Chain[0].Path); app != "" {
		o.AppPath = app
		o.AppName = strings.TrimSuffix(filepath.Base(app), ".app")
		o.BundleID = r.bundleID(ctx, app)
	}
	return o, nil
}

// process reads one process's parent and executable, cached for a few seconds.
func (r *Resolver) process(pid int) (Process, error) {
	r.mu.Lock()
	if c, ok := r.procs[pid]; ok && r.now().Sub(c.at) < procCacheTTL {
		r.mu.Unlock()
		return c.p, nil
	}
	r.mu.Unlock()

	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return Process{}, err
	}
	if int(kp.Proc.P_pid) != pid {
		return Process{}, ErrUnknown // process gone: the kernel returned an empty record
	}
	p := Process{PID: pid, PPID: int(kp.Eproc.Ppid)}
	p.Path, p.Args = procArgs(pid)
	if p.Path == "" {
		p.Path = unix.ByteSliceToString(kp.Proc.P_comm[:])
	}
	if filepath.Base(p.Path) != "launchd_sim" {
		p.Args = nil
	}

	r.mu.Lock()
	if len(r.procs) > 4096 {
		r.procs = map[int]cachedProc{}
	}
	r.procs[pid] = cachedProc{p: p, at: r.now()}
	r.mu.Unlock()
	return p, nil
}

// procArgs reads kern.procargs2: argc, the executable path, padding, then argv. It fails
// (empty result) for other users' processes, which is fine: simulators run as the user.
func procArgs(pid int) (string, []string) {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(b) < 4 {
		return "", nil
	}
	argc := int(binary.LittleEndian.Uint32(b))
	rest := b[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return "", nil
	}
	path := string(rest[:i])
	rest = bytes.TrimLeft(rest[i:], "\x00")
	var args []string
	for len(args) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			j = len(rest)
		}
		args = append(args, string(rest[:j]))
		rest = rest[min(j+1, len(rest)):]
	}
	return path, args
}

var udidInPath = regexp.MustCompile(`/Devices/([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})/`)

// simUDID finds the device UDID in launchd_sim's arguments
// (".../CoreSimulator/Devices/<UDID>/data/var/run/launchd_bootstrap.plist").
func simUDID(args []string) string {
	for _, a := range args {
		if m := udidInPath.FindStringSubmatch(a); m != nil {
			return strings.ToUpper(m[1])
		}
	}
	return "unknown"
}

// outermostApp returns the first ".app" directory on path, so a helper inside a nested
// bundle (Chrome.app/.../Google Chrome Helper.app) belongs to the outer app.
func outermostApp(path string) string {
	i := strings.Index(path, ".app/")
	if i < 0 {
		if strings.HasSuffix(path, ".app") {
			return path
		}
		return ""
	}
	return path[:i+len(".app")]
}

// bundleID reads CFBundleIdentifier from a bundle's Info.plist (macOS layout first, then
// the flat iOS layout), cached per bundle.
func (r *Resolver) bundleID(ctx context.Context, app string) string {
	r.mu.Lock()
	if id, ok := r.bundles[app]; ok {
		r.mu.Unlock()
		return id
	}
	r.mu.Unlock()
	id := ""
	for _, plist := range []string{filepath.Join(app, "Contents", "Info.plist"), filepath.Join(app, "Info.plist")} {
		if _, err := os.Stat(plist); err != nil {
			continue
		}
		out, err := r.run.Run(ctx, "plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", plist)
		if err == nil {
			id = strings.TrimSpace(string(out))
			break
		}
	}
	r.mu.Lock()
	r.bundles[app] = id
	r.mu.Unlock()
	return id
}
