package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/export"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/route"
	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/store"
)

// liveState is what a running wraith can change without restarting: the capture source,
// the bypass list and the no-decrypt list. Changes apply to new connections; list
// changes are also written to config.yaml.
type liveState struct {
	h      *home.Home
	flows  *store.Store
	router *route.Router
	redact []string
	dir    string // where e exports HAR files

	src       atomic.Pointer[source.Source]
	noDecrypt atomic.Pointer[[]string]
	bypass    atomic.Pointer[[]string]
	mu        sync.Mutex // one config edit at a time
}

func newLiveState(h *home.Home, cfg config.Config, src source.Source, flows *store.Store, router *route.Router) *liveState {
	l := &liveState{h: h, flows: flows, router: router, redact: cfg.Export.RedactHeaders}
	l.src.Store(&src)
	nd, bp := slices.Clone(cfg.NoDecrypt), slices.Clone(cfg.Bypass)
	l.noDecrypt.Store(&nd)
	l.bypass.Store(&bp)
	if wd, err := os.Getwd(); err == nil {
		l.dir = wd
	}
	return l
}

// decrypt is the proxy's Decrypt function: hosts on no_decrypt stay spliced (R2.5).
func (l *liveState) decrypt(host string) bool {
	return !config.MatchesAny(*l.noDecrypt.Load(), host)
}

// liveActions implements tui.Actions on a liveState.
type liveActions struct{ *liveState }

func (l liveActions) Source() string { return l.src.Load().String() }

// SetSource changes the source for connections opened from now on (R1.5).
func (l liveActions) SetSource(s string) error {
	src, err := source.Parse(s)
	if err != nil {
		return err
	}
	l.src.Store(&src)
	return nil
}

func (l liveActions) Bypass(host string) error {
	return l.addPattern(host, &l.bypass, config.WriteBypass, func(list []string) {
		if l.router != nil {
			l.router.SetRules(list)
		}
	})
}

func (l liveActions) NoDecrypt(host string) error {
	return l.addPattern(host, &l.noDecrypt, config.WriteNoDecrypt, nil)
}

func (l liveActions) addPattern(raw string, list *atomic.Pointer[[]string], write func(*home.Home, []string) error, apply func([]string)) error {
	p, err := config.NormalizeHostPattern(raw)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := *list.Load()
	if slices.Contains(cur, p) {
		return fmt.Errorf("already on the list")
	}
	next := append(slices.Clone(cur), p)
	if err := write(l.h, next); err != nil {
		return err
	}
	list.Store(&next)
	if apply != nil {
		apply(next)
	}
	return nil
}

func (l liveActions) Curl(f store.Flow) string {
	return export.Curl(f, export.NewRedactor(l.redact))
}

// ExportHAR writes every stored flow, redacted, to wraith-<time>.har in the directory
// wraith was started from.
func (l liveActions) ExportHAR() (string, error) {
	b, err := export.HAR(l.flows.Flows(), export.NewRedactor(l.redact))
	if err != nil {
		return "", err
	}
	p := filepath.Join(l.dir, "wraith-"+time.Now().Format("20060102-150405")+".har")
	return p, export.WriteFile(p, b, false)
}

func (l liveActions) Clear() { l.flows.Clear() }

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}
