// Package sysproxy points the Mac's HTTP and HTTPS proxy at wraith and puts the user's
// settings back afterwards. Every enabled network service's settings are saved to
// state.json before anything changes (R4.1) and restored on exit (R4.2); a state file
// found at start means wraith crashed, and it is restored first (R4.3).
package sysproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
)

// StateFile holds the saved settings while wraith has the system proxy set.
const StateFile = "state.json"

const stateVersion = 1

// Setting is one proxy setting (web or secure web) of one network service.
type Setting struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
	Auth    bool   `json:"auth"`
}

// Service is the saved state of one network service.
type Service struct {
	Name   string  `json:"name"`
	Web    Setting `json:"web"`
	Secure Setting `json:"secure"`
}

// State is the content of state.json.
type State struct {
	Version  int       `json:"version"`
	PID      int       `json:"pid"`
	SavedAt  time.Time `json:"saved_at"`
	Port     int       `json:"port"`
	Services []Service `json:"services"`
}

// Manager sets and restores the system proxy through networksetup.
type Manager struct {
	run  execx.Runner
	home *home.Home
	logf func(format string, args ...any)
	now  func() time.Time
}

// New returns a Manager. logf may be nil.
func New(run execx.Runner, h *home.Home, logf func(string, ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Manager{run: run, home: h, logf: logf, now: time.Now}
}

// ErrAlreadySet means state.json exists: wraith already changed the settings, or crashed
// after doing so. Call Restore (or Recover) first.
var ErrAlreadySet = errors.New("system proxy already set by wraith (state.json exists); restore first")

// ErrAuthenticatedProxy means a service uses a proxy with a password. networksetup cannot
// read the password back, so wraith would lose it on restore; it refuses instead.
var ErrAuthenticatedProxy = errors.New("a network service uses an authenticated proxy; wraith will not change it")

// Services returns the enabled network services, in networksetup's order.
func (m *Manager) Services(ctx context.Context) ([]string, error) {
	all, err := m.allServices(ctx)
	if err != nil {
		return nil, err
	}
	var enabled []string
	for _, s := range all {
		if !s.disabled {
			enabled = append(enabled, s.name)
		}
	}
	return enabled, nil
}

type serviceEntry struct {
	name     string
	disabled bool
}

func (m *Manager) allServices(ctx context.Context) ([]serviceEntry, error) {
	out, err := m.run.Run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return parseServices(out), nil
}

// parseServices reads -listallnetworkservices: a header line, then one service per line,
// disabled ones starting with "*".
func parseServices(out []byte) []serviceEntry {
	var list []serviceEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if first {
			first = false
			if strings.Contains(line, "asterisk") {
				continue
			}
		}
		if line == "" {
			continue
		}
		if name, ok := strings.CutPrefix(line, "*"); ok {
			list = append(list, serviceEntry{name: name, disabled: true})
			continue
		}
		list = append(list, serviceEntry{name: line})
	}
	return list
}

// Snapshot reads the web and secure web proxy settings of each service. networksetup
// takes a few tens of milliseconds a call, so the reads run side by side.
func (m *Manager) Snapshot(ctx context.Context, services []string) ([]Service, error) {
	snap := make([]Service, len(services))
	for i, name := range services {
		snap[i].Name = name
	}
	err := each(2*len(services), func(i int) error {
		s := &snap[i/2]
		var err error
		if i%2 == 0 {
			s.Web, err = m.get(ctx, "-getwebproxy", s.Name)
		} else {
			s.Secure, err = m.get(ctx, "-getsecurewebproxy", s.Name)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// read lists the enabled services and reads their settings.
func (m *Manager) read(ctx context.Context) ([]string, []Service, error) {
	services, err := m.Services(ctx)
	if err != nil {
		return nil, nil, err
	}
	snap, err := m.Snapshot(ctx, services)
	return services, snap, err
}

// each runs f(0) to f(n-1) at once and returns the error of the lowest i that failed.
func each(n int, f func(i int) error) error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = f(i) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) get(ctx context.Context, verb, service string) (Setting, error) {
	out, err := m.run.Run(ctx, "networksetup", verb, service)
	if err != nil {
		return Setting{}, err
	}
	return parseSetting(out)
}

// parseSetting reads -getwebproxy / -getsecurewebproxy output.
func parseSetting(out []byte) (Setting, error) {
	var s Setting
	seen := 0
	for line := range strings.SplitSeq(string(out), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "Enabled":
			s.Enabled = val == "Yes"
			seen++
		case "Server":
			s.Server = val
			seen++
		case "Port":
			p, err := strconv.Atoi(val)
			if err != nil {
				return s, fmt.Errorf("bad proxy port %q", val)
			}
			s.Port = p
			seen++
		case "Authenticated Proxy Enabled":
			s.Auth = val == "1"
		}
	}
	if seen < 3 {
		return s, fmt.Errorf("unexpected networksetup output %q", strings.TrimSpace(string(out)))
	}
	return s, nil
}

// Enable saves every enabled service's settings to state.json, then points their web and
// secure web proxies at 127.0.0.1:port. If any change fails, the ones already made are
// rolled back and state.json is removed.
func (m *Manager) Enable(ctx context.Context, port int) error {
	if err := m.canEnable(port); err != nil {
		return err
	}
	services, snap, err := m.read(ctx)
	if err != nil {
		return err
	}
	return m.enable(ctx, port, services, snap)
}

// canEnable refuses a bad port, and a state file: wraith has the proxy set already.
func (m *Manager) canEnable(port int) error {
	if err := execx.CheckPort(port); err != nil {
		return err
	}
	if _, err := m.home.ReadFile(StateFile); err == nil {
		return ErrAlreadySet
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (m *Manager) enable(ctx context.Context, port int, services []string, snap []Service) error {
	if len(services) == 0 {
		return errors.New("no enabled network service to set a proxy on")
	}
	for _, s := range snap {
		if s.Web.Auth || s.Secure.Auth {
			return fmt.Errorf("%w: %s", ErrAuthenticatedProxy, s.Name)
		}
	}
	st := State{Version: stateVersion, PID: os.Getpid(), SavedAt: m.now().UTC(), Port: port, Services: snap}
	if err := m.writeState(st); err != nil { // R4.1: saved before anything changes
		return err
	}

	// -setwebproxy also turns the proxy on (networksetup(8): "Turns proxy on."), so no
	// -setwebproxystate follows: two commands a service instead of four.
	p := strconv.Itoa(port)
	for _, s := range snap {
		for _, cmd := range [][]string{
			{"-setwebproxy", s.Name, "127.0.0.1", p},
			{"-setsecurewebproxy", s.Name, "127.0.0.1", p},
		} {
			if _, err := m.run.Run(ctx, "networksetup", cmd...); err != nil {
				if rerr := m.Restore(context.WithoutCancel(ctx)); rerr != nil {
					return fmt.Errorf("%w; rolling back also failed: %w", err, rerr)
				}
				return err
			}
		}
	}
	m.logf("system proxy set to 127.0.0.1:%d on %s", port, strings.Join(services, ", "))
	return nil
}

// Restore puts back the settings saved in state.json and removes it. Without a state file
// it runs no command and returns nil, so `wraith stop` is safe to run any time (R4.6).
// A saved service that no longer exists is skipped with a log line. If a command fails,
// state.json is kept so a later `wraith stop` can retry.
func (m *Manager) Restore(ctx context.Context) error {
	_, err := m.restore(ctx)
	return err
}

// Recover restores a state file left by a crashed instance (R4.3). Call it after taking
// the instance lock, so any state file found is a leftover. It reports whether it found
// one, so the caller can warn.
func (m *Manager) Recover(ctx context.Context) (recovered bool, err error) {
	return m.restore(ctx)
}

func (m *Manager) restore(ctx context.Context) (bool, error) {
	b, err := m.home.ReadFile(StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return false, fmt.Errorf("%s is unreadable (%w); fix or delete it, then check System Settings > Network > Proxies", StateFile, err)
	}
	if st.Version != stateVersion {
		return false, fmt.Errorf("%s has version %d, this wraith understands %d", StateFile, st.Version, stateVersion)
	}

	all, err := m.allServices(ctx)
	if err != nil {
		return false, err
	}
	known := make([]string, 0, len(all))
	for _, s := range all {
		known = append(known, s.name)
	}

	var errs []error
	for _, s := range st.Services {
		if err := execx.CheckService(s.Name, known); err != nil {
			m.logf("not restoring %q: %v", s.Name, err)
			continue
		}
		errs = append(errs,
			m.put(ctx, s.Name, "-setwebproxy", "-setwebproxystate", s.Web),
			m.put(ctx, s.Name, "-setsecurewebproxy", "-setsecurewebproxystate", s.Secure))
	}
	if err := errors.Join(errs...); err != nil {
		return true, fmt.Errorf("restoring proxy settings (state.json kept, run `wraith stop` to retry): %w", err)
	}
	if err := m.home.Remove(StateFile); err != nil {
		return true, err
	}
	m.logf("system proxy settings restored")
	return true, nil
}

// put restores one setting: server and port first, then off if it was off. A setting that
// never had a server is cleared with `-setwebproxy <service> "" 0` (checked on macOS: it
// empties both fields, and switches the proxy on, so the state command after it matters).
// Setting the server turns the proxy on, so one that was on needs nothing more.
func (m *Manager) put(ctx context.Context, service, setVerb, stateVerb string, s Setting) error {
	server, port := s.Server, "0"
	if server != "" || s.Port != 0 {
		if err := execx.CheckPort(s.Port); err != nil {
			return err
		}
		port = strconv.Itoa(s.Port)
	}
	if _, err := m.run.Run(ctx, "networksetup", setVerb, service, server, port); err != nil {
		return err
	}
	if s.Enabled {
		return nil
	}
	_, err := m.run.Run(ctx, "networksetup", stateVerb, service, "off")
	return err
}

func (m *Manager) writeState(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return m.home.WriteFile(StateFile, append(b, '\n'), 0o600)
}
