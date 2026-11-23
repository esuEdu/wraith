// Package sim puts the wraith CA into iOS simulators and takes it out again. By default
// the CA goes into simulators only, never the Mac (R2.2). Installing uses
// `xcrun simctl keychain <udid> add-root-cert`, which needs a booted device. Checking and
// removing read and edit the device's trust store directly, so they work on shut-down
// devices too, and removal deletes only wraith's certificate, never others (S4.5).
package sim

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
)

// trustStore is the trust settings database inside a device's data directory (checked
// on the iOS 27.2 runtime: table tsettings, keyed by the certificate's SHA-256).
const trustStore = "data/private/var/protected/trustd/private/TrustStore.sqlite3"

// Device is one simulator.
type Device struct {
	UDID    string
	Name    string
	State   string
	Runtime string
}

// Booted reports whether the device is running.
func (d Device) Booted() bool { return d.State == "Booted" }

func (d Device) String() string { return fmt.Sprintf("%s (%s)", d.Name, d.UDID) }

// Manager drives simctl and the trust stores.
type Manager struct {
	run        execx.Runner
	devicesDir string
}

// New returns a Manager. devicesDir is CoreSimulator's device folder; "" means
// ~/Library/Developer/CoreSimulator/Devices.
func New(run execx.Runner, devicesDir string) (*Manager, error) {
	if devicesDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		devicesDir = filepath.Join(h, "Library", "Developer", "CoreSimulator", "Devices")
	}
	return &Manager{run: run, devicesDir: devicesDir}, nil
}

// Devices lists the available simulators. Entries whose UDID is not a UUID are skipped,
// so nothing odd ever reaches a tool argument (S4.3).
func (m *Manager) Devices(ctx context.Context) ([]Device, error) {
	out, err := m.run.Run(ctx, "xcrun", "simctl", "list", "devices", "-j")
	if err != nil {
		return nil, err
	}
	var list struct {
		Devices map[string][]struct {
			UDID        string `json:"udid"`
			Name        string `json:"name"`
			State       string `json:"state"`
			IsAvailable bool   `json:"isAvailable"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("simctl list: %w", err)
	}
	var devs []Device
	for runtime, ds := range list.Devices {
		rt := runtime[strings.LastIndex(runtime, ".")+1:]
		for _, d := range ds {
			if !d.IsAvailable || execx.CheckUDID(d.UDID) != nil {
				continue
			}
			devs = append(devs, Device{UDID: d.UDID, Name: d.Name, State: d.State, Runtime: rt})
		}
	}
	return devs, nil
}

// BootedDevices lists the running simulators.
func (m *Manager) BootedDevices(ctx context.Context) ([]Device, error) {
	all, err := m.Devices(ctx)
	if err != nil {
		return nil, err
	}
	var booted []Device
	for _, d := range all {
		if d.Booted() {
			booted = append(booted, d)
		}
	}
	return booted, nil
}

// ErrNotBooted means the device must be running for the operation.
var ErrNotBooted = errors.New("simulator is not booted")

// Install adds the CA certificate at certPath (an absolute path) to d's trusted roots,
// unless it is already there. It reports whether it added it.
func (m *Manager) Install(ctx context.Context, d Device, certPath string, fp [32]byte) (bool, error) {
	if err := execx.CheckUDID(d.UDID); err != nil {
		return false, err
	}
	if !filepath.IsAbs(certPath) {
		return false, fmt.Errorf("certificate path %q is not absolute", certPath)
	}
	if !d.Booted() {
		return false, fmt.Errorf("%s: %w", d, ErrNotBooted)
	}
	if ok, err := m.Installed(ctx, d, fp); err != nil || ok {
		return false, err
	}
	if _, err := m.run.Run(ctx, "xcrun", "simctl", "keychain", d.UDID, "add-root-cert", certPath); err != nil {
		return false, err
	}
	return true, nil
}

// Installed reports whether d trusts the certificate with SHA-256 fp.
func (m *Manager) Installed(ctx context.Context, d Device, fp [32]byte) (bool, error) {
	store, err := m.store(d)
	if err != nil || store == "" {
		return false, err
	}
	out, err := m.run.Run(ctx, "sqlite3", "-readonly", store,
		"SELECT count(*) FROM tsettings WHERE hex(sha256) = '"+hexFP(fp)+"';")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "0", nil
}

// Remove deletes the certificate with SHA-256 fp from d's trust store, booted or not,
// leaving every other certificate in place. It reports whether there was one to remove.
// A booted device may keep trusting it until it restarts.
func (m *Manager) Remove(ctx context.Context, d Device, fp [32]byte) (bool, error) {
	ok, err := m.Installed(ctx, d, fp)
	if err != nil || !ok {
		return false, err
	}
	store, err := m.store(d)
	if err != nil {
		return false, err
	}
	_, err = m.run.Run(ctx, "sqlite3", store, "DELETE FROM tsettings WHERE hex(sha256) = '"+hexFP(fp)+"';")
	return err == nil, err
}

// store returns the path of d's trust store, or "" if it has none yet (nothing was ever
// added to that device).
func (m *Manager) store(d Device) (string, error) {
	if err := execx.CheckUDID(d.UDID); err != nil {
		return "", err
	}
	p := filepath.Join(m.devicesDir, d.UDID, trustStore)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	return p, nil
}

func hexFP(fp [32]byte) string { return strings.ToUpper(hex.EncodeToString(fp[:])) }

// Watch polls the booted simulators every interval until ctx ends and installs the CA
// into each device the first time it is seen booted, including devices booted after
// wraith started (R1.6). Errors are logged and retried on the next poll.
func (m *Manager) Watch(ctx context.Context, interval time.Duration, certPath string, fp [32]byte, logf func(string, ...any)) {
	done := map[string]bool{}
	lastErr := ""
	for {
		booted, err := m.BootedDevices(ctx)
		if err != nil && ctx.Err() == nil && err.Error() != lastErr {
			logf("simulators: %v", err) // once per distinct error, not every poll
			lastErr = err.Error()
		} else if err == nil {
			lastErr = ""
		}
		running := map[string]bool{}
		for _, d := range booted {
			running[d.UDID] = true
			if done[d.UDID] {
				continue
			}
			added, err := m.Install(ctx, d, certPath, fp)
			switch {
			case err != nil:
				if ctx.Err() == nil {
					logf("simulator %s: installing the CA failed: %v", d, err)
				}
			case added:
				logf("simulator %s: installed the wraith CA", d)
				done[d.UDID] = true
			default:
				done[d.UDID] = true
			}
		}
		for udid := range done {
			if !running[udid] {
				delete(done, udid) // shut down: check again when it boots
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
