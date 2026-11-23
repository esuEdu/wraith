// Package simtest fakes `xcrun simctl` and the simulators' trust stores for tests. Trust
// stores are real (empty) files under Dir, so sim.Manager finds them, while the fake keeps
// their content: which certificate SHA-256s each device trusts.
package simtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Two devices on the iOS 27.2 runtime, plus two that must be ignored.
const (
	Booted   = "F5659D59-1062-4D7F-B1DA-928CFD4D5DF5" // "iPhone 18 Pro Max", booted
	Shutdown = "196410F2-8977-4511-9257-C038A2AC78AA" // "iPhone 17", shut down
)

// TrustStore is the store's path inside a device folder (sim's constant, repeated here
// so the fake does not depend on unexported names).
const TrustStore = "data/private/var/protected/trustd/private/TrustStore.sqlite3"

// Sims is the fake.
type Sims struct {
	Dir    string
	mu     sync.Mutex
	state  map[string]string
	stores map[string]map[string]bool
}

// New returns a fake whose device folders live under dir.
func New(dir string) *Sims {
	return &Sims{
		Dir:    dir,
		state:  map[string]string{Booted: "Booted", Shutdown: "Shutdown"},
		stores: map[string]map[string]bool{},
	}
}

// SetState boots or shuts down a device.
func (s *Sims) SetState(udid, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[udid] = state
}

// Trusts reports whether udid trusts the certificate with SHA-256 hex (upper case).
func (s *Sims) Trusts(udid, hexSum string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stores[udid][hexSum]
}

// AddTrust makes udid trust hexSum, creating its trust store file.
func (s *Sims) AddTrust(udid, hexSum string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addTrust(udid, hexSum)
}

func (s *Sims) addTrust(udid, hexSum string) error {
	p := filepath.Join(s.Dir, udid, TrustStore)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte("sqlite"), 0o600); err != nil {
		return err
	}
	if s.stores[udid] == nil {
		s.stores[udid] = map[string]bool{}
	}
	s.stores[udid][hexSum] = true
	return nil
}

// HexSum returns the upper-case hex SHA-256 of der, as the trust store keys it.
func HexSum(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

type device struct {
	UDID        string `json:"udid"`
	Name        string `json:"name"`
	State       string `json:"state"`
	IsAvailable bool   `json:"isAvailable"`
}

// Run answers one command; use it as execx.Fake.Handler. add-root-cert reads the PEM file
// it is given and trusts the certificate inside it.
func (s *Sims) Run(tool string, args []string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := tool + " " + strings.Join(args, " ")
	switch {
	case line == "xcrun simctl list devices -j":
		return json.Marshal(map[string]map[string][]device{"devices": {
			"com.apple.CoreSimulator.SimRuntime.iOS-27-2": {
				{Booted, "iPhone 18 Pro Max", s.state[Booted], true},
				{Shutdown, "iPhone 17", s.state[Shutdown], true},
				{"not-a-uuid; rm -rf /", "Evil", "Booted", true},
				{"11111111-2222-3333-4444-555555555555", "Unavailable", "Booted", false},
			},
			"com.apple.CoreSimulator.SimRuntime.iOS-27-0": {},
		}})
	case tool == "xcrun" && len(args) == 5 && args[1] == "keychain" && args[3] == "add-root-cert":
		udid := args[2]
		if s.state[udid] != "Booted" {
			return nil, fmt.Errorf("unable to lookup in current state: %s", s.state[udid])
		}
		der, err := pemDER(args[4])
		if err != nil {
			return nil, err
		}
		return nil, s.addTrust(udid, HexSum(der))
	case tool == "sqlite3" && len(args) >= 2:
		store, sql := args[len(args)-2], args[len(args)-1]
		udid, _, _ := strings.Cut(strings.TrimPrefix(store, s.Dir+"/"), "/")
		sum := sql[strings.Index(sql, "'")+1 : strings.LastIndex(sql, "'")]
		switch {
		case strings.HasPrefix(sql, "SELECT"):
			if s.stores[udid][sum] {
				return []byte("1\n"), nil
			}
			return []byte("0\n"), nil
		case strings.HasPrefix(sql, "DELETE") && args[0] != "-readonly":
			delete(s.stores[udid], sum)
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unexpected call %q", line)
}

func pemDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test fake reading the path it was given
	if err != nil {
		return nil, err
	}
	start := strings.Index(string(b), "-----BEGIN CERTIFICATE-----")
	if start < 0 {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	return decodePEM(b[start:])
}
