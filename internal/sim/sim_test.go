package sim_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/sim"
	"github.com/esuEdu/wraith/internal/sim/simtest"
)

func setup(t *testing.T) (*sim.Manager, *simtest.Sims, *execx.Fake) {
	t.Helper()
	f := simtest.New(t.TempDir())
	fake := execx.NewFake()
	fake.Handler = f.Run
	m, err := sim.New(fake, f.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return m, f, fake
}

// testCert writes a self-signed CA certificate and returns its path and SHA-256.
func testCert(t *testing.T) (string, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, sha256.Sum256(der)
}

func hexOf(fp [32]byte) string { return strings.ToUpper(fmt.Sprintf("%x", fp[:])) }

func TestS4_3_DevicesSkipsBadUDIDsAndUnavailableDevices(t *testing.T) {
	m, _, _ := setup(t)
	devs, err := m.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var udids []string
	for _, d := range devs {
		udids = append(udids, d.UDID)
		if d.Runtime != "iOS-27-2" {
			t.Errorf("%s runtime %q", d.UDID, d.Runtime)
		}
	}
	slices.Sort(udids)
	if want := []string{simtest.Shutdown, simtest.Booted}; !slices.Equal(udids, want) {
		t.Fatalf("devices %v, want %v", udids, want)
	}
	b, _ := m.BootedDevices(context.Background())
	if len(b) != 1 || b[0].UDID != simtest.Booted {
		t.Fatalf("booted %v", b)
	}
}

func TestR2_2_InstallAddsTheCAOnceToABootedSimulator(t *testing.T) {
	m, f, fake := setup(t)
	path, fp := testCert(t)
	d := sim.Device{UDID: simtest.Booted, Name: "iPhone 18 Pro Max", State: "Booted"}

	added, err := m.Install(context.Background(), d, path, fp)
	if err != nil || !added || !f.Trusts(simtest.Booted, hexOf(fp)) {
		t.Fatalf("first install: added %v err %v", added, err)
	}
	added, err = m.Install(context.Background(), d, path, fp)
	if err != nil || added {
		t.Fatalf("second install: added %v err %v, want nothing to do", added, err)
	}
	n := 0
	for _, c := range fake.Calls() {
		if strings.Contains(c, "add-root-cert") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("add-root-cert ran %d times", n)
	}
	if _, err := m.Install(context.Background(), sim.Device{UDID: simtest.Shutdown, State: "Shutdown"}, path, fp); err == nil {
		t.Fatal("install into a shut-down simulator did not fail")
	}
	if _, err := m.Install(context.Background(), d, "ca.pem", fp); err == nil {
		t.Fatal("relative certificate path accepted")
	}
}

func TestS4_5_RemoveDeletesOnlyWraithsCertBootedOrNot(t *testing.T) {
	m, f, _ := setup(t)
	_, fp := testCert(t)
	other := strings.Repeat("AB", 32)
	for _, add := range []struct{ udid, sum string }{
		{simtest.Shutdown, hexOf(fp)}, {simtest.Shutdown, other}, {simtest.Booted, hexOf(fp)},
	} {
		if err := f.AddTrust(add.udid, add.sum); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []sim.Device{{UDID: simtest.Shutdown, State: "Shutdown"}, {UDID: simtest.Booted, State: "Booted"}} {
		removed, err := m.Remove(context.Background(), d, fp)
		if err != nil || !removed || f.Trusts(d.UDID, hexOf(fp)) {
			t.Fatalf("%s: removed %v err %v", d.UDID, removed, err)
		}
	}
	if !f.Trusts(simtest.Shutdown, other) {
		t.Fatal("another certificate was removed too")
	}
	if removed, err := m.Remove(context.Background(), sim.Device{UDID: simtest.Shutdown}, fp); err != nil || removed {
		t.Fatalf("second remove: %v %v", removed, err)
	}
	fresh := sim.Device{UDID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}
	if removed, err := m.Remove(context.Background(), fresh, fp); err != nil || removed {
		t.Fatalf("device without a trust store: %v %v", removed, err)
	}
}

func TestR1_6_SimulatorsBootedLaterGetTheCA(t *testing.T) {
	m, f, _ := setup(t)
	path, fp := testCert(t)
	var mu sync.Mutex
	var logs []string
	logf := func(format string, a ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, a...))
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Watch(ctx, 10*time.Millisecond, path, fp, logf); close(done) }()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second) // R1.6: within 5 s
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("the booted simulator", func() bool { return f.Trusts(simtest.Booted, hexOf(fp)) })
	f.SetState(simtest.Shutdown, "Booted")
	waitFor("the newly booted simulator", func() bool { return f.Trusts(simtest.Shutdown, hexOf(fp)) })
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if joined := strings.Join(logs, "\n"); strings.Count(joined, "installed the wraith CA") != 2 {
		t.Fatalf("logs:\n%s", joined)
	}
}

func TestWatchLogsARepeatedErrorOnce(t *testing.T) {
	fake := execx.NewFake() // no simctl: every list fails the same way
	m, err := sim.New(fake, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	m.Watch(ctx, 5*time.Millisecond, "/x/ca.pem", [32]byte{}, func(string, ...any) { n++ })
	if n != 1 {
		t.Fatalf("logged %d times, want once", n)
	}
}
