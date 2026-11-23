package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/home"
)

func openHome(t *testing.T) *home.Home {
	t.Helper()
	h, err := home.Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func loadCA(t *testing.T, h *home.Home) *CA {
	t.Helper()
	c, _, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func near(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d < -time.Minute || d > time.Minute {
		t.Errorf("%s = %s, want about %s", what, got, want)
	}
}

func TestR2_1_CreatedOnceThenReloaded(t *testing.T) {
	h := openHome(t)
	first, created, err := Load(h)
	if err != nil || !created {
		t.Fatalf("first Load: created=%v err=%v", created, err)
	}
	second, created, err := Load(h)
	if err != nil || created {
		t.Fatalf("second Load: created=%v err=%v", created, err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("second Load made a new CA")
	}
	for _, name := range []string{CertFile, KeyFile} {
		if _, err := os.Stat(filepath.Join(h.Path(), Dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestS1_1_KeyIsP256AndUniquePerMachine(t *testing.T) {
	a, b := loadCA(t, openHome(t)), loadCA(t, openHome(t))
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("two homes got the same CA")
	}
	pub, ok := a.Certificate().PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("CA key is %T, want ECDSA P-256", a.Certificate().PublicKey)
	}
}

func TestS1_2_CADirAndKeyArePrivate(t *testing.T) {
	h := openHome(t)
	loadCA(t, h)
	dir := filepath.Join(h.Path(), Dir)
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, KeyFile): 0o600} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %04o (%v)", path, fi.Mode().Perm(), want, err)
		}
	}

	if err := os.Chmod(filepath.Join(dir, KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(h); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("readable key: err = %v", err)
	}
	_ = os.Chmod(filepath.Join(dir, KeyFile), 0o600)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(h); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("open ca dir: err = %v", err)
	}
}

func TestS1_3_CertificateExportNeverContainsTheKey(t *testing.T) {
	c := loadCA(t, openHome(t))
	pemText := string(c.CertPEM())
	if !strings.Contains(pemText, "BEGIN CERTIFICATE") || strings.Contains(pemText, "PRIVATE KEY") {
		t.Fatalf("CertPEM = %q", pemText)
	}
	leaf, err := c.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.PrivateKey.(*ecdsa.PrivateKey).PublicKey.Equal(c.Certificate().PublicKey) {
		t.Fatal("a leaf carries the CA private key")
	}
}

func TestS1_4_ValidityExpiryWarningAndRotation(t *testing.T) {
	h := openHome(t)
	c := loadCA(t, h)
	cert := c.Certificate()
	near(t, "NotAfter", cert.NotAfter, time.Now().Add(Validity))
	if !strings.HasPrefix(cert.Subject.CommonName, "wraith CA (") || !cert.IsCA || !cert.MaxPathLenZero {
		t.Fatalf("subject %q IsCA %v MaxPathLenZero %v", cert.Subject.CommonName, cert.IsCA, cert.MaxPathLenZero)
	}
	if soon, _ := c.ExpiresSoon(); soon {
		t.Fatal("new CA reported as expiring soon")
	}
	c.now = func() time.Time { return cert.NotAfter.Add(-29 * 24 * time.Hour) }
	if soon, when := c.ExpiresSoon(); !soon || !when.Equal(cert.NotAfter) {
		t.Fatalf("29 days before expiry: soon=%v when=%v", soon, when)
	}

	rotated, err := Rotate(h)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Fingerprint() == c.Fingerprint() || loadCA(t, h).Fingerprint() != rotated.Fingerprint() {
		t.Fatal("Rotate did not replace the stored CA")
	}
}

func TestExpiredCAIsRefused(t *testing.T) {
	h := openHome(t)
	c := loadCA(t, h)
	later := c.Certificate().NotAfter.Add(time.Hour)
	if _, _, err := load(h, func() time.Time { return later }); err == nil || !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("expired CA: err = %v", err)
	}
}

func TestMismatchedOrBrokenFilesAreRefused(t *testing.T) {
	h := openHome(t)
	loadCA(t, h)
	other := openHome(t)
	loadCA(t, other)
	otherKey, _ := os.ReadFile(filepath.Join(other.Path(), Dir, KeyFile))
	if err := os.WriteFile(filepath.Join(h.Path(), Dir, KeyFile), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(h); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: err = %v", err)
	}

	h2 := openHome(t)
	loadCA(t, h2)
	_ = os.WriteFile(filepath.Join(h2.Path(), Dir, CertFile), []byte("garbage"), 0o644)
	if _, _, err := Load(h2); err == nil {
		t.Fatal("garbage certificate accepted")
	}

	h3 := openHome(t)
	loadCA(t, h3)
	_ = os.Remove(filepath.Join(h3.Path(), Dir, CertFile))
	if _, _, err := Load(h3); err == nil || !strings.Contains(err.Error(), "without") {
		t.Fatalf("key without cert: err = %v", err)
	}
}

func TestR2_6_LeavesAreIssuedOncePerHostAndCached(t *testing.T) {
	c := loadCA(t, openHome(t))
	var wg sync.WaitGroup
	certs := make([]*tls.Certificate, 50)
	for i := range certs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if certs[i], err = c.Leaf("api.example.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, cert := range certs[1:] {
		if cert != certs[0] {
			t.Fatal("concurrent requests got different leaves")
		}
	}
	if again, _ := c.Leaf("API.Example.com."); again != certs[0] {
		t.Fatal("same host, other spelling, issued again")
	}
	other, _ := c.Leaf("www.example.com")
	if other == certs[0] || c.leaves.issued != 2 {
		t.Fatalf("issued %d leaves, want 2", c.leaves.issued)
	}
}

func TestS1_6_LeafNamesOneHostForServerAuthForSevenDays(t *testing.T) {
	c := loadCA(t, openHome(t))
	roots := x509.NewCertPool()
	roots.AddCert(c.Certificate())

	for _, host := range []string{"api.example.com", "10.0.0.7", "::1"} {
		cert, err := c.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		leaf := cert.Leaf
		if ip := net.ParseIP(host); ip != nil {
			if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(ip) || len(leaf.DNSNames) != 0 {
				t.Errorf("%s: IPs %v DNS %v", host, leaf.IPAddresses, leaf.DNSNames)
			}
		} else if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host || len(leaf.IPAddresses) != 0 {
			t.Errorf("%s: DNS %v IPs %v", host, leaf.DNSNames, leaf.IPAddresses)
		}
		if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.IsCA {
			t.Errorf("%s: EKU %v IsCA %v", host, leaf.ExtKeyUsage, leaf.IsCA)
		}
		near(t, host+" NotBefore", leaf.NotBefore, time.Now().Add(-LeafBackdate))
		near(t, host+" NotAfter", leaf.NotAfter, time.Now().Add(LeafValidity))
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s does not verify against the CA: %v", host, err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example.com"}); err == nil {
			t.Errorf("%s leaf also valid for other.example.com", host)
		}
	}
	for _, bad := range []string{"", "a b", "*.example.com", "x/y", "user@host"} {
		if _, err := c.Leaf(bad); err == nil {
			t.Errorf("Leaf(%q) accepted", bad)
		}
	}
}

func TestLeafIsReissuedNearExpiryAndCacheIsBounded(t *testing.T) {
	c := loadCA(t, openHome(t))
	first, _ := c.Leaf("example.com")
	c.now = func() time.Time { return first.Leaf.NotAfter.Add(-30 * time.Minute) }
	second, _ := c.Leaf("example.com")
	if second == first {
		t.Fatal("leaf 30 minutes from expiry was reused")
	}

	c.now = time.Now
	c.leaves.max = 3
	for _, h := range []string{"a.test", "b.test", "c.test", "d.test"} {
		if _, err := c.Leaf(h); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.leaves.order.Len(); n != 3 {
		t.Fatalf("cache holds %d leaves, want 3", n)
	}
	if _, ok := c.leaves.byHost["a.test"]; ok {
		t.Fatal("least recently used leaf not evicted")
	}
}
