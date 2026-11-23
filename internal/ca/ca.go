// Package ca is wraith's certificate authority: one CA per machine, kept in
// ~/.wraith/ca/ (R2.1), and the per-host leaf certificates it signs to decrypt traffic
// (R2.6). The private key is created on this Mac, stays in ca/ with mode 0600, and no
// function hands it out (S1.1–S1.3).
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SubjectKeyId per RFC 5280 4.2.1.2, not a security hash
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/esuEdu/wraith/internal/home"
)

// Files in the home directory.
const (
	Dir      = "ca"
	CertFile = "ca.pem"
	KeyFile  = "ca.key"
)

// Lifetimes (S1.4).
const (
	Validity   = 2 * 365 * 24 * time.Hour
	WarnBefore = 30 * 24 * time.Hour
)

// CA is a loaded certificate authority.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	now     func() time.Time
	leaves  *leafCache
}

// Load opens h's ca/ directory and returns the CA there, creating one on first use. It
// refuses a ca/ directory or key file that other users can reach (S1.2), a key that does
// not match the certificate, and an expired CA (run Rotate).
func Load(h *home.Home) (c *CA, created bool, err error) {
	return load(h, time.Now)
}

func load(h *home.Home, now func() time.Time) (*CA, bool, error) {
	dir, err := h.Sub(Dir)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = dir.Close() }()

	certPEM, err := dir.ReadFile(CertFile)
	if errors.Is(err, fs.ErrNotExist) {
		if _, kerr := dir.ReadFile(KeyFile); kerr == nil {
			return nil, false, fmt.Errorf("%s/%s exists without %s; remove it or run `wraith ca rotate`", dir.Path(), KeyFile, CertFile)
		}
		c, err := create(dir, now)
		return c, err == nil, err
	}
	if err != nil {
		return nil, false, err
	}
	if err := dir.CheckPrivate(KeyFile); err != nil {
		return nil, false, err
	}
	keyPEM, err := dir.ReadFile(KeyFile)
	if err != nil {
		return nil, false, err
	}
	c, err := parse(certPEM, keyPEM, now)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", dir.Path(), err)
	}
	if now().After(c.cert.NotAfter) {
		return nil, false, fmt.Errorf("the wraith CA expired on %s; run `wraith ca rotate`", c.cert.NotAfter.Format("2006-01-02"))
	}
	return c, false, nil
}

// Rotate replaces the CA in h with a new one and returns it. Devices that trusted the
// old CA must be given the new one (`wraith ca install`, `wraith ca trust --mac`).
func Rotate(h *home.Home) (*CA, error) {
	dir, err := h.Sub(Dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	return create(dir, time.Now)
}

func create(dir *home.Home, now func() time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	host = strings.TrimSuffix(host, ".local")
	if host == "" {
		host = "this Mac"
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "wraith CA (" + host + ")", Organization: []string{"wraith"}},
		NotBefore:             t.Add(-time.Hour),
		NotAfter:              t.Add(Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// Key first: a crash between the two writes leaves a key without a matching
	// certificate, which load reports, never a certificate whose key is lost.
	if err := dir.WriteFile(KeyFile, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := dir.WriteFile(CertFile, certPEM, 0o644); err != nil {
		return nil, err
	}
	return parse(certPEM, keyPEM, now)
}

func parse(certPEM, keyPEM []byte, now func() time.Time) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is not a PEM certificate", CertFile)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CertFile, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", CertFile)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PEM private key", KeyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", KeyFile, err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s does not match %s; run `wraith ca rotate`", KeyFile, CertFile)
	}
	c := &CA{cert: cert, certPEM: pem.EncodeToMemory(cb), key: key, now: now}
	if c.leaves, err = newLeafCache(c, defaultLeafCacheSize); err != nil {
		return nil, err
	}
	return c, nil
}

// Certificate returns the CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM returns the CA certificate in PEM form, for installing on devices. It never
// contains the key (S1.3).
func (c *CA) CertPEM() []byte { return append([]byte(nil), c.certPEM...) }

// Fingerprint returns the certificate's SHA-256 fingerprint, as hex with colons.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// ExpiresSoon reports whether the CA expires within WarnBefore (S1.4), and when.
func (c *CA) ExpiresSoon() (bool, time.Time) {
	return c.now().Add(WarnBefore).After(c.cert.NotAfter), c.cert.NotAfter
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand does not fail on macOS
	}
	return n.Add(n, big.NewInt(1))
}

func keyID(pub *ecdsa.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha1.Sum(b) // #nosec G401 -- key identifier, not a security hash
	return sum[:]
}
