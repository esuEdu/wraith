package ca

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Leaf lifetimes (S1.6).
const (
	LeafValidity = 7 * 24 * time.Hour
	LeafBackdate = time.Hour
	// leafRenewBefore makes the cache reissue a leaf this close to expiry.
	leafRenewBefore = time.Hour

	defaultLeafCacheSize = 1024
)

// Leaf returns a TLS certificate for host signed by the CA, issuing it on first use and
// caching it in memory (R2.6). host is a DNS name or an IP address; the leaf names that
// one host and nothing else, is valid for serverAuth only, for 7 days, backdated 1 hour
// for clock skew, and is never written to disk (S1.6).
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	h, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	return c.leaves.get(h)
}

func normalizeHost(host string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.String(), nil
	}
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\:*@\x00") {
		return "", fmt.Errorf("cannot issue a certificate for %q", host)
	}
	return h, nil
}

// issue creates one leaf. All leaves share one in-memory key: it never leaves the
// process, and making a key per host would only add latency.
func (c *CA) issue(host string, key crypto.Signer) (*tls.Certificate, error) {
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"wraith"}},
		NotBefore:    now.Add(-LeafBackdate),
		NotAfter:     now.Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// leafCache is an LRU of issued leaves. Concurrent requests for one host wait for a
// single issue.
type leafCache struct {
	ca  *CA
	key crypto.Signer
	max int

	mu       sync.Mutex
	order    *list.List // front = most recently used; values are *leafEntry
	byHost   map[string]*list.Element
	inflight map[string]*inflightIssue
	issued   int // for tests: leaves actually created
}

type leafEntry struct {
	host string
	cert *tls.Certificate
}

type inflightIssue struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

func newLeafCache(c *CA, size int) (*leafCache, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &leafCache{
		ca: c, key: key, max: size,
		order: list.New(), byHost: map[string]*list.Element{}, inflight: map[string]*inflightIssue{},
	}, nil
}

func (lc *leafCache) get(host string) (*tls.Certificate, error) {
	lc.mu.Lock()
	if el, ok := lc.byHost[host]; ok {
		e := el.Value.(*leafEntry)
		if lc.ca.now().Add(leafRenewBefore).Before(e.cert.Leaf.NotAfter) {
			lc.order.MoveToFront(el)
			lc.mu.Unlock()
			return e.cert, nil
		}
		lc.order.Remove(el)
		delete(lc.byHost, host)
	}
	if f, ok := lc.inflight[host]; ok {
		lc.mu.Unlock()
		<-f.done
		return f.cert, f.err
	}
	f := &inflightIssue{done: make(chan struct{})}
	lc.inflight[host] = f
	lc.mu.Unlock()

	f.cert, f.err = lc.ca.issue(host, lc.key)

	lc.mu.Lock()
	delete(lc.inflight, host)
	if f.err == nil {
		lc.issued++
		lc.byHost[host] = lc.order.PushFront(&leafEntry{host: host, cert: f.cert})
		for lc.order.Len() > lc.max {
			old := lc.order.Back()
			lc.order.Remove(old)
			delete(lc.byHost, old.Value.(*leafEntry).host)
		}
	}
	lc.mu.Unlock()
	close(f.done)
	return f.cert, f.err
}
