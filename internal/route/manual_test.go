//go:build manual

package route

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
)

// TestManualBypassOnThisMac dials a real host around the VPN. Run it with the VPN on:
//
//	WRAITH_BYPASS_HOST=api.anthropic.com go test -tags manual -run Manual -v ./internal/route
func TestManualBypassOnThisMac(t *testing.T) {
	host := os.Getenv("WRAITH_BYPASS_HOST")
	if host == "" {
		host = "example.com"
	}
	r := New(context.Background(), execx.Default(), []string{host}, "auto")
	ifi, err := r.Iface()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("interface %s (index %d) %v; resolvers %v", ifi.Name, ifi.Index, ifi.Addrs, r.servers)
	ips, err := r.lookup(context.Background(), host)
	if err != nil {
		t.Fatalf("bound DNS: %v", err)
	}
	t.Logf("bound DNS: %v", ips)
	c, err := r.DialContext(context.Background(), "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).IP
	onIface := false
	for _, a := range ifi.Addrs {
		onIface = onIface || a.Equal(local)
	}
	tc := tls.Client(c, &tls.Config{ServerName: host})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS: %v", err)
	}
	t.Logf("connected %s -> %s, TLS %s, local address on %s: %v",
		c.LocalAddr(), c.RemoteAddr(), tls.VersionName(tc.ConnectionState().Version), ifi.Name, onIface)
	if !onIface {
		t.Fatalf("local address %s is not on %s", local, ifi.Name)
	}
}
