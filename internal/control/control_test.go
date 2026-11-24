package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/export"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/store"
)

// shortHome opens a home directory under /tmp: Unix socket paths must stay short.
func shortHome(t *testing.T) *home.Home {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "wr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	h, err := home.Open(filepath.Join(d, "w"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestS3_5_FlowsAreServedOnAPrivateUnixSocket(t *testing.T) {
	h := shortHome(t)
	s := store.New(10, 1024)
	s.Add(store.Flow{Kind: store.KindHTTP, Method: "GET", URL: "https://api.example.com/x", Status: 200,
		ReqHeader: http.Header{"Authorization": {"Bearer SECRET"}}})
	srv, err := Listen(h, s, export.DefaultPatterns)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(srv.Path())
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %v mode %v err %v", srv.Path(), fi.Mode(), err)
	}

	har, err := FetchHAR(context.Background(), h, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(har), "https://api.example.com/x") || strings.Contains(string(har), "SECRET") {
		t.Fatalf("redacted HAR:\n%s", har)
	}
	raw, err := FetchHAR(context.Background(), h, false)
	if err != nil || !strings.Contains(string(raw), "Bearer SECRET") {
		t.Fatalf("unredacted HAR: %v\n%s", err, raw)
	}

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(srv.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket left after Close")
	}
	if _, err := FetchHAR(context.Background(), h, true); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("after Close: %v, want ErrNotRunning", err)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	h := shortHome(t)
	ln, err := net.Listen("unix", filepath.Join(h.Path(), SocketFile))
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false) // leave the file behind, as a crash would
	_ = ln.Close()
	srv, err := Listen(h, store.New(1, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := FetchHAR(ctx, h, true); err != nil {
		t.Fatal(err)
	}
}

func TestSameUserPeersAreAccepted(t *testing.T) {
	h := shortHome(t)
	srv, err := Listen(h, store.New(1, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := net.Dial("unix", srv.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if uid, err := peerUID(c); err != nil || uid != os.Getuid() {
		t.Fatalf("peerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}

func TestLongHomePathsAreRefused(t *testing.T) {
	h, err := home.Open(filepath.Join(t.TempDir(), strings.Repeat("x", 90)))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := Listen(h, store.New(1, 1), nil); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("err = %v", err)
	}
}
