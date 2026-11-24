// Package control lets other wraith commands talk to the running instance, which is the
// only place flows exist (they live in its memory, R5.2). It is a Unix socket in the home
// directory, mode 0600, never TCP (S3.5), and it also refuses any peer that is not the
// same user.
package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/esuEdu/wraith/internal/export"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/store"
)

// SocketFile is the socket's name in the home directory.
const SocketFile = "wraith.sock"

// maxSocketPath is the room macOS gives a Unix socket path (sun_path, minus the NUL).
const maxSocketPath = 103

// ErrNotRunning means no wraith instance answers on the socket.
var ErrNotRunning = errors.New("wraith is not running; captured flows live only in its memory")

// Server serves the store on the socket.
type Server struct {
	path string
	srv  *http.Server
}

// Listen opens the socket in h and serves flows from s until Close; redact names the
// header patterns hidden unless a client asks for redact=false.
func Listen(h *home.Home, s *store.Store, redact []string) (*Server, error) {
	path := filepath.Join(h.Path(), SocketFile)
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("%s is too long for a Unix socket (%d > %d characters)", path, len(path), maxSocketPath)
	}
	if err := h.Remove(SocketFile); err != nil { // left by a crash; the caller holds the lock
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/har", func(w http.ResponseWriter, r *http.Request) {
		rd := export.NewRedactor(redact)
		if r.URL.Query().Get("redact") == "false" {
			rd = export.NewRedactor(nil)
		}
		b, err := export.HAR(s.Flows(), rd)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(&sameUserListener{Listener: ln}) }()
	return &Server{path: path, srv: srv}, nil
}

// Path is the socket's path.
func (s *Server) Path() string { return s.path }

// Close stops serving and removes the socket.
func (s *Server) Close() error {
	err := s.srv.Close()
	if rerr := os.Remove(s.path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
		err = rerr
	}
	return err
}

// sameUserListener closes connections from any other user before they are served.
type sameUserListener struct{ net.Listener }

func (l *sameUserListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, err := peerUID(c); err == nil && uid == os.Getuid() {
			return c, nil
		}
		_ = c.Close()
	}
}

func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, gerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if gerr == nil {
			uid = int(cred.Uid)
		}
	}); err != nil {
		return -1, err
	}
	return uid, gerr
}

// FetchHAR asks the running instance for its flows as HAR.
func FetchHAR(ctx context.Context, h *home.Home, redact bool) ([]byte, error) {
	path := filepath.Join(h.Path(), SocketFile)
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://wraith/v1/har?redact="+strconv.FormatBool(redact), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrNotRunning
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wraith answered %s", resp.Status)
	}
	return b, nil
}
