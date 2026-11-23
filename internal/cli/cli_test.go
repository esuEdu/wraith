package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/sim"
	"github.com/esuEdu/wraith/internal/sim/simtest"
	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/sysproxy"
	"github.com/esuEdu/wraith/internal/sysproxy/sysproxytest"
)

// syncBuffer is a bytes.Buffer safe to write from the CLI's goroutines while a test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t              *testing.T
	dir            string
	mac            *sysproxytest.Mac
	sims           *simtest.Sims
	stdin          string
	macTrusts      bool
	origin         source.Origin // who "connected" through the proxy
	originErr      error
	fake           *execx.Fake
	stdout, stderr *syncBuffer
	sigs           chan os.Signal
	ready          chan string
	killed         chan int
	euid           int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t:      t,
		dir:    filepath.Join(t.TempDir(), "wraith"),
		mac:    sysproxytest.NewMac(),
		sims:   simtest.New(t.TempDir()),
		fake:   execx.NewFake(),
		stdout: &syncBuffer{},
		stderr: &syncBuffer{},
		sigs:   make(chan os.Signal, 1),
		ready:  make(chan string, 1),
		killed: make(chan int, 1),
		euid:   501,
		origin: source.Origin{ // a simulator app, inside the default source
			PID: 4242, Chain: []source.Process{{PID: 4242, Path: "/sim/Shop.app/Shop"}},
			SimUDID: simtest.Booted, AppPath: "/sim/Shop.app", AppName: "Shop",
		},
	}
	e.fake.Handler = func(tool string, args []string) ([]byte, error) {
		switch tool {
		case "xcrun", "sqlite3":
			return e.sims.Run(tool, args)
		case "security":
			return e.security(args)
		}
		return e.mac.Run(tool, args)
	}
	return e
}

// security fakes /usr/bin/security's trust commands.
func (e *env) security(args []string) ([]byte, error) {
	switch args[0] {
	case "verify-cert":
		if e.macTrusts {
			return nil, nil
		}
		return nil, &execx.Error{Tool: "security", Args: args, ExitCode: 2}
	case "add-trusted-cert":
		e.macTrusts = true
		return nil, nil
	case "remove-trusted-cert", "delete-certificate":
		if !e.macTrusts {
			return nil, &execx.Error{Tool: "security", Args: args, ExitCode: 1}
		}
		if args[0] == "remove-trusted-cert" {
			e.macTrusts = false
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected security %v", args)
}

func (e *env) deps() Deps {
	return Deps{
		Stdin:   strings.NewReader(e.stdin),
		Stdout:  e.stdout,
		Stderr:  e.stderr,
		Runner:  e.fake,
		HomeDir: e.dir,
		Geteuid: func() int { return e.euid },
		Signals: func() (<-chan os.Signal, func()) { return e.sigs, func() {} },
		Kill: func(pid int, sig syscall.Signal) error {
			e.killed <- pid
			e.sigs <- sig
			return nil
		},
		Ready:         func(addr string) { e.ready <- addr },
		StopTimeout:   5 * time.Second,
		SimDevicesDir: e.sims.Dir,
		SimPoll:       10 * time.Millisecond,
		Lookup: func(context.Context, int, int) (source.Origin, error) {
			return e.origin, e.originErr
		},
	}
}

func (e *env) run(args ...string) int {
	return Main(context.Background(), args, e.deps())
}

// startAsync runs `wraith start args...` and waits until it is serving.
func (e *env) startAsync(args ...string) (addr string, done <-chan int) {
	e.t.Helper()
	ch := make(chan int, 1)
	go func() { ch <- e.run(append([]string{"start"}, args...)...) }()
	select {
	case addr = <-e.ready:
		return addr, ch
	case code := <-ch:
		e.t.Fatalf("start exited with %d before serving; stderr:\n%s", code, e.stderr)
	case <-time.After(10 * time.Second):
		e.t.Fatalf("start did not become ready; stderr:\n%s", e.stderr)
	}
	return "", nil
}

func waitExit(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("start did not exit")
	}
	return -1
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

func originalSettings() (web, secure map[string]sysproxytest.Proxy) {
	return sysproxytest.NewMac().Settings()
}

func TestVersion(t *testing.T) {
	e := newEnv(t)
	if code := e.run("version"); code != ExitOK || !strings.HasPrefix(e.stdout.String(), "wraith ") {
		t.Fatalf("code %d, stdout %q", code, e.stdout)
	}
}

func TestR6_3_ExitCodes(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{
			{"nope"},
			{"start", "--port", "abc"},
			{"start", "--port", "0"},
			{"start", "--source", "everything"},
			{"version", "extra"},
			{"doctor"},
		} {
			e := newEnv(t)
			if code := e.run(args...); code != ExitUsage {
				t.Errorf("%q: exit %d, want %d; stderr %q", args, code, ExitUsage, e.stderr)
			}
		}
	})
	t.Run("usage: invalid config file", func(t *testing.T) {
		e := newEnv(t)
		h, err := home.Open(e.dir)
		if err != nil {
			t.Fatal(err)
		}
		_ = h.WriteFile("config.yaml", []byte("prot: 9090\n"), 0o600)
		_ = h.Close()
		if code := e.run("start"); code != ExitUsage {
			t.Fatalf("exit %d, want %d", code, ExitUsage)
		}
	})
	t.Run("runtime: port in use", func(t *testing.T) {
		e := newEnv(t)
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
		if code := e.run("start", "--port", port); code != ExitRuntime {
			t.Fatalf("exit %d, want %d; stderr %q", code, ExitRuntime, e.stderr)
		}
	})
	t.Run("state: system proxy cannot be set", func(t *testing.T) {
		e := newEnv(t)
		e.mac.SetFailOn("networksetup -setwebproxystate Wi-Fi on")
		if code := e.run("start", "--port", freePort(t)); code != ExitState {
			t.Fatalf("exit %d, want %d; stderr %q", code, ExitState, e.stderr)
		}
		e.mac.SetFailOn("")
		if web, _ := e.mac.Settings(); !reflect.DeepEqual(web, func() map[string]sysproxytest.Proxy { w, _ := originalSettings(); return w }()) {
			t.Fatalf("settings not rolled back: %+v", web)
		}
	})
}

func TestS4_1_RefusesToRunAsRoot(t *testing.T) {
	for _, cmd := range []string{"start", "stop"} {
		e := newEnv(t)
		e.euid = 0
		if code := e.run(cmd); code == ExitOK || !strings.Contains(e.stderr.String(), "root") {
			t.Errorf("%s as root: exit %d, stderr %q", cmd, code, e.stderr)
		}
		if calls := e.fake.Calls(); len(calls) != 0 {
			t.Errorf("%s as root ran %q", cmd, calls)
		}
	}
}

func TestR4_2_StartSetsTheProxyAndRestoresOnSignal(t *testing.T) {
	e := newEnv(t)
	port := freePort(t)
	_, done := e.startAsync("--port", port)

	web, secure := e.mac.Settings()
	on := sysproxytest.Proxy{Enabled: true, Server: "127.0.0.1", Port: atoi(port)}
	if web["Wi-Fi"] != on || secure["Wi-Fi"] != on {
		t.Fatalf("while running: web %+v secure %+v", web["Wi-Fi"], secure["Wi-Fi"])
	}

	e.sigs <- syscall.SIGTERM
	if code := waitExit(t, done); code != ExitOK {
		t.Fatalf("exit %d; stderr:\n%s", code, e.stderr)
	}
	wantWeb, _ := originalSettings()
	if web, _ := e.mac.Settings(); !reflect.DeepEqual(web, wantWeb) {
		t.Fatalf("after stop: %+v\nwant %+v", web, wantWeb)
	}
	if !strings.Contains(e.stderr.String(), "system proxy settings restored") {
		t.Fatalf("stderr:\n%s", e.stderr)
	}
}

func TestR4_3_StartRestoresWhatACrashLeftBehind(t *testing.T) {
	e := newEnv(t)
	h, err := home.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysproxy.New(e.fake, h, nil).Enable(context.Background(), 7777); err != nil {
		t.Fatal(err)
	}
	_ = h.Close() // "crash": settings changed, never restored

	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	if !strings.Contains(e.stderr.String(), "did not exit cleanly") {
		t.Fatalf("no crash warning; stderr:\n%s", e.stderr)
	}
	wantWeb, _ := originalSettings()
	if web, _ := e.mac.Settings(); !reflect.DeepEqual(web, wantWeb) {
		t.Fatalf("leftover settings not restored: %+v", web)
	}
	e.sigs <- syscall.SIGINT
	waitExit(t, done)
}

func TestR4_5_SecondInstanceIsRefused(t *testing.T) {
	e := newEnv(t)
	_, done := e.startAsync("--port", freePort(t), "--no-system-proxy")

	second := newEnv(t)
	second.dir = e.dir
	if code := second.run("start", "--port", freePort(t)); code != ExitRuntime ||
		!strings.Contains(second.stderr.String(), "wraith is already running (pid "+strconv.Itoa(os.Getpid())+")") {
		t.Fatalf("second start: exit %d, stderr %q", code, second.stderr)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
}

func TestR4_6_StopRestoresWithoutARunningInstance(t *testing.T) {
	e := newEnv(t)
	if code := e.run("stop"); code != ExitOK || !strings.Contains(e.stderr.String(), "nothing to restore") {
		t.Fatalf("empty stop: exit %d, stderr %q", code, e.stderr)
	}

	h, err := home.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysproxy.New(e.fake, h, nil).Enable(context.Background(), 7777); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	if code := e.run("stop"); code != ExitOK || !strings.Contains(e.stderr.String(), "restored system proxy settings left by an earlier run") {
		t.Fatalf("stop after crash: exit %d, stderr %q", code, e.stderr)
	}
	wantWeb, _ := originalSettings()
	if web, _ := e.mac.Settings(); !reflect.DeepEqual(web, wantWeb) {
		t.Fatalf("not restored: %+v", web)
	}
}

func TestStopSignalsTheRunningInstance(t *testing.T) {
	e := newEnv(t)
	_, done := e.startAsync("--port", freePort(t))

	stopper := newEnv(t)
	stopper.dir, stopper.mac, stopper.fake = e.dir, e.mac, e.fake
	stopper.sigs, stopper.killed = e.sigs, e.killed // Kill delivers to the running start
	if code := stopper.run("stop"); code != ExitOK {
		t.Fatalf("stop: exit %d, stderr %q", code, stopper.stderr)
	}
	if pid := <-e.killed; pid != os.Getpid() {
		t.Fatalf("signalled pid %d, want the instance's %d", pid, os.Getpid())
	}
	if code := waitExit(t, done); code != ExitOK {
		t.Fatalf("start exit %d", code)
	}
	if !strings.Contains(stopper.stderr.String(), "stopped wraith (pid") {
		t.Fatalf("stop stderr %q", stopper.stderr)
	}
	wantWeb, _ := originalSettings()
	if web, _ := e.mac.Settings(); !reflect.DeepEqual(web, wantWeb) {
		t.Fatalf("not restored: %+v", web)
	}
}

func TestS3_4_PanicRestoresTheSystemProxy(t *testing.T) {
	e := newEnv(t)
	d := e.deps()
	d.Ready = func(string) { panic("boom") }
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		Main(context.Background(), []string{"start", "--port", freePort(t)}, d)
	}()
	if recovered != "boom" {
		t.Fatalf("panic not re-raised: %v", recovered)
	}
	wantWeb, _ := originalSettings()
	if web, _ := e.mac.Settings(); !reflect.DeepEqual(web, wantWeb) {
		t.Fatalf("not restored after panic: %+v", web)
	}
	if !strings.Contains(e.stderr.String(), "internal error; system proxy settings restored") {
		t.Fatalf("stderr %q", e.stderr)
	}
}

func TestNoSystemProxyServesAndLogsWithoutTouchingSettings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	e := newEnv(t)
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy")
	for _, c := range e.fake.Calls() {
		if strings.Contains(c, "-set") {
			t.Fatalf("--no-system-proxy ran %q", c)
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}}
	resp, err := client.Get(upstream.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body %q", body)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if !strings.Contains(e.stdout.String(), "GET "+upstream.URL+"/hello 200") {
		t.Fatalf("no flow line in stdout:\n%s", e.stdout)
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func TestDecryptCreatesTheCAAndDecrypts(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "decrypted")
	}))
	defer upstream.Close()

	e := newEnv(t)
	// The test upstream's certificate is self-signed, so it is named as insecure (S2.4).
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--insecure-upstream", "127.0.0.1")
	if !strings.Contains(e.stderr.String(), "created the wraith CA") ||
		!strings.Contains(e.stderr.String(), "not verifying the upstream certificate of 127.0.0.1") {
		t.Fatalf("stderr:\n%s", e.stderr)
	}
	caPEM, err := os.ReadFile(filepath.Join(e.dir, "ca", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	resp, err := client.Get(upstream.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "decrypted" || !strings.HasPrefix(resp.TLS.PeerCertificates[0].Issuer.CommonName, "wraith CA") {
		t.Fatalf("body %q issuer %q", body, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	}
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if !strings.Contains(e.stdout.String(), "[sim iPhone 18 Pro Max · Shop] GET "+upstream.URL+"/x 200") {
		t.Fatalf("stdout:\n%s", e.stdout)
	}
}

func TestS2_4_InsecureUpstreamNeedsDecryptAndOneExactHost(t *testing.T) {
	for _, args := range [][]string{
		{"start", "--no-decrypt", "--insecure-upstream", "dev.test"},
		{"start", "--no-system-proxy", "--insecure-upstream", "*.dev.test"},
		{"start", "--no-system-proxy", "--insecure-upstream", "https://dev.test"},
	} {
		e := newEnv(t)
		args = append(args, "--port", freePort(t))
		if code := e.run(args...); code != ExitUsage {
			t.Errorf("%q: exit %d, want %d; stderr %q", args, code, ExitUsage, e.stderr)
		}
	}
}

func (e *env) newSimManager() (*sim.Manager, error) { return sim.New(e.fake, e.sims.Dir) }
