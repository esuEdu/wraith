package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/sim/simtest"
	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/store"
	"github.com/esuEdu/wraith/internal/tui"
)

func TestLiveViewRunsWhenStdoutIsATerminalAndQuitsOnQ(t *testing.T) {
	e := newEnv(t)
	in, keys := io.Pipe()
	d := e.deps()
	d.Stdin = in
	d.IsTerminal = func() bool { return true }
	done := make(chan int, 1)
	go func() { done <- Main(t.Context(), []string{"start", "--port", freePort(t), "--no-system-proxy"}, d) }()
	select {
	case <-e.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("not ready")
	}
	time.Sleep(200 * time.Millisecond) // let the view draw
	_, _ = keys.Write([]byte("q"))
	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("exit %d; stderr:\n%s", code, e.stderr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("q did not quit the live view")
	}
	if !strings.Contains(e.stdout.String(), "capturing simulator") {
		t.Fatalf("the live view did not draw:\n%q", e.stdout.String())
	}
}

func TestR1_5_SourceChangesApplyToNewConnections(t *testing.T) {
	ts, upstreamRoots := upstreamTLS(t)
	e := newEnv(t)
	e.origin = curl // outside the default simulator source
	var acts tui.Actions
	d := e.deps()
	d.OnActions = func(a tui.Actions) { acts = a }
	done := make(chan int, 1)
	go func() { done <- Main(t.Context(), []string{"start", "--port", freePort(t), "--no-system-proxy"}, d) }()
	addr := <-e.ready

	_, _ = fetch(t, addr, ts.URL+"/before", upstreamRoots)
	if err := acts.SetSource("app:curl"); err != nil {
		t.Fatal(err)
	}
	if acts.Source() != "app:curl" {
		t.Fatalf("source %q", acts.Source())
	}
	if err := acts.SetSource("nonsense"); err == nil {
		t.Fatal("invalid source accepted")
	}
	_, _ = fetch(t, addr, ts.URL+"/after", upstreamRoots)
	e.sigs <- syscall.SIGTERM
	<-done
	out := e.stdout.String()
	if strings.Count(out, "[curl] CONNECT") != 1 {
		t.Fatalf("want exactly the connection made after the change:\n%s", out)
	}
}

func TestR1_5_PickerOffersBootedSimulatorsAndMacApps(t *testing.T) {
	e := newEnv(t)
	var acts tui.Actions
	d := e.deps()
	d.OnActions = func(a tui.Actions) { acts = a }
	done := make(chan int, 1)
	go func() { done <- Main(t.Context(), []string{"start", "--port", freePort(t), "--no-system-proxy"}, d) }()
	<-e.ready
	defer func() { e.sigs <- syscall.SIGTERM; <-done }()
	acts.(liveActions).runningApps = func() ([]source.App, error) {
		return []source.App{{Name: "Safari", Path: "/Applications/Safari.app"}}, nil
	}
	acts.(liveActions).simApps = func() ([]source.SimApp, error) {
		return []source.SimApp{{UDID: strings.ToUpper(simtest.Booted), Name: "Shop"}, {UDID: "0000", Name: "Elsewhere"}}, nil
	}

	var sims []tui.Choice
	waitUntil(t, "the booted simulator to be listed with the CA", func() bool {
		list, err := acts.Choices()
		if err != nil {
			t.Fatal(err)
		}
		sims = nil
		for _, c := range list {
			if strings.HasPrefix(c.Source, "simulator:") {
				sims = append(sims, c)
			}
		}
		return len(sims) == 1 && strings.HasSuffix(sims[0].Note, "CA installed")
	})
	if c := sims[0]; c.Source != "simulator:"+simtest.Booted || c.Label != "iPhone 18 Pro Max" {
		t.Fatalf("simulator choice %+v", c)
	}
	list, _ := acts.Choices()
	var inSim []tui.Choice
	for _, c := range list {
		if c.Parent != "" {
			inSim = append(inSim, c)
		}
	}
	if len(inSim) != 1 || inSim[0].Source != "app:Shop" || inSim[0].Parent != "simulator:"+simtest.Booted || !strings.Contains(inSim[0].Note, "app in iPhone 18 Pro Max") {
		t.Fatalf("apps in the simulator: %+v", inSim)
	}
	last := list[len(list)-1]
	if last.Source != "app:Safari" || !strings.Contains(last.Note, "not decrypted until `wraith ca trust --mac`") {
		t.Fatalf("app choice %+v", last)
	}
	if err := acts.SetSource(sims[0].Source); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeName(t *testing.T) {
	for in, want := range map[string]string{"iOS-26-1": "iOS 26.1", "watchOS-11-0": "watchOS 11.0", "odd": "odd"} {
		if got := runtimeName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestLiveBypassAndNoDecryptAreSavedAndApplied(t *testing.T) {
	e := newEnv(t)
	var acts tui.Actions
	d := e.deps()
	d.OnActions = func(a tui.Actions) { acts = a }
	done := make(chan int, 1)
	go func() { done <- Main(t.Context(), []string{"start", "--port", freePort(t), "--no-system-proxy"}, d) }()
	<-e.ready
	if err := acts.Bypass("api.partner.io"); err != nil {
		t.Fatal(err)
	}
	if err := acts.Bypass("api.partner.io"); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := acts.NoDecrypt("pinned.bank.test"); err != nil {
		t.Fatal(err)
	}
	e.sigs <- syscall.SIGTERM
	<-done
	b, _ := os.ReadFile(filepath.Join(e.dir, "config.yaml"))
	if !strings.Contains(string(b), `"api.partner.io"`) || !strings.Contains(string(b), `"pinned.bank.test"`) {
		t.Fatalf("config.yaml:\n%s", b)
	}
}

func TestConfigThemesAreTheLiveViewsThemes(t *testing.T) {
	if !slices.Equal(config.Themes, tui.Themes) || config.Default().Theme != tui.DefaultTheme {
		t.Fatalf("config offers %v (default %s); the live view has %v (default %s)",
			config.Themes, config.Default().Theme, tui.Themes, tui.DefaultTheme)
	}
	m := tui.New(nil, "", nil)
	for _, name := range config.Themes {
		if err := m.SetTheme(name); err != nil {
			t.Error(err)
		}
	}
}

func TestResendFromTheLiveViewIsRecordedAsAReplay(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "pong "+r.Header.Get("X-Token"))
	}))
	t.Cleanup(ts.Close)
	e := newEnv(t) // a simulator app, inside the default source
	var acts tui.Actions
	d := e.deps()
	d.OnActions = func(a tui.Actions) { acts = a }
	done := make(chan int, 1)
	go func() { done <- Main(t.Context(), []string{"start", "--port", freePort(t), "--no-system-proxy"}, d) }()
	addr := <-e.ready

	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}}
	req, _ := http.NewRequest("GET", ts.URL+"/ping", nil)
	req.Header.Set("X-Token", "abc")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	orig := store.Flow{Kind: store.KindHTTP, Source: "sim iPhone 17 · Shop", Method: "GET", URL: ts.URL + "/ping", ReqHeader: http.Header{"X-Token": {"abc"}}}
	f, err := acts.Replay(orig)
	if err != nil || f.Status != 200 || string(f.RespBody.Data) != "pong abc" || f.Source != "replay · sim iPhone 17 · Shop" || hits.Load() != 2 {
		t.Fatalf("replay: %+v %v (%d hits)", f, err, hits.Load())
	}
	e.sigs <- syscall.SIGTERM
	<-done
	if out := e.stdout.String(); !strings.Contains(out, "[replay · sim iPhone 17 · Shop] GET "+ts.URL+"/ping 200") {
		t.Fatalf("the resent request is not a flow of its own:\n%s", out)
	}
}
