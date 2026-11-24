package tui

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/store"
)

type fakeActions struct {
	source              string
	choices             []Choice
	bypassed, noDecrypt []string
	exported, cleared   int
}

func (f *fakeActions) Source() string             { return f.source }
func (f *fakeActions) Choices() ([]Choice, error) { return f.choices, nil }
func (f *fakeActions) SetSource(s string) error {
	if _, err := source.Parse(s); err != nil {
		return err
	}
	f.source = s
	return nil
}
func (f *fakeActions) Bypass(h string) error      { f.bypassed = append(f.bypassed, h); return nil }
func (f *fakeActions) NoDecrypt(h string) error   { f.noDecrypt = append(f.noDecrypt, h); return nil }
func (f *fakeActions) Curl(fl store.Flow) string  { return "curl '" + fl.URL + "'" }
func (f *fakeActions) ExportHAR() (string, error) { f.exported++; return "/tmp/x.har", nil }
func (f *fakeActions) Clear()                     { f.cleared++ }

func press(m *Model, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "backspace":
			msg = tea.KeyPressMsg{Code: tea.KeyBackspace}
		case "up":
			msg = tea.KeyPressMsg{Code: tea.KeyUp}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		default:
			r := []rune(k)[0]
			msg = tea.KeyPressMsg{Code: r, Text: k}
		}
		m.Update(msg)
	}
}

// screen is what the view shows, without colors.
func screen(m *Model) string { return ansi.Strip(m.View().Content) }

// run delivers a command's message back to the model, as the program would.
func run(m *Model, cmd tea.Cmd) {
	if cmd != nil {
		m.Update(cmd())
	}
}

func typeText(m *Model, s string) {
	for _, r := range s {
		press(m, string(r))
	}
}

func flows() []store.Flow {
	t0 := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	return []store.Flow{
		{ID: 1, Kind: store.KindHTTP, Start: t0, Source: "sim iPhone 17 · Shop", Method: "GET", URL: "https://api.shop.test/cart", Status: 200, Route: "vpn",
			ReqHeader: http.Header{"Accept": {"application/json"}}, RespBody: store.Body{Data: []byte(`{"items":[]}`), Size: 12}},
		{ID: 2, Kind: store.KindTunnel, Start: t0, Source: "sim iPhone 17 · Shop", Method: "CONNECT", URL: "pinned.bank.test:443", Status: 200, Route: "direct"},
		{ID: 3, Kind: store.KindHTTP, Start: t0, Source: "curl", Method: "POST", URL: "http://login.test/session", Status: 503, Route: "vpn"},
	}
}

func newModel() (*Model, *fakeActions) {
	act := &fakeActions{source: "simulator"}
	return New(act, "127.0.0.1:9090", flows()), act
}

func TestListShowsFlowsAndFollowsNewOnes(t *testing.T) {
	m, _ := newModel()
	out := screen(m)
	for _, want := range []string{"capturing simulator", "3 flows", "https://api.shop.test/cart", "pinned.bank.test:443", "tun", "503"} {
		if !strings.Contains(out, want) {
			t.Errorf("list misses %q:\n%s", want, out)
		}
	}
	if f, _ := m.selected(); f.ID != 3 {
		t.Fatalf("selected %d, want the newest", f.ID)
	}
	m.Update(FlowMsg(store.Flow{ID: 4, Kind: store.KindHTTP, Method: "GET", URL: "https://new.test/", Status: 200}))
	if f, _ := m.selected(); f.ID != 4 {
		t.Fatal("did not follow the new flow")
	}
	press(m, "up", "up")
	m.Update(FlowMsg(store.Flow{ID: 5, Kind: store.KindHTTP, URL: "https://later.test/"}))
	if f, _ := m.selected(); f.ID != 2 {
		t.Fatalf("selection jumped to %d while reading older flows", f.ID)
	}
}

func TestFilterAndDetails(t *testing.T) {
	m, _ := newModel()
	press(m, "/")
	typeText(m, "shop cartx")
	press(m, "backspace", "enter")
	if len(m.shown) != 1 || m.flows[m.shown[0]].ID != 1 {
		t.Fatalf("filter shows %v", m.shown)
	}
	press(m, "enter")
	out := screen(m)
	for _, want := range []string{"GET https://api.shop.test/cart", "Accept: application/json", `"items": []`, "route vpn"} {
		if !strings.Contains(out, want) {
			t.Errorf("details miss %q:\n%s", want, out)
		}
	}
	press(m, "esc", "esc")
	if m.filter != "" || len(m.shown) != 3 {
		t.Fatal("esc did not clear the filter")
	}
}

func TestR1_5_SourceChangesFromTheLiveView(t *testing.T) {
	m, act := newModel()
	press(m, "s")
	for range len("simulator") {
		press(m, "backspace")
	}
	typeText(m, "app:Safari")
	press(m, "enter")
	if act.source != "app:Safari" || !strings.Contains(m.status, "capturing app:Safari for new connections") {
		t.Fatalf("source %q status %q", act.source, m.status)
	}
	press(m, "s") // the picker starts empty; text that matches nothing is used as typed
	for range len("app:Safari") {
		press(m, "backspace")
	}
	typeText(m, "bogus")
	press(m, "enter")
	if act.source != "app:Safari" || !strings.Contains(m.status, "must be all") {
		t.Fatalf("invalid source accepted: %q %q", act.source, m.status)
	}
}

func TestR1_5_SourcePickerListsSimulatorsAndApps(t *testing.T) {
	m, act := newModel()
	act.choices = []Choice{
		{Source: "simulator:2F3A0D4E-1B2C-4D5E-8F90-A1B2C3D4E5F6", Label: "iPhone 17 Pro", Note: "iOS 26.1 · CA installed"},
		{Source: "simulator:9C1BEA91-F023-4C77-857A-A5622219DC8B", Label: "iPad Air", Note: "iOS 26.1 · CA not installed yet"},
		{Source: "app:Safari", Label: "Safari", Note: "Mac app"},
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	if out := screen(m); !strings.Contains(out, "looking for booted simulators") {
		t.Fatalf("picker before the list arrives:\n%s", out)
	}
	run(m, cmd)
	out := screen(m)
	for _, want := range []string{"Capture which source?", "▸ ● simulator", "every booted simulator (2 now)", "iPhone 17 Pro", "iOS 26.1 · CA installed", "iPad Air", "Safari", "Mac app"} {
		if !strings.Contains(out, want) {
			t.Errorf("picker misses %q:\n%s", want, out)
		}
	}
	press(m, "down", "enter") // the first simulator, by UDID
	if act.source != "simulator:2F3A0D4E-1B2C-4D5E-8F90-A1B2C3D4E5F6" || m.mode != modeList {
		t.Fatalf("source %q mode %v", act.source, m.mode)
	}
	if out := screen(m); !strings.Contains(out, "capturing iPhone 17 Pro") {
		t.Fatalf("header does not name the simulator:\n%s", out)
	}

	run(m, func() tea.Cmd { _, c := m.Update(tea.KeyPressMsg{Code: 's', Text: "s"}); return c }())
	typeText(m, "ipad")
	if out := screen(m); strings.Contains(out, "Safari") || !strings.Contains(out, "▸   iPad Air") {
		t.Fatalf("typing does not narrow the list:\n%s", out)
	}
	press(m, "enter")
	if act.source != "simulator:9C1BEA91-F023-4C77-857A-A5622219DC8B" {
		t.Fatalf("source %q", act.source)
	}

	press(m, "s")
	typeText(m, "pid:4242")
	if out := screen(m); !strings.Contains(out, "enter uses pid:4242 as typed") {
		t.Fatalf("no hint for typed sources:\n%s", out)
	}
	press(m, "enter")
	if act.source != "pid:4242" {
		t.Fatalf("typed source not used: %q", act.source)
	}
	press(m, "s", "esc")
	if m.mode != modeList || act.source != "pid:4242" {
		t.Fatal("esc changed the source")
	}
}

func TestThemeUsesTheTerminalPaletteOnly(t *testing.T) {
	m, _ := newModel()
	press(m, "up") // a row that is not selected shows its colors
	out := m.View().Content
	if strings.Contains(out, "38;2;") || strings.Contains(out, "48;2;") || strings.Contains(out, "38;5;") || strings.Contains(out, "48;5;") {
		t.Fatalf("a fixed RGB or 256-color code would ignore the terminal's theme:\n%q", out)
	}
	for _, sgr := range []string{"\x1b[36", "\x1b[1;7;36", "\x1b[31", "\x1b[7m"} { // cyan accent, badge, red 503, selection
		if !strings.Contains(out, sgr) {
			t.Errorf("missing %q in\n%q", sgr, out)
		}
	}
}

func TestDetailsDecodePrettyPrintAndWrapBodies(t *testing.T) {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write([]byte(`{"pedido":"A04FBEEB","itens":[1,2]}`))
	_ = zw.Close()
	long := strings.Repeat("abcdefghij", 30) // 300 characters, wider than the screen
	act := &fakeActions{source: "simulator"}
	m := New(act, "127.0.0.1:9090", []store.Flow{{
		ID: 1, Kind: store.KindHTTP, Method: "POST", URL: "https://api.test/ordem", Status: 200,
		ReqHeader:  http.Header{"Content-Type": {"text/plain"}},
		ReqBody:    store.Body{Data: []byte(long), Size: int64(len(long))},
		RespHeader: http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"application/json"}},
		RespBody:   store.Body{Data: z.Bytes(), Size: int64(z.Len())},
	}})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 60})
	press(m, "enter")
	out := screen(m)
	for _, want := range []string{"gzip, 35 decoded", `"pedido": "A04FBEEB",`, `"itens": [`, long[:79], long[79:158]} {
		if !strings.Contains(out, want) {
			t.Errorf("details miss %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "binary") || strings.Contains(out, "…") {
		t.Errorf("a body was not decoded or was cut:\n%s", out)
	}
}

func TestHostActionsCurlExportClear(t *testing.T) {
	m, act := newModel()
	press(m, "up") // the tunnel to pinned.bank.test
	press(m, "b", "n")
	if strings.Join(act.bypassed, ",") != "pinned.bank.test" || strings.Join(act.noDecrypt, ",") != "pinned.bank.test" {
		t.Fatalf("bypass %v no-decrypt %v", act.bypassed, act.noDecrypt)
	}
	press(m, "c")
	if !strings.Contains(m.status, "a tunnel has no request") {
		t.Fatalf("curl on a tunnel: %q", m.status)
	}
	press(m, "up")
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	if cmd == nil || !strings.Contains(m.status, "copied") {
		t.Fatalf("curl on a request: cmd %v status %q", cmd, m.status)
	}
	press(m, "e")
	if act.exported != 1 || !strings.Contains(m.status, "exported to /tmp/x.har") {
		t.Fatalf("export: %d %q", act.exported, m.status)
	}
	press(m, "x")
	if act.cleared != 1 || len(m.flows) != 0 || !strings.Contains(screen(m), "waiting for traffic") {
		t.Fatal("clear did not empty the list")
	}
}

func TestQuitAndNotices(t *testing.T) {
	m, _ := newModel()
	m.Update(NoticeMsg("simulator iPhone 17: installed the wraith CA"))
	if !strings.Contains(screen(m), "installed the wraith CA") {
		t.Fatal("notice not shown")
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if cmd == nil {
		t.Fatal("q did not quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("q's command is not Quit")
	}
}

func TestFlowsAlreadyShownAreNotRepeated(t *testing.T) {
	m, _ := newModel()
	m.Update(FlowMsg(flows()[2])) // ID 3, already in the snapshot
	if len(m.flows) != 3 {
		t.Fatalf("%d flows, want 3", len(m.flows))
	}
}
