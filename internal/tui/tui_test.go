package tui

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/esuEdu/wraith/internal/export"
	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/store"
)

type fakeActions struct {
	source              string
	choices             []Choice
	bypassed, noDecrypt []string
	exported, cleared   int
	replayed            []store.Flow
	mocked              []store.Flow
	throttle            string
}

func (f *fakeActions) ToggleMock(fl store.Flow) (string, error) {
	f.mocked = append(f.mocked, fl)
	return "mocking " + fl.Method + " " + fl.URL, nil
}
func (f *fakeActions) Mocks() int                    { return len(f.mocked) }
func (f *fakeActions) Throttle() string              { return f.throttle }
func (f *fakeActions) SetThrottle(name string) error { f.throttle = name; return nil }

func (f *fakeActions) Replay(fl store.Flow) (store.Flow, error) {
	f.replayed = append(f.replayed, fl)
	return store.Flow{ID: 99, Kind: store.KindHTTP, Method: fl.Method, URL: fl.URL, Status: 201, Duration: 84 * time.Millisecond}, nil
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
func (f *fakeActions) Redactor() export.Redactor  { return export.NewRedactor(export.DefaultPatterns) }
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
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
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
	for _, want := range []string{" GET  https://api.shop.test/cart", "200 OK", "route vpn", " Response ", "JSON", `"items": []`} {
		if !strings.Contains(out, want) {
			t.Errorf("response tab misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Accept") {
		t.Errorf("response tab shows a request header:\n%s", out)
	}
	press(m, "tab")
	if out := screen(m); !strings.Contains(out, "Accept: application/json") || !strings.Contains(out, "no body") {
		t.Errorf("request tab:\n%s", out)
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
		{Source: "app:Slack", Label: "Slack", Note: "Mac app"},
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	if out := screen(m); !strings.Contains(out, "looking for booted simulators") {
		t.Fatalf("picker before the list arrives:\n%s", out)
	}
	run(m, cmd)
	out := screen(m)
	// The current source is simulator: its group is open, the cursor on it; Mac apps stay folded.
	for _, want := range []string{"Capture which source?", "▾ Simulators       2 booted", "▸ ●   every simulator", "iPhone 17 Pro", "iOS 26.1 · CA installed", "iPad Air", "▸ Mac apps         2 running"} {
		if !strings.Contains(out, want) {
			t.Errorf("picker misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Safari") {
		t.Errorf("the Mac apps group is open:\n%s", out)
	}
	press(m, "down", "enter") // the first simulator, by UDID
	if act.source != "simulator:2F3A0D4E-1B2C-4D5E-8F90-A1B2C3D4E5F6" || m.mode != modeList {
		t.Fatalf("source %q mode %v", act.source, m.mode)
	}
	if out := screen(m); !strings.Contains(out, "capturing iPhone 17 Pro") {
		t.Fatalf("header does not name the simulator:\n%s", out)
	}

	run(m, func() tea.Cmd { _, c := m.Update(tea.KeyPressMsg{Code: 's', Text: "s"}); return c }())
	typeText(m, "safari") // typing searches every group, folded or not
	if out := screen(m); strings.Contains(out, "iPad") || !strings.Contains(out, "▸   Safari") {
		t.Fatalf("typing does not search the folded apps:\n%s", out)
	}
	press(m, "enter")
	if act.source != "app:Safari" {
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

func TestSourcePickerGroupsOpenAndFold(t *testing.T) {
	m, act := newModel()
	act.source = "all"
	act.choices = []Choice{{Source: "app:Safari", Label: "Safari", Note: "Mac app"}, {Source: "app:Slack", Label: "Slack", Note: "Mac app"}}
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	run(m, func() tea.Cmd { _, c := m.Update(tea.KeyPressMsg{Code: 's', Text: "s"}); return c }())
	if out := screen(m); strings.Contains(out, "Safari") || strings.Contains(out, "every simulator") {
		t.Fatalf("groups start open:\n%s", out)
	}
	if m.View().MouseMode != tea.MouseModeCellMotion {
		t.Fatal("the picker does not take clicks")
	}
	press(m, "down", "down") // Mac apps
	m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	if out := screen(m); !strings.Contains(out, "▾ Mac apps") || !strings.Contains(out, "Slack") {
		t.Fatalf("→ does not open the group:\n%s", out)
	}
	press(m, "down")                             // Safari
	m.Update(tea.KeyPressMsg{Code: tea.KeyLeft}) // folds its group, back on the heading
	if out := screen(m); strings.Contains(out, "Safari") || !strings.Contains(out, "▸   ▸ Mac apps") {
		t.Fatalf("← does not fold the group:\n%s", out)
	}
	press(m, "enter") // enter opens it too
	if !strings.Contains(screen(m), "Slack") {
		t.Fatal("enter does not open the group")
	}

	// A click on a heading opens or folds it; a click on a source captures it.
	line := func(text string) int {
		for i, l := range strings.Split(screen(m), "\n") {
			if strings.Contains(l, text) {
				return i
			}
		}
		t.Fatalf("no line with %q:\n%s", text, screen(m))
		return -1
	}
	m.Update(tea.MouseClickMsg{X: 10, Y: line("Simulators"), Button: tea.MouseLeft})
	if !strings.Contains(screen(m), "every simulator") {
		t.Fatal("a click does not open the group")
	}
	m.Update(tea.MouseWheelMsg{X: 10, Y: 6, Button: tea.MouseWheelDown})
	m.Update(tea.MouseClickMsg{X: 10, Y: line("Slack"), Button: tea.MouseLeft})
	if act.source != "app:Slack" || m.mode != modeList {
		t.Fatalf("a click does not capture the app: %q", act.source)
	}
	if m.View().MouseMode == tea.MouseModeCellMotion {
		t.Fatal("the list takes the mouse: selecting text in the terminal would stop working")
	}
}

func TestTerminalThemeUsesTheTerminalPaletteOnly(t *testing.T) {
	m, _ := newModel()
	if err := m.SetTheme("terminal"); err != nil {
		t.Fatal(err)
	}
	if v := m.View(); v.BackgroundColor != nil || v.ForegroundColor != nil {
		t.Fatal("the terminal theme changes the terminal's colors")
	}
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

func TestHeliotropeHazeIsTheDefault(t *testing.T) {
	m, _ := newModel()
	v := m.View()
	if v.BackgroundColor == nil || v.ForegroundColor == nil {
		t.Fatal("Heliotrope Haze does not paint the screen")
	}
	for _, sgr := range []string{"48;2;201;128;242", "38;2;255;126;219", "48;2;58;43;92"} { // badge, selection bar, selected row
		if !strings.Contains(v.Content, sgr) {
			t.Errorf("missing %q in\n%q", sgr, v.Content)
		}
	}
	press(m, "up", "up", "enter") // GET /cart: {"items":[]}
	out := m.View().Content
	for _, sgr := range []string{"\x1b[38;2;122;155;245m\"items\"", "\x1b[38;2;106;95;133m["} { // a blue key, faint punctuation
		if !strings.Contains(out, sgr) {
			t.Errorf("JSON is not colored: missing %q in\n%q", sgr, out)
		}
	}
	if err := m.SetTheme("neon"); err == nil {
		t.Fatal("an unknown theme was accepted")
	}
}

func TestDetailsCopyEachPart(t *testing.T) {
	act := &fakeActions{source: "simulator"}
	m := New(act, "127.0.0.1:9090", []store.Flow{{
		ID: 1, Kind: store.KindHTTP, Method: "POST", URL: "https://api.test/login?access_token=s3cret&x=1", Status: 200,
		ReqHeader:  http.Header{"Authorization": {"Bearer s3cret"}, "Content-Type": {"application/json"}},
		ReqBody:    store.Body{Data: []byte(`{"user":"ana"}`), Size: 14},
		RespHeader: http.Header{"Content-Type": {"image/png"}},
		RespBody:   store.Body{Data: []byte{0x89, 'P', 'N', 'G', 0xff, 0xfe}, Size: 6},
	}})
	press(m, "enter")
	clip := func(key string) string {
		_, cmd := m.Update(tea.KeyPressMsg{Code: []rune(key)[0], Text: key})
		if cmd == nil {
			return ""
		}
		return fmt.Sprint(cmd())
	}
	if got := clip("b"); got != "" || !strings.Contains(m.status, "binary; nothing copied") {
		t.Fatalf("binary response body: %q %q", got, m.status)
	}
	if got := clip("h"); got != "Content-Type: image/png\n" {
		t.Fatalf("response headers: %q", got)
	}
	press(m, "tab")
	if got := clip("b"); got != "{\n  \"user\": \"ana\"\n}" || !strings.Contains(m.status, "copied the request body") {
		t.Fatalf("request body: %q %q", got, m.status)
	}
	if got := clip("h"); got != "Authorization: REDACTED\nContent-Type: application/json\n" || !strings.Contains(m.status, "Authorization redacted") {
		t.Fatalf("request headers: %q %q", got, m.status)
	}
	if got := clip("u"); strings.Contains(got, "s3cret") || !strings.Contains(got, "x=1") || !strings.Contains(m.status, "secrets redacted") {
		t.Fatalf("url: %q %q", got, m.status)
	}
	if got := clip("c"); !strings.HasPrefix(got, "curl ") {
		t.Fatalf("curl: %q", got)
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
	for _, want := range []string{"gzip, 35 B decoded", `"pedido": "A04FBEEB",`, `"itens": [`} {
		if !strings.Contains(out, want) {
			t.Errorf("response misses %q:\n%s", want, out)
		}
	}
	press(m, "tab")
	out += screen(m)
	for _, want := range []string{" " + long[:79] + "\n", "     " + long[79:154] + "\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("request body is not wrapped: missing %q:\n%s", want, out)
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

func TestS2_6_DeviceSetupShowsTheQRCode(t *testing.T) {
	act := &fakeActions{source: "device"}
	m := New(act, "127.0.0.1:9090", nil)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m.SetDevices(DeviceSetup{Addr: "192.168.0.12:9090", URL: "http://192.168.0.12:9090/?key=abcdefghij", Warning: "the macOS firewall blocks wraith"})
	out := screen(m)
	for _, want := range []string{"devices 192.168.0.12:9090", "Scan the code", "server 192.168.0.12  port 9090", "?key=abcdefghij", "firewall blocks wraith", "▀▀▀", "d device"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	m.Update(FlowMsg(flows()[0])) // once traffic arrives the list replaces the panel; d shows it again
	if strings.Contains(screen(m), "Scan the code") {
		t.Fatal("the panel hides the flows")
	}
	press(m, "d")
	if !strings.Contains(screen(m), "Scan the code") {
		t.Fatal("d does not show the panel")
	}
	press(m, "esc")
	if strings.Contains(screen(m), "Scan the code") {
		t.Fatal("esc does not close the panel")
	}
	if len(QR(strings.Repeat("x", 4000))) != 0 || len(QR("http://192.168.0.12:9090/?key=abcdefghij")) == 0 {
		t.Fatal("QR")
	}
}

func TestTunnelsSayWhyTheyWereNotDecrypted(t *testing.T) {
	act := &fakeActions{source: "device"}
	m := New(act, "127.0.0.1:9090", []store.Flow{
		{ID: 1, Kind: store.KindTunnel, Method: "CONNECT", URL: "wps.apple.com:443", Status: 200, Err: "passed through: on no_decrypt"},
		{ID: 2, Kind: store.KindTunnel, Method: "CONNECT", URL: "api.bank.test:443", Status: 0, Err: "rejected wraith's certificate (tls: bad certificate): the app pins, or the device does not trust the wraith CA yet; passed through for 30s, then tried again"},
		{ID: 3, Kind: store.KindTunnel, Method: "CONNECT", URL: "api.bank.test:443", Status: 200, Err: "passed through: this client rejected wraith's certificate for it a moment ago (pinned, or the CA is not trusted yet); it is tried again soon"},
	})
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 20})
	out := screen(m)
	for _, want := range []string{"wps.apple.com:443  no_decrypt", "ERR CONNECT", "api.bank.test:443  certificate rejected", "api.bank.test:443  rejected earlier, retried soon"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	press(m, "g", "enter")
	if out := screen(m); !strings.Contains(out, "why: passed through: on no_decrypt") || strings.Contains(out, "error:") {
		t.Fatalf("details:\n%s", out)
	}
}

func TestFilterSearchesBodiesAndHeaders(t *testing.T) {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write([]byte(`{"pedido":"A04FBEEB","cliente":"Ana Souza"}`))
	_ = zw.Close()
	act := &fakeActions{source: "simulator"}
	m := New(act, "127.0.0.1:9090", []store.Flow{
		{ID: 1, Kind: store.KindHTTP, Method: "GET", URL: "https://api.test/orders", Status: 200,
			RespHeader: http.Header{"Content-Encoding": {"gzip"}, "X-Trace-Id": {"t-777"}}, RespBody: store.Body{Data: z.Bytes(), Size: int64(z.Len())}},
		{ID: 2, Kind: store.KindHTTP, Method: "POST", URL: "https://api.test/login", Status: 401,
			ReqHeader: http.Header{"Content-Type": {"application/json"}}, ReqBody: store.Body{Data: []byte(`{"user":"ana"}`), Size: 14}},
		{ID: 3, Kind: store.KindTunnel, Method: "CONNECT", URL: "pinned.test:443", Status: 200},
	})
	filter := func(q string) []uint64 {
		press(m, "/")
		for range len(m.input) {
			press(m, "backspace")
		}
		typeText(m, q)
		press(m, "enter")
		var ids []uint64
		for _, i := range m.shown {
			ids = append(ids, m.flows[i].ID)
		}
		return ids
	}
	for q, want := range map[string]string{
		"body:a04fbeeb":      "[1]",   // inside a gzip body, any case
		`body:"ana souza"`:   "[1]",   // a phrase
		"b:ana":              "[1 2]", // request and response bodies
		"header:t-777":       "[1]",   // a header value
		"h:content-type":     "[2]",   // a header name
		"api.test body:user": "[2]",   // with a plain word
		"login body:pedido":  "[]",    // every term must match
		"pinned":             "[3]",   // plain words as before
	} {
		if got := fmt.Sprint(filter(q)); got != want {
			t.Errorf("%s: %s, want %s", q, got, want)
		}
	}
	filter("pinned")
	if out := screen(m); !strings.Contains(out, "filter pinned") {
		t.Errorf("header does not show the filter:\n%s", out)
	}
	press(m, "/")
	if !strings.Contains(screen(m), "body:text") {
		t.Error("the filter prompt does not explain body: and header:")
	}
}

func TestResendTheSelectedRequest(t *testing.T) {
	m, act := newModel() // the newest flow, selected, is POST http://login.test/session
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	if cmd != nil || len(act.replayed) != 0 || !strings.Contains(m.status, "r again to resend POST login.test/session") {
		t.Fatalf("a POST was resent without asking: %q", m.status)
	}
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	run(m, cmd)
	if len(act.replayed) != 1 || act.replayed[0].ID != 3 || !strings.Contains(m.status, "resent POST login.test/session: 201 in 84ms") {
		t.Fatalf("replayed %v status %q", act.replayed, m.status)
	}
	press(m, "up") // the tunnel
	if _, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"}); cmd != nil || !strings.Contains(m.status, "no request to send again") {
		t.Fatalf("tunnel: %q", m.status)
	}
	press(m, "up", "enter") // GET /cart, from the details: no question asked
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	run(m, cmd)
	if len(act.replayed) != 2 || act.replayed[1].Method != "GET" || !strings.Contains(screen(m), "resent GET api.shop.test/cart") {
		t.Fatalf("GET from the details: %v\n%s", act.replayed, screen(m))
	}
}

func TestSourcePickerListsAppsUnderTheirSimulator(t *testing.T) {
	m, act := newModel()
	act.source = "app:Shop" // an app in a simulator: its simulator's group opens
	act.choices = []Choice{
		{Source: "simulator:A", Label: "iPhone 17 Pro", Note: "iOS 26.1"},
		{Source: "app:Shop", Label: "Shop", Parent: "simulator:A", Note: "app in iPhone 17 Pro"},
		{Source: "app:Bank", Label: "Bank", Parent: "simulator:A", Note: "app in iPhone 17 Pro"},
		{Source: "app:Slack", Label: "Slack", Note: "Mac app"},
	}
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	run(m, func() tea.Cmd { _, c := m.Update(tea.KeyPressMsg{Code: 's', Text: "s"}); return c }())
	out := screen(m)
	for _, want := range []string{"▾ Simulators", "1 booted", "  iPhone 17 Pro", "▸ ●     Shop", "    Bank", "▸ Mac apps", "1 running"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Slack") {
		t.Errorf("the Mac apps group is open:\n%s", out)
	}
	press(m, "down", "enter") // Bank, in the simulator
	if act.source != "app:Bank" {
		t.Fatalf("source %q", act.source)
	}
}

func TestTabCompletesTheFilterFromWhatWasCaptured(t *testing.T) {
	m, _ := newModel()
	m.Update(FlowMsg(store.Flow{ID: 4, Kind: store.KindHTTP, Source: "device 192.168.0.23 · Bank", Method: "GET", URL: "https://api.bank.test/me", Status: 200, Route: "vpn",
		RespHeader: http.Header{"X-Request-Id": {"7"}, "X-Rate-Limit": {"9"}}}))
	press(m, "/")

	typeText(m, "pin")
	press(m, "tab") // one match: filled in, ready for the next word
	if m.input != "pinned.bank.test " {
		t.Fatalf("one match: %q", m.input)
	}

	typeText(m, "api")
	press(m, "tab") // two hosts agree as far as "api."
	if m.input != "pinned.bank.test api." || !strings.Contains(screen(m), "api.shop.test") {
		t.Fatalf("common prefix: %q\n%s", m.input, screen(m))
	}
	press(m, "tab", "tab") // then steps through them
	if m.input != "pinned.bank.test api.shop.test" || !strings.Contains(screen(m), "[api.shop.test]") {
		t.Fatalf("stepping: %q\n%s", m.input, screen(m))
	}
	press(m, "shift+tab")
	if m.input != "pinned.bank.test api.bank.test" {
		t.Fatalf("stepping back: %q", m.input)
	}

	press(m, " ")
	typeText(m, "Ba")
	press(m, "tab") // the app part of a source
	if !strings.HasSuffix(m.input, " Bank ") {
		t.Fatalf("app: %q", m.input)
	}
	typeText(m, "iphone")
	press(m, "tab") // not a prefix of anything, so what contains it; spaces are quoted
	if !strings.HasSuffix(m.input, ` "sim iPhone 17 · Shop" `) {
		t.Fatalf("source: %q", m.input)
	}
	typeText(m, "h:x-r")
	press(m, "tab") // x-rate-limit and x-request-id agree only as far as typed: the first is shown
	if !strings.HasSuffix(m.input, " h:x-rate-limit") {
		t.Fatalf("header: %q", m.input)
	}
	press(m, "enter")
	if len(m.shown) != 0 { // no single flow is both bank hosts
		t.Fatalf("filter %q shows %v", m.filter, m.shown)
	}

	press(m, "/")
	for range len(m.input) {
		press(m, "backspace")
	}
	typeText(m, "zzz")
	press(m, "tab")
	if m.input != "zzz" || !strings.Contains(screen(m), `nothing captured matches "zzz"`) {
		t.Fatalf("no match: %q\n%s", m.input, screen(m))
	}
	press(m, "backspace")
	if strings.Contains(screen(m), "nothing captured") {
		t.Fatal("the note outlived the next key")
	}
}

func TestTimingTabShowsTheWaterfall(t *testing.T) {
	act := &fakeActions{source: "simulator"}
	f := store.Flow{ID: 1, Kind: store.KindHTTP, Method: "GET", URL: "https://api.test/slow", Status: 200, Duration: 400 * time.Millisecond,
		Throttle: "3g", Timing: store.Timing{Known: true, Blocked: 100 * time.Millisecond, DNS: 10 * time.Millisecond, Connect: 20 * time.Millisecond,
			TLS: 30 * time.Millisecond, Send: time.Millisecond, Wait: 200 * time.Millisecond, Receive: 39 * time.Millisecond}}
	mocked := store.Flow{ID: 2, Kind: store.KindHTTP, Method: "GET", URL: "https://api.test/cart", Status: 503, Route: "mock", Mock: "GET https://api.test/cart"}
	m := New(act, "127.0.0.1:9090", []store.Flow{f, mocked})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	press(m, "up", "enter", "3")
	out := screen(m)
	for _, want := range []string{" Timing ", "total 400ms", "blocked     100ms", "3g latency", "dns          10ms", "tls          30ms",
		"wait        200ms", "server, to first byte", "receive      39ms", "throttled 3g"} {
		if !strings.Contains(out, want) {
			t.Errorf("timing misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, " Messages ") {
		t.Error("a plain request has a Messages tab")
	}
	press(m, "tab") // Timing → Response, wrapping around
	if m.tabOf(f) != tabResponse {
		t.Fatalf("tab after Timing: %d", m.tab)
	}
	press(m, "esc", "down", "enter", "3")
	if out := screen(m); !strings.Contains(out, "answered by the mock GET https://api.test/cart") || !strings.Contains(out, "mocked") {
		t.Errorf("a mocked flow's timing:\n%s", out)
	}
}

func TestMessagesTabFollowsAWebSocket(t *testing.T) {
	act := &fakeActions{source: "simulator"}
	t0 := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	ws := store.Flow{ID: 1, Kind: store.KindHTTP, Method: "GET", URL: "https://chat.test/live", Status: 101}
	m := New(act, "127.0.0.1:9090", []store.Flow{ws})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	press(m, "enter", "4")
	if out := screen(m); !strings.Contains(out, " Messages 0 ") || !strings.Contains(out, "none yet") {
		t.Fatalf("before any message:\n%s", out)
	}
	ws.Messages = []store.Message{
		{At: t0, FromClient: true, Op: "text", Data: []byte(`{"op":"join","room":"cart"}`), Size: 27},
		{At: t0.Add(time.Second), Op: "binary", Data: []byte{0, 1, 2}, Size: 3},
		{At: t0.Add(2 * time.Second), Op: "text", Note: "compressed; not decoded", Size: 900},
		{At: t0.Add(3 * time.Second), Op: "close", Data: append([]byte{0x03, 0xe8}, "bye"...), Size: 5},
	}
	ws.MessagesDropped = 2
	m.Update(FlowMsg(ws)) // the same flow, with messages: an update, not a new row
	if len(m.flows) != 1 {
		t.Fatalf("an update added a row: %d flows", len(m.flows))
	}
	out := screen(m)
	for _, want := range []string{" Messages 6 ", "4 · 2 older let go", `12:00:00.000 ↑ text   {"op":"join","room":"cart"}`, "↓ binary 3 B",
		"compressed; not decoded · 900 B", "↓ close  1000 normal: bye"} {
		if !strings.Contains(out, want) {
			t.Errorf("messages miss %q:\n%s", want, out)
		}
	}
	press(m, "esc", "/")
	typeText(m, "body:room")
	press(m, "enter")
	if len(m.shown) != 1 {
		t.Fatal("body: does not search a WebSocket's messages")
	}
}

func TestTCyclesThrottleAndMMocks(t *testing.T) {
	m, act := newModel()
	press(m, "t")
	if act.throttle != "lte" || !strings.Contains(m.status, "like lte") || !strings.Contains(screen(m), "throttle lte") {
		t.Fatalf("t: %q %q", act.throttle, m.status)
	}
	press(m, "t", "t", "t", "t")
	if act.throttle != "" || !strings.Contains(m.status, "throttle off") || strings.Contains(m.header(), "throttle") {
		t.Fatalf("t around to off: %q %q", act.throttle, m.status)
	}
	press(m, "up", "up", "m") // GET /cart
	if len(act.mocked) != 1 || act.mocked[0].ID != 1 || !strings.Contains(m.status, "mocking GET https://api.shop.test/cart") || !strings.Contains(screen(m), "1 mock") {
		t.Fatalf("m: %+v %q", act.mocked, m.status)
	}
}

func gqlFlow(id uint64, op, vars, resp string) store.Flow {
	f := store.Flow{ID: id, Kind: store.KindHTTP, Method: "POST", URL: "https://api.shop.test/graphql", Status: 200,
		ReqHeader:  http.Header{"Content-Type": {"application/json"}},
		ReqBody:    store.Body{Data: []byte(`{"operationName":"` + op + `","query":"query ` + op + `($id: ID!) {\n  cart(id: $id) { total }\n}","variables":` + vars + `}`)},
		RespHeader: http.Header{"Content-Type": {"application/json"}},
		RespBody:   store.Body{Data: []byte(resp)}}
	f.SetGraphQL()
	return f
}

func TestGraphQLRowsFilterAndQuery(t *testing.T) {
	m := New(&fakeActions{source: "simulator"}, "127.0.0.1:9090", []store.Flow{
		gqlFlow(1, "GetCart", `{"id":"7"}`, `{"data":{"cart":{"total":1}}}`),
		gqlFlow(2, "GetUser", `{"id":"9"}`, `{"errors":[{"message":"nope"}]}`),
	})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	out := screen(m)
	if !strings.Contains(out, "https://api.shop.test/graphql  query GetCart") || !strings.Contains(out, "query GetUser  ✗ 1 error") {
		t.Fatalf("rows:\n%s", out)
	}
	press(m, "/")
	typeText(m, "op:getc")
	press(m, "enter")
	if len(m.shown) != 1 || m.flows[m.shown[0]].ID != 1 {
		t.Fatalf("op: shows %v", m.shown)
	}
	press(m, "esc", "/")
	typeText(m, "op:Get")
	press(m, "tab") // completes operation names
	if m.input != "op:GetCart" && m.input != "op:GetUser" {
		t.Fatalf("op: completion: %q", m.input)
	}
	press(m, "esc", "enter", "2")
	out = screen(m)
	for _, want := range []string{"GraphQL query GetUser  ✗ 1 error in the response", " Query query GetUser ", "query GetUser($id: ID!) {", "cart(id: $id) { total }", " Variables ", `"id": "9"`} {
		if !strings.Contains(out, want) {
			t.Errorf("request tab misses %q:\n%s", want, out)
		}
	}
}

func TestEqualsComparesTwoRequests(t *testing.T) {
	a := gqlFlow(1, "GetCart", `{"id":"7"}`, `{"data":{"cart":{"total":1,"currency":"BRL"}}}`)
	b := gqlFlow(2, "GetCart", `{"id":"8"}`, `{"data":{"cart":{"currency":"BRL","total":2}}}`)
	b.ReqHeader.Set("Authorization", "Bearer x")
	tun := store.Flow{ID: 3, Kind: store.KindTunnel, Method: "CONNECT", URL: "x.test:443", Status: 200}
	m := New(&fakeActions{source: "simulator"}, "127.0.0.1:9090", []store.Flow{a, b, tun})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 50})
	press(m, "=")
	if m.cmp.mark != 0 || !strings.Contains(m.status, "tunnel") {
		t.Fatalf("a tunnel was marked: %q", m.status)
	}
	press(m, "up", "up", "=")
	if m.cmp.mark != 1 || !strings.Contains(screen(m), "◆") && !strings.Contains(m.status, "marked") {
		t.Fatalf("mark: %d %q", m.cmp.mark, m.status)
	}
	press(m, "down", "=")
	if m.mode != modeCompare {
		t.Fatal("= on a second request did not compare")
	}
	out := screen(m)
	for _, want := range []string{" compare ", " A POST https://api.shop.test/graphql", " B POST", "line same", "operation same",
		"headers 1 line differ", "+ Authorization: Bearer x", "status same"} {
		if !strings.Contains(out, want) {
			t.Errorf("compare misses %q:\n%s", want, out)
		}
	}
	diffLine := func(sign, text string) bool { // the JSON keeps its indentation after the sign
		for l := range strings.SplitSeq(out, "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(l), sign+" "); ok && strings.TrimSpace(rest) == text {
				return true
			}
		}
		return false
	}
	for _, d := range [][2]string{{"-", `"id": "7"`}, {"+", `"id": "8"`}, {"-", `"total": 1`}, {"+", `"total": 2`}} {
		if !diffLine(d[0], d[1]) {
			t.Errorf("compare misses %s %s:\n%s", d[0], d[1], out)
		}
	}
	if diffLine("+", `"currency": "BRL",`) || diffLine("-", `"currency": "BRL",`) {
		t.Errorf("key order showed as a difference:\n%s", out)
	}
	press(m, "s")
	if out := screen(m); !strings.Contains(out, "- Authorization: Bearer x") {
		t.Errorf("s did not swap A and B:\n%s", out)
	}
	press(m, "esc")
	if m.mode != modeList || m.cmp.mark != 1 {
		t.Fatalf("esc: mode %d mark %d", m.mode, m.cmp.mark)
	}
	press(m, "up", "=")
	if m.cmp.mark != 0 {
		t.Fatal("= on the marked request did not unmark it")
	}
}

func TestDiffLinesAndCollapse(t *testing.T) {
	a := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	b := []string{"a", "b", "c", "D", "e", "f", "g", "h", "i"}
	var got []string
	for _, o := range collapse(diffLines(a, b), 1) {
		got = append(got, string(o.kind)+o.text)
	}
	want := []string{"~… 2 same lines", " c", "-d", "+D", " e", "~… 2 same lines", " h", "+i"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if ops := diffLines(nil, nil); len(ops) != 0 {
		t.Fatalf("empty: %v", ops)
	}
	// Past maxDiffCells the middle is not matched line by line: A's lines out, B's in.
	var x, y []string
	for i := range 3000 {
		x, y = append(x, fmt.Sprint("a", i)), append(y, fmt.Sprint("b", i))
	}
	ops := diffLines(x, y)
	if len(ops) != 6000 || ops[0].kind != '-' || ops[2999].kind != '-' || ops[3000].kind != '+' {
		t.Fatalf("big diff: %d ops", len(ops))
	}
}
