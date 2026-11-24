package tui

import (
	"net/http"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/esuEdu/wraith/internal/source"
	"github.com/esuEdu/wraith/internal/store"
)

type fakeActions struct {
	source              string
	bypassed, noDecrypt []string
	exported, cleared   int
}

func (f *fakeActions) Source() string { return f.source }
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
	out := m.View().Content
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
	out := m.View().Content
	for _, want := range []string{"GET https://api.shop.test/cart", "Accept: application/json", `{"items":[]}`, "route vpn"} {
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
	press(m, "s") // pre-filled with the current source
	for range len("app:Safari") {
		press(m, "backspace")
	}
	typeText(m, "bogus")
	press(m, "enter")
	if act.source != "app:Safari" || !strings.Contains(m.status, "must be all") {
		t.Fatalf("invalid source accepted: %q %q", act.source, m.status)
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
	if act.cleared != 1 || len(m.flows) != 0 || !strings.Contains(m.View().Content, "waiting for traffic") {
		t.Fatal("clear did not empty the list")
	}
}

func TestQuitAndNotices(t *testing.T) {
	m, _ := newModel()
	m.Update(NoticeMsg("simulator iPhone 17: installed the wraith CA"))
	if !strings.Contains(m.View().Content, "installed the wraith CA") {
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
