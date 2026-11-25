// Package tui is wraith's live view: a list of captured flows that updates as traffic
// arrives, with a filter, a detail view, a source picker, and keys for the common
// actions. It draws in Heliotrope Haze, or in the terminal's own palette.
package tui

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/esuEdu/wraith/internal/export"
	"github.com/esuEdu/wraith/internal/store"
)

// Actions is what the view can ask of the running wraith.
type Actions interface {
	Source() string
	SetSource(s string) error // new connections only (R1.5)
	// Choices lists the booted simulators and running Mac apps for the source picker.
	// It may be slow (simctl), so the view calls it off the UI loop.
	Choices() ([]Choice, error)
	Bypass(host string) error
	NoDecrypt(host string) error
	Curl(f store.Flow) string
	// Redactor hides secrets in the headers and URLs the details copy, as exports do.
	Redactor() export.Redactor
	ExportHAR() (path string, err error)
	Clear()
	// Replay sends a captured request again through the proxy's route and returns the
	// new flow. It may be slow (the upstream answers); the view calls it off the UI loop.
	Replay(f store.Flow) (store.Flow, error)
}

// replayMsg delivers what Replay did.
type replayMsg struct {
	orig, f store.Flow
	err     error
}

// Choice is one entry in the source picker.
type Choice struct {
	Source string // what SetSource gets, e.g. "simulator:<udid>" or "app:Safari"
	Label  string // what the picker and the header show, e.g. "iPhone 17 Pro"
	Note   string // e.g. "iOS 26.1 · CA installed"
	// Parent is the source this one is listed under, e.g. an app under the simulator it
	// runs in ("simulator:<udid>"); empty for a source of its own.
	Parent string
}

type mode int

const (
	modeList mode = iota
	modeDetail
	modeFilter
	modeSource
)

// FlowMsg delivers a newly captured flow.
type FlowMsg store.Flow

// NoticeMsg shows a message from the proxy or the simulator watcher in the status line.
type NoticeMsg string

// DeviceSetup is how an iPhone or iPad reaches wraith (S2.6), for the setup panel.
type DeviceSetup struct {
	Addr    string // ip:port, the proxy the device sets
	URL     string // the setup link with its key, shown as a QR code
	Warning string // why devices may not get through, e.g. the firewall
}

// choicesMsg delivers what Actions.Choices found.
type choicesMsg struct {
	list []Choice
	err  error
}

// Model is the live view.
type Model struct {
	act    Actions
	listen string

	flows    []store.Flow
	shown    []int // indexes into flows that pass the filter
	cursor   int   // index into shown
	offset   int   // first row of shown on screen
	follow   bool  // keep the newest flow selected
	filter   string
	terms    []term            // the filter, parsed
	bodies   map[uint64]string // decoded bodies in lower case, for body: terms
	input    string            // text being typed for the filter or the source
	comp     completion        // tab in the filter
	mode     mode
	detailAt int // first line of the detail view on screen
	tab      int // tabResponse or tabRequest
	detail   struct {
		at, width, tab int // the flow (index into flows), width and tab the lines were built for
		lines          []string
	}
	confirm struct { // r on a request that may change data asks once more
		id uint64
		at time.Time
	}
	pick   picker
	labels map[string]string // source → the name the picker showed for it

	dev     DeviceSetup // zero without --device
	showDev bool        // the setup panel is open (d)

	t             *theme
	width, height int
	status        string
	statusAt      time.Time
}

// New returns a Model showing flows (oldest first) for a proxy listening on listen.
func New(act Actions, listen string, flows []store.Flow) *Model {
	m := &Model{act: act, listen: listen, flows: flows, follow: true, width: 100, height: 30, labels: map[string]string{}, bodies: map[uint64]string{}}
	m.t, _ = themeNamed(DefaultTheme)
	m.refilter()
	return m
}

// SetTheme switches to one of Themes.
func (m *Model) SetTheme(name string) error {
	t, ok := themeNamed(name)
	if !ok {
		return fmt.Errorf("theme %q must be one of %s", name, strings.Join(Themes, ", "))
	}
	m.t, m.detail.lines = t, nil
	return nil
}

// SetDevices turns on the device setup panel (d).
func (m *Model) SetDevices(d DeviceSetup) { m.dev = d }

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case FlowMsg:
		if n := len(m.flows); n > 0 && msg.ID != 0 && msg.ID <= m.flows[n-1].ID {
			break // already in the snapshot the view started with
		}
		m.flows = append(m.flows, store.Flow(msg))
		m.refilter()
	case NoticeMsg:
		m.say(string(msg))
	case choicesMsg:
		m.pickerLoaded(msg)
	case replayMsg:
		m.replayed(msg)
	case tea.KeyPressMsg:
		return m.key(msg)
	case tea.MouseMsg:
		if m.mode == modeSource {
			return m, m.pickerMouse(msg)
		}
	}
	return m, nil
}

func (m *Model) say(s string) { m.status, m.statusAt = s, time.Now() }

func (m *Model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	switch m.mode {
	case modeFilter:
		return m.typing(k)
	case modeSource:
		return m.picking(k)
	case modeDetail:
		switch key {
		case "esc", "q", "enter", "backspace":
			m.mode = modeList
		case "tab", "shift+tab", "left", "right":
			m.tab, m.detailAt = 1-m.tab, 0
		case "1":
			m.tab, m.detailAt = tabResponse, 0
		case "2":
			m.tab, m.detailAt = tabRequest, 0
		case "down", "j":
			m.detailAt++
		case "up", "k":
			m.detailAt = max(0, m.detailAt-1)
		case "pgdown", "space":
			m.detailAt += m.rows()
		case "pgup":
			m.detailAt = max(0, m.detailAt-m.rows())
		case "g", "home":
			m.detailAt = 0
		case "G", "end":
			m.detailAt = len(m.detail.lines) // clamped when drawn
		case "c":
			return m, m.copyCurl()
		case "r":
			return m, m.replay()
		case "b":
			return m, m.copyBody()
		case "h":
			return m, m.copyHeaders()
		case "u":
			return m, m.copyURL()
		case "ctrl+c":
			return m, tea.Quit
		}
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "d":
		m.showDev = !m.showDev && m.dev.Addr != ""
	case "down", "j":
		m.move(1)
	case "up", "k":
		m.move(-1)
	case "pgdown":
		m.move(m.rows())
	case "pgup":
		m.move(-m.rows())
	case "g", "home":
		m.move(-len(m.shown))
	case "G", "end":
		m.move(len(m.shown))
	case "enter", "right", "l":
		if _, ok := m.selected(); ok {
			m.mode, m.detailAt = modeDetail, 0
		}
	case "/":
		m.mode, m.input, m.comp = modeFilter, m.filter, completion{}
	case "esc":
		if m.showDev {
			m.showDev = false
		} else if m.filter != "" {
			m.filter, m.terms = "", nil
			m.refilter()
		}
	case "s":
		return m, m.openPicker()
	case "b":
		m.hostAction("bypass", m.act.Bypass)
	case "n":
		m.hostAction("no-decrypt", m.act.NoDecrypt)
	case "c":
		return m, m.copyCurl()
	case "r":
		return m, m.replay()
	case "e":
		if p, err := m.act.ExportHAR(); err != nil {
			m.say("export failed: " + err.Error())
		} else {
			m.say("exported to " + p + " (secrets redacted)")
		}
	case "x":
		m.act.Clear()
		m.flows, m.shown, m.cursor, m.offset, m.follow = nil, nil, 0, 0, true
		m.bodies = map[uint64]string{}
		m.detail.lines = nil
		m.refilter()
		m.say("cleared")
	}
	return m, nil
}

// typing handles the filter prompt.
func (m *Model) typing(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "tab":
		m.complete(1)
		return m, nil
	case "shift+tab":
		m.complete(-1)
		return m, nil
	}
	m.comp = completion{}
	switch k.String() {
	case "esc":
		m.mode = modeList
	case "enter":
		m.filter = strings.TrimSpace(m.input)
		m.terms = parseFilter(m.filter)
		m.refilter()
		m.mode = modeList
	case "ctrl+c":
		return m, tea.Quit
	default:
		m.edit(k)
	}
	return m, nil
}

// edit applies a key to the text being typed: backspace, or a printable key.
func (m *Model) edit(k tea.KeyPressMsg) bool {
	if k.String() == "backspace" {
		if _, size := utf8.DecodeLastRuneInString(m.input); size > 0 {
			m.input = m.input[:len(m.input)-size]
			return true
		}
		return false
	}
	if k.Text != "" {
		m.input += k.Text
		return true
	}
	return false
}

// setSource switches the capture source and says so.
func (m *Model) setSource(s string) bool {
	if err := m.act.SetSource(s); err != nil {
		m.say(err.Error())
		return false
	}
	m.say("capturing " + m.sourceName() + " for new connections")
	return true
}

// sourceName is the current source as the picker named it ("iPhone 17 Pro" rather than
// "simulator:<udid>"), or as wraith spells it.
func (m *Model) sourceName() string {
	s := m.act.Source()
	if l, ok := m.labels[s]; ok {
		return l
	}
	return s
}

// replay sends the selected request again. A method that may change data on the server
// (anything but GET, HEAD, OPTIONS) asks for a second r within a few seconds.
func (m *Model) replay() tea.Cmd {
	f, ok := m.selected()
	if !ok {
		return nil
	}
	if f.Kind != store.KindHTTP {
		m.say("a tunnel was not decrypted: there is no request to send again")
		return nil
	}
	switch f.Method {
	case "GET", "HEAD", "OPTIONS":
	default:
		if m.confirm.id != f.ID || time.Since(m.confirm.at) > 4*time.Second {
			m.confirm.id, m.confirm.at = f.ID, time.Now()
			m.say("r again to resend " + f.Method + " " + shortURL(f.URL) + ": it may change data on the server")
			return nil
		}
	}
	m.confirm.id = 0
	m.say("resending " + f.Method + " " + shortURL(f.URL) + "…")
	act := m.act
	return func() tea.Msg {
		nf, err := act.Replay(f)
		return replayMsg{orig: f, f: nf, err: err}
	}
}

func (m *Model) replayed(msg replayMsg) {
	what := msg.orig.Method + " " + shortURL(msg.orig.URL)
	switch {
	case msg.f.ID == 0 && msg.err != nil:
		m.say("could not resend " + what + ": " + msg.err.Error())
	case msg.err != nil || msg.f.Status == 0 || msg.f.Status >= 500 && msg.f.Err != "":
		m.say("resent " + what + ": no answer (" + msg.f.Err + "); it is the newest row")
	default:
		m.say(fmt.Sprintf("resent %s: %d in %s; it is the newest row", what, msg.f.Status, msg.f.Duration.Round(time.Millisecond)))
	}
}

// shortURL is a URL without its scheme and query, for status messages.
func shortURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if len(u) > 60 {
		u = u[:59] + "…"
	}
	return u
}

func (m *Model) hostAction(what string, do func(string) error) {
	f, ok := m.selected()
	if !ok {
		return
	}
	host := flowHost(f)
	if host == "" {
		return
	}
	if err := do(host); err != nil {
		m.say(what + " " + host + ": " + err.Error())
		return
	}
	m.say("added " + host + " to " + what + " (saved to config.yaml; applies to new connections)")
}

func (m *Model) selected() (store.Flow, bool) {
	if m.cursor < 0 || m.cursor >= len(m.shown) || m.shown[m.cursor] >= len(m.flows) {
		return store.Flow{}, false
	}
	return m.flows[m.shown[m.cursor]], true
}

func (m *Model) move(d int) {
	m.cursor = min(max(m.cursor+d, 0), max(len(m.shown)-1, 0))
	m.follow = m.cursor == len(m.shown)-1
}

// rows is how many flows fit on screen: all but the header, two rules and the footer.
func (m *Model) rows() int { return max(m.height-4, 1) }

// refilter recomputes the visible flows, keeping the selection on the newest flow when
// following and on the same flow otherwise.
func (m *Model) refilter() {
	var keep uint64
	if f, ok := m.selected(); ok && !m.follow {
		keep = f.ID
	}
	m.shown = m.shown[:0]
	for i, f := range m.flows {
		if m.matches(f) {
			m.shown = append(m.shown, i)
		}
	}
	switch {
	case m.follow || keep == 0:
		m.cursor = max(len(m.shown)-1, 0)
	default:
		for i, idx := range m.shown {
			if m.flows[idx].ID == keep {
				m.cursor = i
			}
		}
	}
	m.cursor = min(m.cursor, max(len(m.shown)-1, 0))
}

// containsWords reports whether every word of query appears in hay (already lower case).
func containsWords(hay, query string) bool {
	for w := range strings.FieldsSeq(strings.ToLower(query)) {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// flowHost is the host a flow went to, for bypass and no-decrypt.
func flowHost(f store.Flow) string {
	if f.Kind == store.KindTunnel {
		h, _, err := net.SplitHostPort(f.URL)
		if err != nil {
			return f.URL
		}
		return h
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
