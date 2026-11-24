// Package tui is wraith's live view: a list of captured flows that updates as traffic
// arrives, with a filter, a detail view, and keys for the common actions.
package tui

import (
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/esuEdu/wraith/internal/store"
)

// Actions is what the view can ask of the running wraith.
type Actions interface {
	Source() string
	SetSource(s string) error // new connections only (R1.5)
	Bypass(host string) error
	NoDecrypt(host string) error
	Curl(f store.Flow) string
	ExportHAR() (path string, err error)
	Clear()
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
	input    string // text being typed for the filter or the source
	mode     mode
	detailAt int // first line of the detail view on screen

	width, height int
	status        string
	statusAt      time.Time
}

// New returns a Model showing flows (oldest first) for a proxy listening on listen.
func New(act Actions, listen string, flows []store.Flow) *Model {
	m := &Model{act: act, listen: listen, flows: flows, follow: true, width: 100, height: 30}
	m.refilter()
	return m
}

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
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *Model) say(s string) { m.status, m.statusAt = s, time.Now() }

func (m *Model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	switch m.mode {
	case modeFilter, modeSource:
		return m.typing(k)
	case modeDetail:
		switch key {
		case "esc", "q", "enter", "left", "h":
			m.mode = modeList
		case "down", "j":
			m.detailAt++
		case "up", "k":
			m.detailAt = max(0, m.detailAt-1)
		case "pgdown", "space":
			m.detailAt += m.rows()
		case "pgup":
			m.detailAt = max(0, m.detailAt-m.rows())
		case "c":
			return m, m.copyCurl()
		case "ctrl+c":
			return m, tea.Quit
		}
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
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
		m.mode, m.input = modeFilter, m.filter
	case "esc":
		if m.filter != "" {
			m.filter = ""
			m.refilter()
		}
	case "s":
		m.mode, m.input = modeSource, m.act.Source()
	case "b":
		m.hostAction("bypass", m.act.Bypass)
	case "n":
		m.hostAction("no-decrypt", m.act.NoDecrypt)
	case "c":
		return m, m.copyCurl()
	case "e":
		if p, err := m.act.ExportHAR(); err != nil {
			m.say("export failed: " + err.Error())
		} else {
			m.say("exported to " + p + " (secrets redacted)")
		}
	case "x":
		m.act.Clear()
		m.flows, m.shown, m.cursor, m.offset, m.follow = nil, nil, 0, 0, true
		m.refilter()
		m.say("cleared")
	}
	return m, nil
}

// typing handles the filter and source prompts.
func (m *Model) typing(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.mode = modeList
	case "enter":
		if m.mode == modeFilter {
			m.filter = strings.TrimSpace(m.input)
			m.refilter()
		} else if err := m.act.SetSource(strings.TrimSpace(m.input)); err != nil {
			m.say(err.Error())
			return m, nil
		} else {
			m.say("capturing " + m.act.Source() + " for new connections")
		}
		m.mode = modeList
	case "backspace":
		if _, size := utf8.DecodeLastRuneInString(m.input); size > 0 {
			m.input = m.input[:len(m.input)-size]
		}
	case "ctrl+c":
		return m, tea.Quit
	default:
		if k.Text != "" {
			m.input += k.Text
		}
	}
	return m, nil
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

func (m *Model) copyCurl() tea.Cmd {
	f, ok := m.selected()
	if !ok {
		return nil
	}
	if f.Kind != store.KindHTTP {
		m.say("a tunnel has no request to copy (it was not decrypted)")
		return nil
	}
	m.say("copied the request as curl (secrets redacted)")
	return tea.SetClipboard(m.act.Curl(f))
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

// rows is how many flows fit on screen.
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
		if matches(f, m.filter) {
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

// matches reports whether every word of filter appears in the flow's summary.
func matches(f store.Flow, filter string) bool {
	if filter == "" {
		return true
	}
	hay := strings.ToLower(fmt.Sprintf("%s %s %s %d %s %s %s", f.Source, f.Method, f.URL, f.Status, f.Route, f.Kind, f.Err))
	for w := range strings.FieldsSeq(strings.ToLower(filter)) {
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

var (
	dim    = lipgloss.NewStyle().Faint(true)
	bold   = lipgloss.NewStyle().Bold(true)
	invert = lipgloss.NewStyle().Reverse(true)
	ok     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	warn   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	bad    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

// View implements tea.Model.
func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "wraith"
	return v
}

func (m *Model) render() string {
	if m.mode == modeDetail {
		if f, ok := m.selected(); ok {
			return m.renderDetail(f)
		}
	}
	var b strings.Builder
	head := fmt.Sprintf(" wraith · %s · capturing %s · %d flows", m.listen, m.act.Source(), len(m.flows))
	if m.filter != "" {
		head += fmt.Sprintf(" · filter %q (%d shown)", m.filter, len(m.shown))
	}
	b.WriteString(bold.Render(clip(head, m.width)) + "\n")

	rows := m.rows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	if len(m.shown) == 0 {
		b.WriteString(dim.Render(" waiting for traffic from the capture source…") + "\n")
	}
	for i := m.offset; i < min(m.offset+rows, len(m.shown)); i++ {
		line := m.row(m.flows[m.shown[i]])
		if i == m.cursor {
			line = invert.Render(clip(line, m.width))
		}
		b.WriteString(line + "\n")
	}
	for i := len(m.shown) - m.offset; i < rows; i++ {
		b.WriteString("\n")
	}
	b.WriteString(m.footer())
	return b.String()
}

func (m *Model) row(f store.Flow) string {
	status := fmt.Sprintf("%3d", f.Status)
	style := ok
	switch {
	case f.Kind == store.KindTunnel && f.Status == 200:
		status, style = "tun", dim
	case f.Status == 0 || f.Status >= 500:
		style = bad
	case f.Status >= 400:
		style = warn
	}
	src := fmt.Sprintf("%-20.20s", f.Source)
	line := fmt.Sprintf(" %s %s %s %-7.7s %-6s ", f.Start.Format("15:04:05"), src, style.Render(status), f.Method, f.Route)
	return clip(line+f.URL, m.width)
}

func (m *Model) footer() string {
	switch m.mode {
	case modeFilter:
		return bold.Render(" filter: ") + m.input + "▏" + dim.Render("  enter apply · esc cancel")
	case modeSource:
		return bold.Render(" source: ") + m.input + "▏" + dim.Render("  all · simulator[:udid|name] · app:<name|id> · pid:<n> · enter apply · esc cancel")
	}
	help := " ↑↓ move · enter details · / filter · s source · b bypass · n no-decrypt · c copy curl · e export · x clear · q quit"
	if m.status != "" && time.Since(m.statusAt) < 8*time.Second {
		return clip(" "+m.status, m.width)
	}
	return dim.Render(clip(help, m.width))
}

func (m *Model) renderDetail(f store.Flow) string {
	var lines []string
	add := func(s string) { lines = append(lines, s) }
	add(bold.Render(fmt.Sprintf(" %s %s", f.Method, f.URL)))
	add(fmt.Sprintf(" status %d · %s · %s · route %s · source %s · %s",
		f.Status, f.Proto, f.Duration.Round(time.Millisecond), f.Route, f.Source, f.Start.Format("15:04:05.000")))
	if f.Err != "" {
		add(bad.Render(" error: " + f.Err))
	}
	if f.Kind == store.KindTunnel {
		add("")
		add(dim.Render(" passed through without decrypting: no headers or bodies to show"))
	} else {
		section := func(title string, h map[string][]string, body store.Body) {
			add("")
			add(bold.Render(" " + title))
			for _, k := range sortedKeys(h) {
				for _, v := range h[k] {
					add(" " + k + ": " + v)
				}
			}
			add("")
			add(" " + bodySummary(body))
			if len(body.Data) > 0 && utf8.Valid(body.Data) {
				for l := range strings.SplitSeq(string(body.Data), "\n") {
					add(" " + l)
				}
			}
		}
		section("request", f.ReqHeader, f.ReqBody)
		section("response", f.RespHeader, f.RespBody)
	}
	rows := max(m.height-2, 1)
	m.detailAt = min(m.detailAt, max(len(lines)-rows, 0))
	var b strings.Builder
	for i := m.detailAt; i < min(m.detailAt+rows, len(lines)); i++ {
		b.WriteString(clip(lines[i], m.width) + "\n")
	}
	for i := min(m.detailAt+rows, len(lines)) - m.detailAt; i < rows; i++ {
		b.WriteString("\n")
	}
	if m.status != "" && time.Since(m.statusAt) < 8*time.Second {
		b.WriteString(clip(" "+m.status, m.width))
	} else {
		b.WriteString(dim.Render(" ↑↓ scroll · c copy curl · esc back"))
	}
	return b.String()
}

func bodySummary(b store.Body) string {
	switch {
	case b.Size == 0:
		return dim.Render("(no body)")
	case !utf8.Valid(b.Data):
		return dim.Render(fmt.Sprintf("(binary, %d bytes)", b.Size))
	case b.Truncated:
		return dim.Render(fmt.Sprintf("(%d bytes, first %d shown)", b.Size, len(b.Data)))
	}
	return dim.Render(fmt.Sprintf("(%d bytes)", b.Size))
}

func sortedKeys(h map[string][]string) []string { return slices.Sorted(maps.Keys(h)) }

// clip cuts s to width display cells (ANSI styles are measured by lipgloss).
func clip(s string, width int) string {
	if width <= 0 || lipgloss.Width(s) <= width {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r)) > width-1 {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}
