package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/esuEdu/wraith/internal/store"
)

// The theme uses only the terminal's 16 ANSI colors plus bold, faint and reverse, never
// fixed RGB values, so wraith looks like the rest of the terminal in any light or dark
// theme. Cyan is the accent.
var (
	dim        = lipgloss.NewStyle().Faint(true)
	bold       = lipgloss.NewStyle().Bold(true)
	accent     = lipgloss.NewStyle().Foreground(lipgloss.Cyan)
	accentBold = accent.Bold(true)
	badge      = lipgloss.NewStyle().Bold(true).Reverse(true).Foreground(lipgloss.Cyan)
	selected   = lipgloss.NewStyle().Reverse(true)
	ok         = lipgloss.NewStyle().Foreground(lipgloss.Green)
	warn       = lipgloss.NewStyle().Foreground(lipgloss.Yellow)
	bad        = lipgloss.NewStyle().Foreground(lipgloss.Red)
	direct     = lipgloss.NewStyle().Foreground(lipgloss.Magenta)
)

// View implements tea.Model.
func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "wraith · " + m.sourceName()
	return v
}

func (m *Model) render() string {
	switch m.mode {
	case modeDetail:
		if f, ok := m.selected(); ok {
			return m.renderDetail(f)
		}
	case modeSource:
		return m.renderPicker()
	}
	var b strings.Builder
	b.WriteString(m.header() + "\n" + m.rule() + "\n")

	rows := m.rows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	lines := 0
	if len(m.shown) == 0 {
		msg := " waiting for traffic from " + m.sourceName() + "…"
		if m.filter != "" {
			msg = " no flow matches the filter; esc clears it"
		}
		b.WriteString(dim.Render(msg) + "\n")
		lines++
	}
	for i := m.offset; i < min(m.offset+rows, len(m.shown)); i++ {
		b.WriteString(m.row(m.flows[m.shown[i]], i == m.cursor) + "\n")
		lines++
	}
	b.WriteString(strings.Repeat("\n", max(rows-lines, 0)))
	b.WriteString(m.rule() + "\n")
	b.WriteString(m.footer())
	return b.String()
}

// header is the top line: name, address, source, flow count and filter.
func (m *Model) header() string {
	sep := dim.Render(" · ")
	h := badge.Render(" wraith ") + " " + dim.Render(m.listen) + sep +
		"capturing " + accentBold.Render(m.sourceName()) + sep + fmt.Sprintf("%d flows", len(m.flows))
	if m.filter != "" {
		h += sep + "filter " + accentBold.Render(m.filter) + dim.Render(fmt.Sprintf(" (%d shown)", len(m.shown)))
	}
	return clip(h, m.width)
}

func (m *Model) rule() string { return dim.Render(strings.Repeat("─", max(m.width, 1))) }

// row is one flow in the list; the selected one is drawn in reverse video across the
// screen, with an accent bar in front.
func (m *Model) row(f store.Flow, sel bool) string {
	status := fmt.Sprintf("%3d", f.Status)
	stStyle := ok
	switch {
	case f.Kind == store.KindTunnel && f.Status == 200:
		status, stStyle = "tun", dim
	case f.Status == 0:
		status, stStyle = "ERR", bad
	case f.Status >= 500:
		stStyle = bad
	case f.Status >= 400:
		stStyle = warn
	}
	routeStyle := dim
	switch f.Route {
	case "direct":
		routeStyle = direct
	case "failed":
		routeStyle = bad
	}
	cols := []string{
		f.Start.Format("15:04:05"),
		fmt.Sprintf("%-22.22s", f.Source),
		status,
		fmt.Sprintf("%-7.7s", f.Method),
		fmt.Sprintf("%-6.6s", f.Route),
	}
	if sel {
		line := strings.Join(append(cols, f.URL), " ")
		line = clip(line, m.width-1)
		line += strings.Repeat(" ", max(m.width-1-lipgloss.Width(line), 0))
		return accent.Render("▌") + selected.Render(line)
	}
	host, rest := splitURL(f.URL)
	line := " " + dim.Render(cols[0]) + " " + cols[1] + " " + stStyle.Render(cols[2]) + " " +
		bold.Render(cols[3]) + " " + routeStyle.Render(cols[4]) + " " + host + dim.Render(rest)
	return clip(line, m.width)
}

// splitURL cuts a URL after its host, so the path can be drawn fainter.
func splitURL(u string) (host, rest string) {
	start := 0
	if i := strings.Index(u, "://"); i >= 0 {
		start = i + 3
	}
	if j := strings.IndexAny(u[start:], "/?"); j >= 0 {
		return u[:start+j], u[start+j:]
	}
	return u, ""
}

func (m *Model) footer() string {
	if m.mode == modeFilter {
		prompt := accentBold.Render(" filter › ") + m.input + accent.Render("▏")
		return clip(prompt+"   "+hints("enter", "apply", "esc", "cancel"), m.width)
	}
	if m.status != "" && time.Since(m.statusAt) < 8*time.Second {
		return clip(accent.Render(" ● ")+m.status, m.width)
	}
	// Most useful first; on a narrow screen the ones before "q quit" go, from the end.
	keys := []string{"↵", "details", "s", "source", "/", "filter", "c", "curl", "e", "export",
		"b", "bypass", "n", "no-decrypt", "x", "clear", "↑↓", "move", "q", "quit"}
	h := hints(keys...)
	for lipgloss.Width(h) > m.width && len(keys) > 4 {
		keys = append(keys[:len(keys)-4], keys[len(keys)-2:]...)
		h = hints(keys...)
	}
	return clip(h, m.width)
}

// hints draws key/description pairs: " ↵ details  / filter …".
func hints(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, accentBold.Render(pairs[i])+" "+dim.Render(pairs[i+1]))
	}
	return " " + strings.Join(parts, "  ")
}

// detailLines are the lines of the detail view for f, cached per flow and width so a
// large body is decoded and wrapped once, not on every key.
func (m *Model) detailLines(f store.Flow) []string {
	at := m.shown[m.cursor]
	if m.detail.lines != nil && m.detail.at == at && m.detail.width == m.width {
		return m.detail.lines
	}
	var lines []string
	add := func(s string) { lines = append(lines, s) }
	add(" " + accentBold.Render(f.Method) + " " + bold.Render(f.URL))
	status := fmt.Sprintf("%d", f.Status)
	switch {
	case f.Status == 0 || f.Status >= 500:
		status = bad.Render(status)
	case f.Status >= 400:
		status = warn.Render(status)
	default:
		status = ok.Render(status)
	}
	sep := dim.Render(" · ")
	add(" status " + status + sep + f.Proto + sep + f.Duration.Round(time.Millisecond).String() + sep +
		"route " + f.Route + sep + "source " + f.Source + sep + dim.Render(f.Start.Format("15:04:05.000")))
	if f.Err != "" {
		add(bad.Render(" error: " + f.Err))
	}
	if f.Kind == store.KindTunnel {
		add("")
		add(dim.Render(" passed through without decrypting: no headers or bodies to show"))
	} else {
		section := func(title string, h http.Header, body store.Body) {
			add("")
			add(" " + accentBold.Render(title) + " " + dim.Render(strings.Repeat("─", max(m.width-len(title)-3, 0))))
			for _, k := range slices.Sorted(maps.Keys(h)) {
				for _, v := range h[k] {
					add(" " + accent.Render(k) + dim.Render(":") + " " + v)
				}
			}
			add("")
			d := store.Decode(body, h.Get("Content-Encoding"))
			text, ok := bodyText(d)
			add(" " + bodySummary(body, d, ok))
			if ok {
				for l := range strings.SplitSeq(text, "\n") {
					for _, w := range wrap(strings.TrimRight(l, "\r"), m.width-1) {
						add(" " + w)
					}
				}
			}
		}
		section("request", f.ReqHeader, f.ReqBody)
		section("response", f.RespHeader, f.RespBody)
	}
	m.detail.at, m.detail.width, m.detail.lines = at, m.width, lines
	return lines
}

func (m *Model) renderDetail(f store.Flow) string {
	lines := m.detailLines(f)
	rows := max(m.height-2, 1)
	m.detailAt = min(m.detailAt, max(len(lines)-rows, 0))
	var b strings.Builder
	end := min(m.detailAt+rows, len(lines))
	for _, l := range lines[m.detailAt:end] {
		b.WriteString(clip(l, m.width) + "\n")
	}
	b.WriteString(strings.Repeat("\n", rows-(end-m.detailAt)))
	if m.status != "" && time.Since(m.statusAt) < 8*time.Second {
		b.WriteString(m.rule() + "\n" + clip(accent.Render(" ● ")+m.status, m.width))
		return b.String()
	}
	where := ""
	if len(lines) > rows {
		where = dim.Render(fmt.Sprintf("   %d–%d of %d", m.detailAt+1, end, len(lines)))
	}
	b.WriteString(m.rule() + "\n")
	b.WriteString(clip(hints("↑↓", "scroll", "space", "page", "c", "copy curl", "esc", "back")+where, m.width))
	return b.String()
}

// bodyText is a decoded body as text to show, pretty-printed when it is JSON; ok is
// false for an empty or binary body.
func bodyText(d store.Decoded) (text string, ok bool) {
	data := d.Data
	if d.Partial { // the cut may fall inside a character
		for i := 0; i < utf8.UTFMax-1 && len(data) > 0 && !utf8.Valid(data); i++ {
			data = data[:len(data)-1]
		}
	}
	if len(data) == 0 || !utf8.Valid(data) {
		return "", false
	}
	var buf bytes.Buffer
	if !d.Partial && json.Indent(&buf, data, "", "  ") == nil {
		return buf.String(), true
	}
	return string(data), true
}

func bodySummary(b store.Body, d store.Decoded, text bool) string {
	if b.Size == 0 {
		return dim.Render("(no body)")
	}
	s := fmt.Sprintf("%d bytes", b.Size)
	if d.Encoding != "" {
		s += fmt.Sprintf(" %s, %d decoded", d.Encoding, len(d.Data))
	}
	if !text {
		s = "binary, " + s
	}
	switch {
	case d.Partial && d.Encoding == "":
		s += fmt.Sprintf(", first %d shown", len(d.Data))
	case d.Partial:
		s += ", only the start"
	}
	if d.Err != "" {
		s += "; " + d.Err
	}
	return dim.Render("(" + s + ")")
}

// wrap breaks s into pieces of at most width display cells.
func wrap(s string, width int) []string {
	if width <= 0 || len(s) <= width && isASCII(s) {
		return []string{s}
	}
	var out []string
	var cur strings.Builder
	w := 0
	for _, r := range s {
		rw := 1
		if r >= utf8.RuneSelf {
			rw = lipgloss.Width(string(r))
		}
		if w+rw > width && w > 0 {
			out = append(out, cur.String())
			cur.Reset()
			w = 0
		}
		cur.WriteRune(r)
		w += rw
	}
	return append(out, cur.String())
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// clip cuts s to width display cells, keeping its styles intact.
func clip(s string, width int) string {
	if width <= 0 {
		return s
	}
	return ansi.Truncate(s, width, "…")
}
