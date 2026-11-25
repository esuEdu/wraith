package tui

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/esuEdu/wraith/internal/store"
)

// View implements tea.Model.
func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "wraith · " + m.sourceName()
	v.BackgroundColor, v.ForegroundColor = m.t.bg, m.t.fg
	if m.mode == modeSource { // clicks pick a source; elsewhere the mouse stays the terminal's, to select text
		v.MouseMode = tea.MouseModeCellMotion
	}
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
	t := m.t
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
	if m.dev.Addr != "" && (m.showDev || len(m.flows) == 0) {
		panel := m.devicePanel(rows)
		b.WriteString(strings.Join(panel, "\n") + "\n")
		b.WriteString(strings.Repeat("\n", max(rows-len(panel), 0)))
		b.WriteString(m.rule() + "\n" + m.footer())
		return b.String()
	}
	if len(m.shown) == 0 {
		msg := " waiting for traffic from " + m.sourceName() + "…"
		if m.filter != "" {
			msg = " no flow matches the filter; esc clears it"
		}
		b.WriteString(t.muted.Render(msg) + "\n")
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
	t := m.t
	sep := t.dim.Render(" · ")
	h := t.badge.Render(" wraith ") + " " + t.muted.Render(m.listen) + sep +
		t.muted.Render("capturing ") + t.accentBold.Render(m.sourceName()) + sep + t.muted.Render(fmt.Sprintf("%d flows", len(m.flows)))
	if m.dev.Addr != "" {
		h += sep + t.muted.Render("devices ") + m.dev.Addr
	}
	if m.filter != "" {
		h += sep + t.muted.Render("filter ") + t.accentBold.Render(m.filter) + t.dim.Render(fmt.Sprintf(" (%d shown)", len(m.shown)))
	}
	return clip(h, m.width)
}

func (m *Model) rule() string { return m.t.dim.Render(strings.Repeat("─", max(m.width, 1))) }

// row is one flow in the list; the selected one is highlighted across the screen, with
// a bar in front.
func (m *Model) row(f store.Flow, sel bool) string {
	t := m.t
	status := fmt.Sprintf("%3d", f.Status)
	stStyle := t.status(f.Status)
	switch {
	case f.Kind == store.KindTunnel && f.Status == 200:
		status, stStyle = "tun", t.dim
	case f.Status == 0:
		status = "ERR"
	}
	routeStyle := t.dim
	switch f.Route {
	case "direct":
		routeStyle = t.direct
	case "failed":
		routeStyle = t.bad
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
		if r := tunnelReason(f); r != "" {
			line += "  " + r
		}
		line = clip(line, m.width-1)
		line += strings.Repeat(" ", max(m.width-1-lipgloss.Width(line), 0))
		return t.mark.Render("▌") + t.selected.Render(line)
	}
	host, rest := splitURL(f.URL)
	why := ""
	if r := tunnelReason(f); r != "" {
		why = "  " + stStyle.Render(r)
	}
	line := " " + t.dim.Render(cols[0]) + " " + cols[1] + " " + stStyle.Render(cols[2]) + " " +
		t.method(f.Method).Render(cols[3]) + " " + routeStyle.Render(cols[4]) + " " + host + t.muted.Render(rest) + why
	return clip(line, m.width)
}

// tunnelReason is why a tunnel was not decrypted, in a word or two for the list; the
// details have the whole sentence.
func tunnelReason(f store.Flow) string {
	if f.Kind != store.KindTunnel || f.Err == "" {
		return ""
	}
	for _, r := range []struct{ has, says string }{
		{"rejected wraith's certificate (", "certificate rejected"},
		{"a moment ago", "rejected earlier, retried soon"},
		{"no_decrypt", "no_decrypt"},
		{"sent nothing", "idle"},
		{"closed the tunnel", "closed"},
		{"not TLS", "not TLS"},
		{"Mac does not trust", "Mac app, CA not trusted"},
	} {
		if strings.Contains(f.Err, r.has) {
			return r.says
		}
	}
	return ""
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
	t := m.t
	if m.mode == modeFilter {
		prompt := t.accentBold.Render(" filter › ") + m.input + t.mark.Render("▏")
		help := t.muted.Render("words · body:text · header:text · \"a phrase\"")
		return clip(prompt+"   "+help+"  "+t.hints("enter", "apply", "esc", "cancel"), m.width)
	}
	if s, ok := m.statusLine(); ok {
		return s
	}
	// Most useful first; on a narrow screen the ones before "q quit" go, from the end.
	keys := []string{"↵", "details", "s", "source", "/", "filter", "c", "curl", "r", "resend", "e", "export",
		"b", "bypass", "n", "no-decrypt", "x", "clear", "↑↓", "move", "q", "quit"}
	if m.dev.Addr != "" {
		keys = append(keys[:4], append([]string{"d", "device"}, keys[4:]...)...)
	}
	h := t.hints(keys...)
	for lipgloss.Width(h) > m.width && len(keys) > 4 {
		keys = append(keys[:len(keys)-4], keys[len(keys)-2:]...)
		h = t.hints(keys...)
	}
	return clip(h, m.width)
}

// statusLine is the latest message, while it is fresh.
func (m *Model) statusLine() (string, bool) {
	if m.status == "" || time.Since(m.statusAt) >= 8*time.Second {
		return "", false
	}
	return clip(m.t.mark.Render(" ● ")+m.status, m.width), true
}

// The details have a fixed top (request line, status, tabs) over a scrolling tab: the
// response or the request, each with its headers and body.

const (
	tabResponse = iota
	tabRequest
)

var tabNames = [...]string{"Response", "Request"}

// detailTop is the part of the details that does not scroll.
func (m *Model) detailTop(f store.Flow) []string {
	t := m.t
	sep := t.dim.Render(" · ")
	top := []string{" " + t.method(f.Method).Reverse(true).Render(" "+f.Method+" ") + " " + t.bold.Render(f.URL)}

	code := fmt.Sprintf("%d", f.Status)
	if txt := http.StatusText(f.Status); txt != "" && f.Kind == store.KindHTTP {
		code += " " + txt
	}
	if f.Status == 0 {
		code = "no response"
	}
	meta := []string{t.status(f.Status).Bold(true).Render(code)}
	for _, s := range []string{f.Proto, f.Duration.Round(time.Millisecond).String(), "route " + f.Route, f.Source, f.Start.Format("15:04:05.000")} {
		if strings.TrimSpace(s) != "" && s != "route " {
			meta = append(meta, t.muted.Render(s))
		}
	}
	top = append(top, " "+strings.Join(meta, sep))
	switch {
	case f.Err != "" && f.Kind == store.KindTunnel && f.Status == 200:
		top = append(top, t.muted.Render(" why: "+f.Err))
	case f.Err != "":
		top = append(top, t.bad.Render(" error: "+f.Err))
	}
	if f.Kind == store.KindHTTP {
		tabs := " "
		for i, name := range tabNames {
			st := t.tabOff
			if i == m.tab {
				st = t.tabOn
			}
			tabs += st.Render(" "+name+" ") + " "
		}
		top = append(top, "", tabs)
	}
	return top
}

// detailLines are the scrolling lines of the details for f, cached per flow, tab and
// width so a large body is decoded and colored once, not on every key.
func (m *Model) detailLines(f store.Flow) []string {
	at := m.shown[m.cursor]
	if m.detail.lines != nil && m.detail.at == at && m.detail.width == m.width && m.detail.tab == m.tab {
		return m.detail.lines
	}
	t := m.t
	var lines []string
	add := func(indent int, words bool, segs ...seg) {
		for _, l := range wrapSegs(segs, m.width-1, indent, words) {
			lines = append(lines, " "+render(l))
		}
	}
	title := func(name, note string) {
		w := lipgloss.Width(name) + lipgloss.Width(note) + 4
		lines = append(lines, " "+t.accentBold.Render(name)+" "+note+" "+t.dim.Render(strings.Repeat("─", max(m.width-w, 0))))
	}
	if f.Kind == store.KindTunnel {
		lines = append(lines, "", t.muted.Render(" passed through without decrypting: no headers or bodies to show"))
	} else {
		h, body := f.RespHeader, f.RespBody
		if m.tab == tabRequest {
			h, body = f.ReqHeader, f.ReqBody
		}
		lines = append(lines, "")
		title("Headers", t.muted.Render(fmt.Sprint(headerCount(h))))
		keys := slices.Sorted(maps.Keys(h))
		keyW := 0
		for _, k := range keys {
			keyW = max(keyW, len(k))
		}
		keyW = min(keyW, 24)
		for _, k := range keys {
			for _, v := range h[k] {
				pad := strings.Repeat(" ", max(keyW-len(k), 0))
				add(min(keyW+2, m.width/2), true, seg{k, &t.key}, seg{":" + pad + " ", &t.dim}, seg{v, nil})
			}
		}
		if len(h) == 0 {
			lines = append(lines, t.muted.Render(" none"))
		}

		lines = append(lines, "")
		d := store.Decode(body, h.Get("Content-Encoding"))
		text, isJSON, ok := bodyText(d)
		note := t.bodySummary(body, d, ok)
		if isJSON {
			note = t.accent.Render("JSON") + t.dim.Render(" · ") + note
		}
		title("Body", note)
		if ok {
			color := isJSON && len(text) <= maxHighlight
			for l := range strings.SplitSeq(text, "\n") {
				l = strings.TrimRight(l, "\r")
				if color {
					add(4, false, t.jsonSegs(l)...)
				} else {
					add(4, false, seg{l, nil})
				}
			}
		}
	}
	m.detail.at, m.detail.width, m.detail.tab, m.detail.lines = at, m.width, m.tab, lines
	return lines
}

func headerCount(h http.Header) int {
	n := 0
	for _, vs := range h {
		n += len(vs)
	}
	return n
}

func (m *Model) renderDetail(f store.Flow) string {
	t := m.t
	top := m.detailTop(f)
	lines := m.detailLines(f)
	rows := max(m.height-len(top)-3, 1) // the top, a rule under it, and the rule and hints at the bottom
	m.detailAt = min(m.detailAt, max(len(lines)-rows, 0))

	var b strings.Builder
	for _, l := range top {
		b.WriteString(clip(l, m.width) + "\n")
	}
	b.WriteString(m.rule() + "\n")
	end := min(m.detailAt+rows, len(lines))
	for _, l := range lines[m.detailAt:end] {
		b.WriteString(clip(l, m.width) + "\n")
	}
	b.WriteString(strings.Repeat("\n", rows-(end-m.detailAt)))
	b.WriteString(m.rule() + "\n")
	if s, ok := m.statusLine(); ok {
		b.WriteString(s)
		return b.String()
	}
	where := ""
	if len(lines) > rows {
		where = t.dim.Render(fmt.Sprintf("   %d–%d of %d", m.detailAt+1, end, len(lines)))
	}
	var h string
	if f.Kind == store.KindHTTP {
		other := strings.ToLower(tabNames[1-m.tab])
		sep := t.dim.Render("  │ ")
		h = t.hints("tab", other) + sep + t.muted.Render("copy") + t.hints("b", "body", "h", "headers", "u", "url", "c", "curl") +
			sep + t.hints("r", "resend", "esc", "back")[1:]
	} else {
		h = t.hints("u", "copy host", "esc", "back")
	}
	b.WriteString(clip(h+where, m.width))
	return b.String()
}

// clip cuts s to width display cells, keeping its styles intact.
func clip(s string, width int) string {
	if width <= 0 {
		return s
	}
	return ansi.Truncate(s, width, "…")
}
