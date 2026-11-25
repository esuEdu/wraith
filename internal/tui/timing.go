package tui

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"charm.land/lipgloss/v2"

	"github.com/esuEdu/wraith/internal/store"
)

// nextTab is the tab step places after cur among f's tabs, wrapping around.
func nextTab(f store.Flow, cur, step int) int {
	tabs := tabsOf(f)
	i := slices.Index(tabs, cur)
	if i < 0 {
		return tabs[0]
	}
	return tabs[(i+step+len(tabs))%len(tabs)]
}

// tabOf is the tab to show for f: the one chosen, if f has it, else Response.
func (m *Model) tabOf(f store.Flow) int {
	if slices.Contains(tabsOf(f), m.tab) {
		return m.tab
	}
	return tabResponse
}

// timingLines draw where a flow's time went as a waterfall: each phase a bar that starts
// where the one before it ended, on a scale of the whole request.
func (m *Model) timingLines(f store.Flow) []string {
	t := m.t
	lines := []string{""}
	switch {
	case f.Mock != "":
		return append(lines, t.muted.Render(" answered by the mock "+f.Mock+": no upstream, so no timing"))
	case !f.Timing.Known:
		return append(lines, t.muted.Render(" no response came from the upstream, so there is no timing to show"))
	}
	tm := f.Timing
	phases := []struct {
		name string
		d    time.Duration
		note string
	}{
		{"blocked", tm.Blocked, "in wraith"},
		{"dns", tm.DNS, "DNS lookup"},
		{"connect", tm.Connect, "TCP connect"},
		{"tls", tm.TLS, "TLS handshake"},
		{"send", tm.Send, "request sent"},
		{"wait", tm.Wait, "server, to first byte"},
		{"receive", tm.Receive, "download"},
	}
	if f.Throttle != "" {
		phases[0].note = f.Throttle + " latency"
	}
	total := f.Duration
	if total <= 0 {
		total = time.Millisecond
	}
	barW := max(m.width-46, 10) // " name  duration  " before it, a note of up to 22 after it
	lines = append(lines, " "+t.accentBold.Render("Timing")+" "+t.muted.Render("total "+ms(f.Duration))+" "+
		t.dim.Render(strings.Repeat("─", max(m.width-len("Timing total ")-len(ms(f.Duration))-3, 0))))
	at := time.Duration(0)
	for _, p := range phases {
		if p.d <= 0 && p.name != "wait" {
			continue
		}
		from := int(float64(barW) * at.Seconds() / total.Seconds())
		n := max(int(float64(barW)*p.d.Seconds()/total.Seconds()), 1)
		from = min(from, barW-1)
		n = min(n, barW-from)
		style := t.accent
		switch p.name {
		case "wait":
			style = t.warn
		case "receive":
			style = t.ok
		case "blocked":
			style = t.dim
		}
		bar := strings.Repeat(" ", from) + style.Render(strings.Repeat("█", n)) + strings.Repeat(" ", barW-from-n)
		lines = append(lines, fmt.Sprintf(" %-8s %8s  %s  %s", p.name, ms(p.d), bar, t.muted.Render(p.note)))
		at += p.d
	}
	if tm.Reused {
		lines = append(lines, "", t.muted.Render(" reused an open connection: no DNS, connect or TLS this time"))
	}
	return lines
}

// ms writes a duration the way the timing shows it: 0.4ms, 12ms, 1.25s.
func ms(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// messageLines list a WebSocket's messages, oldest first: when, which way, the kind and
// the payload (text as is, binary by size).
func (m *Model) messageLines(f store.Flow) []string {
	t := m.t
	lines := []string{""}
	note := fmt.Sprintf("%d", len(f.Messages))
	if f.MessagesDropped > 0 {
		note += fmt.Sprintf(" · %d older let go", f.MessagesDropped)
	}
	w := len("Messages ") + len(note) + 3
	lines = append(lines, " "+t.accentBold.Render("Messages")+" "+t.muted.Render(note)+" "+t.dim.Render(strings.Repeat("─", max(m.width-w, 0))))
	if len(f.Messages) == 0 {
		return append(lines, t.muted.Render(" none yet: they appear here as the app and the server talk"))
	}
	for _, msg := range f.Messages {
		dir, dirStyle := "↑", t.accent
		if !msg.FromClient {
			dir, dirStyle = "↓", t.ok
		}
		head := " " + t.dim.Render(msg.At.Format("15:04:05.000")) + " " + dirStyle.Render(dir) + " " + fmt.Sprintf("%-6s", msg.Op) + " "
		body := messageText(msg)
		var style *lipgloss.Style
		if msg.Op != "text" {
			style = &t.muted
		}
		prefix := len("15:04:05.000") + 11
		for i, l := range wrapSegs([]seg{{body, style}}, max(m.width-1-prefix, 10), 0, false) {
			if i == 0 {
				lines = append(lines, head+render(l))
			} else {
				lines = append(lines, strings.Repeat(" ", prefix+1)+render(l))
			}
		}
	}
	return lines
}

// messageText is what the list shows of a message's payload.
func messageText(msg store.Message) string {
	var s string
	switch {
	case msg.Note != "":
		s = msg.Note + " · " + size(msg.Size)
	case msg.Op == "close":
		s = closeText(msg.Data)
	case msg.Op == "text" && utf8.Valid(msg.Data):
		s = strings.ReplaceAll(string(msg.Data), "\n", "⏎")
	case len(msg.Data) == 0:
		s = ""
	default:
		s = size(msg.Size)
		if utf8.Valid(msg.Data) {
			s += " · " + strings.ReplaceAll(string(msg.Data), "\n", "⏎")
		}
	}
	if msg.Truncated {
		s += fmt.Sprintf(" … (%s, only the start kept)", size(msg.Size))
	}
	return s
}

// closeText reads a close frame's payload: a status code, then a reason.
func closeText(b []byte) string {
	if len(b) < 2 {
		return "no status"
	}
	code := int(b[0])<<8 | int(b[1])
	s := fmt.Sprint(code)
	if name, ok := closeCodes[code]; ok {
		s += " " + name
	}
	if len(b) > 2 {
		s += ": " + string(b[2:])
	}
	return s
}

var closeCodes = map[int]string{1000: "normal", 1001: "going away", 1002: "protocol error", 1003: "unsupported data",
	1006: "abnormal", 1007: "invalid data", 1008: "policy violation", 1009: "too big", 1011: "server error"}
