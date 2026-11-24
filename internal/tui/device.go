package tui

import (
	"net"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"rsc.io/qr"
)

// QR draws text as a QR code for a terminal: two modules per character with half
// blocks, dark on light in the terminal's own black and bright white, with a light
// border so it scans on a dark background too. It is nil if text is too long.
func QR(text string) []string {
	c, err := qr.Encode(text, qr.L)
	if err != nil {
		return nil
	}
	const quiet = 2
	dark := func(x, y int) bool {
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Black(x, y)
	}
	color := func(d bool) ansi.Color {
		if d {
			return ansi.Black
		}
		return ansi.BrightWhite
	}
	var out []string
	for y := -quiet; y < c.Size+quiet; y += 2 {
		var b strings.Builder
		for x := -quiet; x < c.Size+quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			if y+1 >= c.Size+quiet { // an odd last row: its lower half is the background
				b.WriteString(ansi.Style{}.ForegroundColor(color(top)).Styled("▀"))
				continue
			}
			b.WriteString(ansi.Style{}.ForegroundColor(color(top)).BackgroundColor(color(bottom)).Styled("▀"))
		}
		out = append(out, b.String())
	}
	return out
}

// devicePanel is the setup for an iPhone or iPad (d, and while nothing is captured yet):
// the QR code that opens the setup page, and the steps.
func (m *Model) devicePanel(rows int) []string {
	t := m.t
	host, port, _ := net.SplitHostPort(m.dev.Addr)
	steps := []string{
		t.bold.Render("Set up an iPhone or iPad on this Wi-Fi"),
		"",
	}
	steps = append(steps,
		t.accentBold.Render("1")+" Scan the code with the Camera and open the link.",
		t.accentBold.Render("2")+" Download the certificate and install it in Settings,",
		"  then turn on "+t.bold.Render("wraith CA")+" in General › About ›",
		"  Certificate Trust Settings. (Once per device.)",
		t.accentBold.Render("3")+" Wi-Fi › ⓘ › Configure Proxy › Manual:",
		"  server "+t.accentBold.Render(host)+"  port "+t.accentBold.Render(port),
		t.muted.Render("Once per device: wraith remembers it for next time."),
	)
	steps = append(steps,
		"",
		t.muted.Render("Nothing arrives? The device must be on this Wi-Fi, not"),
		t.muted.Render("cellular or a VPN; guest networks keep devices apart."),
	)
	if m.dev.Warning != "" {
		steps = append(steps, "")
		for _, l := range strings.Split(ansi.Wordwrap(m.dev.Warning, 54, " "), "\n") {
			steps = append(steps, t.warn.Render(l))
		}
	}
	steps = append(steps, "", t.dim.Render("or open ")+t.muted.Render(m.dev.URL))
	if len(m.flows) > 0 {
		steps = append(steps, t.dim.Render("d or esc goes back to the flows"))
	}

	code := QR(m.dev.URL)
	codeW := 0
	if len(code) > 0 {
		codeW = lipgloss.Width(code[0])
	}
	var out []string
	if m.width >= codeW+58 && len(code) <= rows { // side by side
		for i := range max(len(code), len(steps)) {
			l := strings.Repeat(" ", codeW)
			if i < len(code) {
				l = code[i]
			}
			if i < len(steps) {
				l += "   " + steps[i]
			}
			out = append(out, " "+l)
		}
	} else {
		if len(code)+len(steps)+1 <= rows {
			for _, l := range code {
				out = append(out, " "+l)
			}
			out = append(out, "")
		}
		for _, l := range steps {
			out = append(out, " "+l)
		}
	}
	for i, l := range out {
		out[i] = clip(l, m.width)
	}
	return out[:min(len(out), rows)]
}
