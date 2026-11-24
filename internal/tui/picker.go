package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// The source picker (s): all, every booted simulator, each booted simulator, each running
// Mac app. Typing narrows the list; text that matches nothing is used as typed, so
// pid:<n> and apps that are not running yet still work.

type picker struct {
	choices []Choice // from Actions.Choices
	loading bool
	err     string
	cursor  int // index into entries()
}

// openPicker shows the picker and starts looking for simulators and apps.
func (m *Model) openPicker() tea.Cmd {
	m.mode, m.input, m.status = modeSource, "", ""
	m.pick = picker{loading: true}
	m.pick.cursor = indexOf(m.entries(), m.act.Source())
	act := m.act
	return func() tea.Msg {
		list, err := act.Choices()
		return choicesMsg{list: list, err: err}
	}
}

func (m *Model) pickerLoaded(msg choicesMsg) {
	m.pick.choices, m.pick.loading, m.pick.err = msg.list, false, ""
	if msg.err != nil {
		m.pick.err = msg.err.Error()
	}
	for _, c := range msg.list {
		m.labels[c.Source] = c.Label
	}
	if m.input == "" {
		m.pick.cursor = indexOf(m.entries(), m.act.Source())
	}
}

// entries is what the picker lists for the text typed so far.
func (m *Model) entries() []Choice {
	sims := 0
	for _, c := range m.pick.choices {
		if strings.HasPrefix(c.Source, "simulator:") {
			sims++
		}
	}
	allNote := "every process on this Mac"
	if m.dev.Addr != "" {
		allNote += ", and every device you allowed"
	}
	simNote := "every booted simulator"
	if !m.pick.loading {
		simNote = fmt.Sprintf("every booted simulator (%d now)", sims)
	}
	all := append([]Choice{
		{Source: "all", Label: "all", Note: allNote},
		{Source: "simulator", Label: "simulator", Note: simNote},
	}, m.pick.choices...)
	if strings.TrimSpace(m.input) == "" {
		return all
	}
	var out []Choice
	for _, c := range all {
		if containsWords(strings.ToLower(c.Label+" "+c.Source+" "+c.Note), m.input) {
			out = append(out, c)
		}
	}
	return out
}

func indexOf(list []Choice, source string) int {
	for i, c := range list {
		if strings.EqualFold(c.Source, source) {
			return i
		}
	}
	return 0
}

// picking handles keys while the picker is open.
func (m *Model) picking(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	list := m.entries()
	switch k.String() {
	case "esc":
		m.mode = modeList
	case "ctrl+c":
		return m, tea.Quit
	case "up", "ctrl+p":
		m.pick.cursor = max(m.pick.cursor-1, 0)
	case "down", "ctrl+n":
		m.pick.cursor = min(m.pick.cursor+1, max(len(list)-1, 0))
	case "pgup":
		m.pick.cursor = max(m.pick.cursor-m.pickRows(), 0)
	case "pgdown":
		m.pick.cursor = min(m.pick.cursor+m.pickRows(), max(len(list)-1, 0))
	case "enter":
		src := strings.TrimSpace(m.input)
		if m.pick.cursor < len(list) {
			c := list[m.pick.cursor]
			src = c.Source
			if c.Label != c.Source {
				m.labels[c.Source] = c.Label
			}
		}
		if src == "" || m.setSource(src) {
			m.mode = modeList
		}
	default:
		if m.edit(k) {
			m.pick.cursor = 0
		}
	}
	return m, nil
}

// pickRows is how many entries fit: all but the header, rules, title, note and footer.
func (m *Model) pickRows() int { return max(m.height-7, 1) }

func (m *Model) renderPicker() string {
	var b strings.Builder
	b.WriteString(m.header() + "\n" + m.rule() + "\n")

	title := " " + m.t.bold.Render("Capture which source?") + m.t.dim.Render("  applies to new connections; open ones keep theirs")
	if m.status != "" && time.Since(m.statusAt) < 8*time.Second {
		title = " " + m.t.warn.Render(m.status)
	}
	b.WriteString(clip(title, m.width) + "\n\n")

	list := m.entries()
	rows := m.pickRows()
	off := max(m.pick.cursor-rows+1, 0)
	labelW := 10
	for _, c := range list {
		labelW = max(labelW, lipgloss.Width(c.Label))
	}
	labelW = min(labelW, 28)
	current := m.act.Source()
	for i := off; i < off+rows; i++ {
		if i >= len(list) {
			b.WriteString("\n")
			continue
		}
		c := list[i]
		mark, label := "  ", clip(c.Label, labelW)
		label += strings.Repeat(" ", labelW-lipgloss.Width(label))
		if i == m.pick.cursor {
			mark, label = m.t.mark.Render("▸ "), m.t.accentBold.Render(label)
		}
		cur := "  "
		if strings.EqualFold(c.Source, current) {
			cur = m.t.ok.Render("● ")
		}
		b.WriteString(clip(" "+mark+cur+label+"  "+m.t.muted.Render(c.Note), m.width) + "\n")
	}

	var note string
	switch {
	case len(list) == 0:
		note = m.t.dim.Render(" nothing matches; enter uses ") + m.t.bold.Render(strings.TrimSpace(m.input)) + m.t.dim.Render(" as typed (e.g. pid:1234, app:<name|bundle-id>)")
	case m.pick.loading:
		note = m.t.dim.Render(" looking for booted simulators and running apps…")
	case m.pick.err != "":
		note = m.t.warn.Render(" " + m.pick.err)
	default:
		note = m.t.dim.Render(" ● is the current source")
	}
	b.WriteString(clip(note, m.width) + "\n")
	b.WriteString(m.rule() + "\n")
	prompt := m.t.accentBold.Render(" source › ") + m.input + m.t.mark.Render("▏")
	b.WriteString(clip(prompt+"   "+m.t.hints("↑↓", "choose", "enter", "capture", "esc", "cancel"), m.width))
	return b.String()
}
