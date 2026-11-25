package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// The source picker (s): all, then a group per kind of source, each folded until opened,
// so a long list of apps or simulators stays out of the way:
//
//	all                      every process on this Mac
//	▸ Simulators             3 booted
//	▾ Mac apps               24 running
//	    Safari               Mac app
//	    Slack                Mac app
//	▸ iPhone & iPad          1 set up        (with --device)
//
// Enter, → or a click opens a group; ←, or enter again, folds it. The group holding the
// current source starts open. Typing searches every source as one flat list; text that
// matches nothing is used as typed, so pid:<n> and apps that are not running yet still
// work.

type picker struct {
	choices []Choice // from Actions.Choices
	loading bool
	err     string
	cursor  int             // index into rows()
	open    map[string]bool // groups shown open
	top     int             // first row on screen
}

// pickRow is one line of the picker: a group heading, or a source to pick.
type pickRow struct {
	group   string // the group's key ("sim", "app", "dev"); "" for all
	heading bool
	choice  Choice // a heading's Label is the group's title, its Note the count
}

type pickGroup struct {
	key, title, prefix string
	all                Choice // the source that takes the whole group, listed first in it
	count              string // e.g. "%d booted"
}

func (m *Model) pickGroups() []pickGroup {
	g := []pickGroup{
		{"sim", "Simulators", "simulator:", Choice{Source: "simulator", Label: "every simulator", Note: "every booted simulator, as it boots"}, "%d booted"},
		{"app", "Mac apps", "app:", Choice{}, "%d running"},
	}
	if m.dev.Addr != "" {
		g = append(g, pickGroup{"dev", "iPhone & iPad", "device:", Choice{Source: "device", Label: "every device", Note: "every iPhone or iPad you set up"}, "%d set up"})
	}
	return g
}

// groupOf is the group a source belongs to, "" for all and for sources typed by hand.
func (m *Model) groupOf(source string) string {
	for _, g := range m.pickGroups() {
		if strings.EqualFold(source, g.all.Source) && g.all.Source != "" || strings.HasPrefix(strings.ToLower(source), g.prefix) {
			return g.key
		}
	}
	return ""
}

func (m *Model) allChoice() Choice {
	note := "every process on this Mac"
	if m.dev.Addr != "" {
		note += ", and every device you set up"
	}
	return Choice{Source: "all", Label: "all", Note: note}
}

// pickList is what the picker shows: the groups with their open ones unfolded, or, once
// something is typed, every source that matches it.
func (m *Model) pickList() []pickRow {
	groups := m.pickGroups()
	if strings.TrimSpace(m.input) != "" {
		var out []pickRow
		cands := []Choice{m.allChoice()}
		for _, g := range groups {
			if g.all.Source != "" {
				cands = append(cands, g.all)
			}
		}
		cands = append(cands, m.pick.choices...)
		for _, c := range cands {
			if containsWords(strings.ToLower(c.Label+" "+c.Source+" "+c.Note), m.input) {
				out = append(out, pickRow{group: m.groupOf(c.Source), choice: c})
			}
		}
		return out
	}
	out := []pickRow{{choice: m.allChoice()}}
	for _, g := range groups {
		var kids []Choice
		if g.all.Source != "" {
			kids = append(kids, g.all)
		}
		n := 0
		for _, c := range m.pick.choices {
			if strings.HasPrefix(c.Source, g.prefix) {
				kids = append(kids, c)
				n++
			}
		}
		count := fmt.Sprintf(g.count, n)
		if m.pick.loading {
			count = "looking…"
		}
		out = append(out, pickRow{group: g.key, heading: true, choice: Choice{Label: g.title, Note: count}})
		if m.pick.open[g.key] {
			for _, c := range kids {
				out = append(out, pickRow{group: g.key, choice: c})
			}
		}
	}
	return out
}

// cursorOnCurrent puts the cursor on the current source, or on its group's heading.
func (m *Model) cursorOnCurrent() {
	cur := m.act.Source()
	for i, r := range m.pickList() {
		if !r.heading && strings.EqualFold(r.choice.Source, cur) {
			m.pick.cursor = i
			return
		}
	}
	for i, r := range m.pickList() { // not listed (yet): its group's heading
		if r.heading && r.group == m.groupOf(cur) {
			m.pick.cursor = i
			return
		}
	}
	m.pick.cursor = 0
}

// openPicker shows the picker, with the current source's group open, and starts looking
// for simulators and apps.
func (m *Model) openPicker() tea.Cmd {
	m.mode, m.input, m.status = modeSource, "", ""
	m.pick = picker{loading: true, open: map[string]bool{}}
	if g := m.groupOf(m.act.Source()); g != "" {
		m.pick.open[g] = true
	}
	m.cursorOnCurrent()
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
		m.cursorOnCurrent()
	}
}

// picking handles keys while the picker is open.
func (m *Model) picking(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	rows := m.pickList()
	at := func() (pickRow, bool) {
		if m.pick.cursor < len(rows) {
			return rows[m.pick.cursor], true
		}
		return pickRow{}, false
	}
	switch k.String() {
	case "esc":
		m.mode = modeList
	case "ctrl+c":
		return m, tea.Quit
	case "up", "ctrl+p":
		m.pick.cursor = max(m.pick.cursor-1, 0)
	case "down", "ctrl+n":
		m.pick.cursor = min(m.pick.cursor+1, max(len(rows)-1, 0))
	case "pgup":
		m.pick.cursor = max(m.pick.cursor-m.pickRows(), 0)
	case "pgdown":
		m.pick.cursor = min(m.pick.cursor+m.pickRows(), max(len(rows)-1, 0))
	case "right", "tab":
		if r, ok := at(); ok && r.heading {
			m.pick.open[r.group] = true
		}
	case "left", "shift+tab":
		if r, ok := at(); ok && r.group != "" && strings.TrimSpace(m.input) == "" {
			m.fold(r.group)
		}
	case "enter":
		if r, ok := at(); ok && r.heading {
			if m.pick.open[r.group] {
				m.fold(r.group)
			} else {
				m.pick.open[r.group] = true
			}
			return m, nil
		}
		m.choose(rows)
	default:
		if m.edit(k) {
			m.pick.cursor = 0
		}
	}
	return m, nil
}

// fold closes a group and puts the cursor on its heading.
func (m *Model) fold(group string) {
	m.pick.open[group] = false
	for i, r := range m.pickList() {
		if r.heading && r.group == group {
			m.pick.cursor = i
		}
	}
}

// choose captures the source under the cursor, or the text as typed.
func (m *Model) choose(rows []pickRow) {
	src := strings.TrimSpace(m.input)
	if m.pick.cursor < len(rows) {
		c := rows[m.pick.cursor].choice
		src = c.Source
		if strings.Contains(c.Source, ":") && c.Label != c.Source {
			m.labels[c.Source] = c.Label
		}
	}
	if src == "" || m.setSource(src) {
		m.mode = modeList
	}
}

// pickerMouse handles clicks and the wheel: a click acts on the row under it as enter.
func (m *Model) pickerMouse(msg tea.MouseMsg) tea.Cmd {
	mouse := msg.Mouse()
	rows := m.pickList()
	switch msg.(type) {
	case tea.MouseWheelMsg:
		switch mouse.Button {
		case tea.MouseWheelUp:
			m.pick.cursor = max(m.pick.cursor-1, 0)
		case tea.MouseWheelDown:
			m.pick.cursor = min(m.pick.cursor+1, max(len(rows)-1, 0))
		}
	case tea.MouseClickMsg:
		i := m.pick.top + mouse.Y - pickFirstLine
		if mouse.Button != tea.MouseLeft || mouse.Y < pickFirstLine || i < 0 || i >= len(rows) || mouse.Y-pickFirstLine >= m.pickRows() {
			return nil
		}
		m.pick.cursor = i
		_, cmd := m.picking(tea.KeyPressMsg{Code: tea.KeyEnter})
		return cmd
	}
	return nil
}

// pickFirstLine is the screen line of the picker's first row: below the header, a rule,
// the title and a blank line.
const pickFirstLine = 4

// pickRows is how many rows fit: all but the header, rules, title, note and footer.
func (m *Model) pickRows() int { return max(m.height-7, 1) }

func (m *Model) renderPicker() string {
	t := m.t
	var b strings.Builder
	b.WriteString(m.header() + "\n" + m.rule() + "\n")

	title := " " + t.bold.Render("Capture which source?") + t.dim.Render("  applies to new connections; open ones keep theirs")
	if m.status != "" && time.Since(m.statusAt) < 8*time.Second {
		title = " " + t.warn.Render(m.status)
	}
	b.WriteString(clip(title, m.width) + "\n\n")

	rows := m.pickList()
	n := m.pickRows()
	if m.pick.cursor < m.pick.top {
		m.pick.top = m.pick.cursor
	}
	if m.pick.cursor >= m.pick.top+n {
		m.pick.top = m.pick.cursor - n + 1
	}
	m.pick.top = max(min(m.pick.top, len(rows)-n), 0)
	labelW := 12
	for _, r := range rows {
		labelW = max(labelW, lipgloss.Width(r.choice.Label)+2) // room for "▸ " or the indent
	}
	labelW = min(labelW, 30)
	current := m.act.Source()
	flat := strings.TrimSpace(m.input) != ""
	for i := m.pick.top; i < m.pick.top+n; i++ {
		if i >= len(rows) {
			b.WriteString("\n")
			continue
		}
		r := rows[i]
		sel := i == m.pick.cursor
		mark := "  "
		if sel {
			mark = t.mark.Render("▸ ")
		}
		cur := "  "
		if !r.heading && strings.EqualFold(r.choice.Source, current) {
			cur = t.ok.Render("● ")
		}
		label := r.choice.Label
		switch {
		case r.heading:
			fold := "▸ "
			if m.pick.open[r.group] {
				fold = "▾ "
			}
			label = fold + label
		case r.group != "" && !flat:
			label = "  " + label
		}
		label = clip(label, labelW)
		label += strings.Repeat(" ", max(labelW-lipgloss.Width(label), 0))
		switch {
		case r.heading && sel:
			label = t.accentBold.Render(label)
		case r.heading:
			label = t.bold.Render(label)
		case sel:
			label = t.accentBold.Render(label)
		}
		if r.heading {
			cur = "  "
			if m.groupOf(current) == r.group && !m.pick.open[r.group] {
				cur = t.ok.Render("● ") // the current source is folded away in here
			}
		}
		b.WriteString(clip(" "+mark+cur+label+"  "+t.muted.Render(r.choice.Note), m.width) + "\n")
	}

	var note string
	switch {
	case len(rows) == 0:
		note = t.dim.Render(" nothing matches; enter uses ") + t.bold.Render(strings.TrimSpace(m.input)) + t.dim.Render(" as typed (e.g. pid:1234, app:<name|bundle-id>)")
	case m.pick.loading:
		note = t.dim.Render(" looking for booted simulators and running apps…")
	case m.pick.err != "":
		note = t.warn.Render(" " + m.pick.err)
	default:
		note = t.dim.Render(" ● is the current source · type to search them all")
	}
	b.WriteString(clip(note, m.width) + "\n")
	b.WriteString(m.rule() + "\n")
	prompt := t.accentBold.Render(" source › ") + m.input + t.mark.Render("▏")
	hints := t.hints("↑↓", "move", "→←", "open/fold", "enter", "capture", "esc", "cancel")
	if m.pick.cursor < len(rows) && rows[m.pick.cursor].heading {
		hints = t.hints("↑↓", "move", "enter", "open", "esc", "cancel")
	}
	b.WriteString(clip(prompt+"   "+hints, m.width))
	return b.String()
}
