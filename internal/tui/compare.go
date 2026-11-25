package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/esuEdu/wraith/internal/store"
)

// Compare: = marks a request, = on another one shows what differs between the two, part
// by part: the request line, headers and body, then the response's status, headers and
// body. JSON is compared with its keys sorted, so only real differences show.

// compareState is the comparison on screen.
type compareState struct {
	mark  uint64 // the marked flow's ID; 0 for none
	a, b  store.Flow
	at    int // first line on screen
	width int
	lines []string
}

// markOrCompare marks the selected flow, unmarks it, or compares it with the mark.
func (m *Model) markOrCompare() {
	f, ok := m.selected()
	if !ok {
		return
	}
	if f.Kind != store.KindHTTP {
		m.say("a tunnel was not decrypted: there is nothing in it to compare")
		return
	}
	switch m.cmp.mark {
	case 0:
		m.cmp.mark = f.ID
		m.say("marked " + f.Method + " " + f.URL + " · select another request and press = to compare them")
		return
	case f.ID:
		m.cmp.mark = 0
		m.say("unmarked")
		return
	}
	var a store.Flow
	found := false
	for _, g := range m.flows {
		if g.ID == m.cmp.mark {
			a, found = g, true
		}
	}
	if !found {
		m.cmp.mark = 0
		m.say("the marked request is no longer in the list; = marks this one")
		return
	}
	m.cmp.a, m.cmp.b, m.cmp.at, m.cmp.lines = a, f, 0, nil
	m.mode, m.status = modeCompare, ""
}

// comparing handles keys while the comparison is open.
func (m *Model) comparing(key string) {
	rows := max(m.height-6, 1)
	switch key {
	case "esc", "q", "backspace", "=":
		m.mode = modeList
	case "down", "j":
		m.cmp.at++
	case "up", "k":
		m.cmp.at = max(m.cmp.at-1, 0)
	case "pgdown", "space":
		m.cmp.at += rows
	case "pgup":
		m.cmp.at = max(m.cmp.at-rows, 0)
	case "g", "home":
		m.cmp.at = 0
	case "G", "end":
		m.cmp.at = len(m.cmp.lines)
	case "s": // swap sides
		m.cmp.a, m.cmp.b, m.cmp.lines = m.cmp.b, m.cmp.a, nil
	}
}

func (m *Model) renderCompare() string {
	t := m.t
	c := &m.cmp
	side := func(label string, f store.Flow) string {
		meta := []string{fmt.Sprint(f.Status), ms(f.Duration), f.Source, f.Start.Format("15:04:05")}
		if len(f.GraphQL) > 0 {
			meta = append([]string{store.GraphQLLabel(f.GraphQL)}, meta...)
		}
		return " " + t.accentBold.Render(label) + " " + t.method(f.Method).Render(f.Method) + " " + f.URL + "  " + t.muted.Render(strings.Join(meta, " · "))
	}
	top := []string{" " + t.badge.Render(" compare ") + " " + t.muted.Render("what changed from A to B"),
		side("A", c.a), side("B", c.b)}
	if c.lines == nil || c.width != m.width {
		c.lines, c.width = m.compareLines(c.a, c.b), m.width
	}
	rows := max(m.height-len(top)-3, 1)
	c.at = min(c.at, max(len(c.lines)-rows, 0))
	var b strings.Builder
	for _, l := range top {
		b.WriteString(clip(l, m.width) + "\n")
	}
	b.WriteString(m.rule() + "\n")
	end := min(c.at+rows, len(c.lines))
	for _, l := range c.lines[c.at:end] {
		b.WriteString(clip(l, m.width) + "\n")
	}
	b.WriteString(strings.Repeat("\n", rows-(end-c.at)))
	b.WriteString(m.rule() + "\n")
	if s, ok := m.statusLine(); ok {
		b.WriteString(s)
		return b.String()
	}
	where := ""
	if len(c.lines) > rows {
		where = t.dim.Render(fmt.Sprintf("   %d–%d of %d", c.at+1, end, len(c.lines)))
	}
	b.WriteString(clip(t.hints("↑↓", "scroll", "s", "swap A and B", "esc", "back")+where, m.width))
	return b.String()
}

// compareLines are the scrolling part: each part of the two flows, its differences or
// "same".
func (m *Model) compareLines(a, b store.Flow) []string {
	t := m.t
	var lines []string
	section := func(name string) {
		w := len(name) + 3
		lines = append(lines, "", " "+t.accentBold.Render(name)+" "+t.dim.Render(strings.Repeat("─", max(m.width-w, 0))))
	}
	part := func(name string, x, y []string) {
		ops := diffLines(x, y)
		changed := 0
		for _, o := range ops {
			if o.kind != ' ' {
				changed++
			}
		}
		if changed == 0 {
			lines = append(lines, "   "+t.key.Render(name)+" "+t.muted.Render("same"))
			return
		}
		lines = append(lines, "   "+t.key.Render(name)+" "+t.warn.Render(fmt.Sprintf("%d line%s differ", changed, plural(changed))))
		for _, o := range collapse(ops, 2) {
			switch o.kind {
			case '-':
				lines = append(lines, clip("   "+t.bad.Render("- "+o.text), m.width))
			case '+':
				lines = append(lines, clip("   "+t.ok.Render("+ "+o.text), m.width))
			case '~':
				lines = append(lines, "   "+t.dim.Render("  "+o.text))
			default:
				lines = append(lines, clip("   "+t.muted.Render("  "+o.text), m.width))
			}
		}
	}
	section("Request")
	part("line", []string{a.Method + " " + a.URL}, []string{b.Method + " " + b.URL})
	if len(a.GraphQL)+len(b.GraphQL) > 0 {
		part("operation", []string{store.GraphQLLabel(a.GraphQL)}, []string{store.GraphQLLabel(b.GraphQL)})
	}
	part("headers", headerLines(a.ReqHeader), headerLines(b.ReqHeader))
	part("body", comparableBody(a.ReqBody, a.ReqHeader), comparableBody(b.ReqBody, b.ReqHeader))
	section("Response")
	part("status", []string{statusLine(a)}, []string{statusLine(b)})
	part("headers", headerLines(a.RespHeader), headerLines(b.RespHeader))
	part("body", comparableBody(a.RespBody, a.RespHeader), comparableBody(b.RespBody, b.RespHeader))
	return lines
}

func statusLine(f store.Flow) string {
	if f.Status == 0 {
		return "no response: " + f.Err
	}
	return strings.TrimSpace(fmt.Sprint(f.Status) + " " + http.StatusText(f.Status))
}

func headerLines(h http.Header) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(h)) {
		for _, v := range h[k] {
			out = append(out, k+": "+v)
		}
	}
	return out
}

// comparableBody is a body as lines to compare: JSON re-indented with its keys sorted,
// text as it is, and binary as its size.
func comparableBody(b store.Body, h http.Header) []string {
	d := store.Decode(b, h.Get("Content-Encoding"))
	if len(d.Data) == 0 {
		return nil
	}
	if !utf8.Valid(d.Data) {
		return []string{fmt.Sprintf("(binary, %s)", size(int64(len(d.Data))))}
	}
	data := d.Data
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if !d.Partial && dec.Decode(&v) == nil && !dec.More() {
		if out, err := json.MarshalIndent(v, "", "  "); err == nil { // maps marshal with sorted keys
			data = out
		}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if d.Partial {
		lines = append(lines, "(only the start was captured)")
	}
	return lines
}

// diffOp is one line of a diff: ' ' in both, '-' only in A, '+' only in B, and '~' for a
// run of same lines left out.
type diffOp struct {
	kind byte
	text string
}

// maxDiffCells bounds the table the middle of a diff takes: past it, the middle is shown
// as all of A's lines out and all of B's in.
const maxDiffCells = 4_000_000

// diffLines compares two lists of lines: the same start and end are cut off, and the
// middle is matched by longest common subsequence.
func diffLines(a, b []string) []diffOp {
	var head, tail []diffOp
	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		head = append(head, diffOp{' ', a[0]})
		a, b = a[1:], b[1:]
	}
	for len(a) > 0 && len(b) > 0 && a[len(a)-1] == b[len(b)-1] {
		tail = append(tail, diffOp{' ', a[len(a)-1]})
		a, b = a[:len(a)-1], b[:len(b)-1]
	}
	slices.Reverse(tail)
	var mid []diffOp
	table := lcsTable(a, b)
	if table == nil && len(a) > 0 && len(b) > 0 { // too big to match: A's lines out, B's in
		for _, l := range a {
			mid = append(mid, diffOp{'-', l})
		}
		for _, l := range b {
			mid = append(mid, diffOp{'+', l})
		}
		return append(append(head, mid...), tail...)
	}
	n, k := len(a), len(b)
	i, j := 0, 0
	for i < n || j < k {
		switch {
		case i < n && j < k && a[i] == b[j]:
			mid = append(mid, diffOp{' ', a[i]})
			i++
			j++
		case i < n && (j == k || table.at(i+1, j) >= table.at(i, j+1)): // A's line out first, as diff does
			mid = append(mid, diffOp{'-', a[i]})
			i++
		default:
			mid = append(mid, diffOp{'+', b[j]})
			j++
		}
	}
	return append(append(head, mid...), tail...)
}

// lcs holds the longest common subsequence of a[i:] and b[j:] for every i and j. It is
// exactly len(a) by len(b); past either end the answer is 0.
type lcs [][]int32

func (l lcs) at(i, j int) int32 {
	if i >= len(l) || j >= len(l[i]) {
		return 0
	}
	return l[i][j]
}

// lcsTable fills the table, or returns nil when it would be bigger than maxDiffCells.
func lcsTable(a, b []string) lcs {
	n, k := len(a), len(b)
	if n > maxDiffCells || k > maxDiffCells || n*k > maxDiffCells {
		return nil
	}
	t := make(lcs, n)
	for i := range t {
		t[i] = make([]int32, k)
	}
	for i := n - 1; i >= 0; i-- {
		for j := k - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i][j] = t.at(i+1, j+1) + 1
			} else {
				t[i][j] = max(t.at(i+1, j), t.at(i, j+1))
			}
		}
	}
	return t
}

// collapse keeps context lines of same lines around each change, and says how many it
// left out.
func collapse(ops []diffOp, context int) []diffOp {
	keep := make([]bool, len(ops))
	for i, o := range ops {
		if o.kind != ' ' {
			for j := max(i-context, 0); j <= min(i+context, len(ops)-1); j++ {
				keep[j] = true
			}
		}
	}
	var out []diffOp
	for i := 0; i < len(ops); {
		if keep[i] {
			out = append(out, ops[i])
			i++
			continue
		}
		j := i
		for j < len(ops) && !keep[j] {
			j++
		}
		out = append(out, diffOp{'~', fmt.Sprintf("… %d same line%s", j-i, plural(j-i))})
		i = j
	}
	return out
}
