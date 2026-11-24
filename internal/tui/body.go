package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"

	"github.com/esuEdu/wraith/internal/store"
)

// maxHighlight is the largest body the details color as JSON; bigger ones are shown plain
// so opening them stays quick.
const maxHighlight = 1 << 20

// seg is a piece of a line drawn in one style; a nil style draws it as is.
type seg struct {
	text string
	st   *lipgloss.Style
}

func render(segs []seg) string {
	var b strings.Builder
	for _, s := range segs {
		if s.st == nil {
			b.WriteString(s.text)
		} else {
			b.WriteString(s.st.Render(s.text))
		}
	}
	return b.String()
}

// wrapSegs breaks a line into lines of at most width display cells, keeping each piece's
// style; lines after the first start with indent spaces. With trim set, a space that
// falls at the start of a new line is dropped, as for header values.
func wrapSegs(segs []seg, width, indent int, trim bool) [][]seg {
	if width <= indent {
		return [][]seg{segs}
	}
	var (
		out  [][]seg
		line []seg
		cur  strings.Builder
		w    int
	)
	flush := func(st *lipgloss.Style) {
		if cur.Len() > 0 {
			line = append(line, seg{cur.String(), st})
			cur.Reset()
		}
	}
	for _, s := range segs {
		for _, r := range s.text {
			rw := 1
			if r >= utf8.RuneSelf {
				rw = max(lipgloss.Width(string(r)), 0)
			}
			if w+rw > width && w > indent {
				flush(s.st)
				out = append(out, line)
				line = []seg{{strings.Repeat(" ", indent), nil}}
				w = indent
				if trim && r == ' ' {
					continue
				}
			}
			cur.WriteRune(r)
			w += rw
		}
		flush(s.st)
	}
	return append(out, line)
}

// bodyText is a decoded body as text to show, pretty-printed when it is JSON; ok is
// false for an empty or binary body.
func bodyText(d store.Decoded) (text string, isJSON, ok bool) {
	data := d.Data
	if d.Partial { // the cut may fall inside a character
		for i := 0; i < utf8.UTFMax-1 && len(data) > 0 && !utf8.Valid(data); i++ {
			data = data[:len(data)-1]
		}
	}
	if len(data) == 0 || !utf8.Valid(data) {
		return "", false, false
	}
	var buf bytes.Buffer
	if !d.Partial && json.Indent(&buf, data, "", "  ") == nil {
		return buf.String(), true, true
	}
	return string(data), false, true
}

// jsonSegs colors one line of indented JSON: keys, strings, numbers, true/false/null and
// punctuation each get their style.
func (t *theme) jsonSegs(line string) []seg {
	var out []seg
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			j := i
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			out = append(out, seg{line[i:j], nil})
			i = j
		case c == '"':
			j := i + 1
			for j < len(line) && line[j] != '"' {
				if line[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, len(line))
			st := &t.jsonStr
			if strings.HasPrefix(strings.TrimLeft(line[j:], " "), ":") {
				st = &t.jsonKey
			}
			out = append(out, seg{line[i:j], st})
			i = j
		case strings.ContainsRune("{}[]:,", rune(c)):
			out = append(out, seg{line[i : i+1], &t.jsonPunct})
			i++
		default:
			j := i
			for j < len(line) && !strings.ContainsRune(" \t{}[]:,\"", rune(line[j])) {
				j++
			}
			st := &t.jsonNum
			switch line[i:j] {
			case "true", "false", "null":
				st = &t.jsonLit
			}
			out = append(out, seg{line[i:j], st})
			i = j
		}
	}
	return out
}

func (t *theme) bodySummary(b store.Body, d store.Decoded, text bool) string {
	if b.Size == 0 {
		return t.muted.Render("no body")
	}
	s := size(b.Size)
	if d.Encoding != "" {
		s += fmt.Sprintf(" %s, %s decoded", d.Encoding, size(int64(len(d.Data))))
	}
	if !text {
		s = "binary, " + s
	}
	switch {
	case d.Partial && d.Encoding == "":
		s += fmt.Sprintf(", first %s shown", size(int64(len(d.Data))))
	case d.Partial:
		s += ", only the start"
	}
	if d.Err != "" {
		s += "; " + d.Err
	}
	return t.muted.Render(s)
}

// size is a byte count for people: 328 B, 4.1 kB, 2.3 MB.
func size(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d B", n)
	case n < 1000*1000:
		return fmt.Sprintf("%.1f kB", float64(n)/1000)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/1000/1000)
}
