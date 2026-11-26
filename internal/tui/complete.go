package tui

import (
	"cmp"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/esuEdu/wraith/internal/store"
)

// Tab in the filter completes the word being typed, as a shell does, from what has been
// captured: hosts, sources and apps, methods, statuses and routes, the body: and header:
// prefixes, and after header: the header names seen. One match is filled in; several are
// filled in as far as they agree and listed, and the next tab steps through them.

type completion struct {
	base  string   // the filter up to the word being completed, with its field prefix
	list  []string // the matches being stepped through
	at    int      // the one shown
	input string   // the filter as tab left it; any other edit ends the stepping
	note  string   // what the footer shows instead of the help
}

// maxNoted is how many matches the footer names.
const maxNoted = 6

// complete handles tab (step 1) and shift+tab (step -1) in the filter.
func (m *Model) complete(step int) {
	c := &m.comp
	if len(c.list) > 1 && m.input == c.input {
		c.at = (c.at + step + len(c.list)) % len(c.list)
		m.input = c.base + quote(c.list[c.at])
		c.input, c.note = m.input, m.noteFor(c.list, c.at)
		return
	}

	head, word := lastWord(m.input)
	field, prefix, rest := "", "", word
	for _, p := range []struct{ prefix, field string }{{"body:", "body"}, {"b:", "body"}, {"header:", "header"}, {"h:", "header"}, {"op:", "op"}} {
		if r, ok := strings.CutPrefix(strings.ToLower(word), p.prefix); ok {
			field, prefix, rest = p.field, word[:len(p.prefix)], r
			break
		}
	}
	rest = strings.TrimLeft(rest, `"`)
	if field == "body" {
		*c = completion{note: "bodies are not completed"}
		return
	}

	list := matching(m.candidates(field), rest)
	*c = completion{base: head + prefix}
	switch len(list) {
	case 0:
		c.note = "nothing captured matches " + strconv.Quote(word)
	case 1:
		m.input = c.base + quote(list[0])
		if !strings.HasSuffix(list[0], ":") {
			m.input += " "
		}
	default:
		if p := commonPrefix(list); len(p) > len(rest) && strings.HasPrefix(strings.ToLower(p), strings.ToLower(rest)) && !strings.Contains(p, " ") {
			m.input = c.base + p
			c.note = m.noteFor(list, -1)
			// The next tab starts stepping from the first match.
			c.list, c.at, c.input = list, -1, m.input
			if step < 0 {
				c.at = 0
			}
			return
		}
		c.list, c.at = list, 0
		if step < 0 {
			c.at = len(list) - 1
		}
		m.input = c.base + quote(list[c.at])
		c.note = m.noteFor(list, c.at)
	}
	c.input = m.input
}

// candidates are the words the filter could complete to, most seen first.
func (m *Model) candidates(field string) []string {
	seen := map[string]int{}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			seen[s]++
		}
	}
	anyGraphQL := false
	for _, f := range m.flows {
		anyGraphQL = anyGraphQL || len(f.GraphQL) > 0
		if field == "op" {
			for _, o := range f.GraphQL {
				add(o.Name)
			}
			continue
		}
		if field == "header" {
			for k := range f.ReqHeader {
				add(strings.ToLower(k))
			}
			for k := range f.RespHeader {
				add(strings.ToLower(k))
			}
			continue
		}
		add(hostOf(f))
		add(f.Source)
		if _, app, ok := strings.Cut(f.Source, " · "); ok {
			add(app)
		}
		add(f.Method)
		if f.Status != 0 {
			add(strconv.Itoa(f.Status))
		}
		add(f.Via())
	}
	list := make([]string, 0, len(seen)+2)
	for s := range seen {
		list = append(list, s)
	}
	slices.SortFunc(list, func(a, b string) int {
		if c := cmp.Compare(seen[b], seen[a]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	if field == "" {
		list = append(list, "body:", "header:")
		if anyGraphQL {
			list = append(list, "op:")
		}
	}
	return list
}

// matching keeps the candidates that start with typed, ignoring case; if none do, those
// that contain it, so "shop" still finds api.shop.example.
func matching(list []string, typed string) []string {
	t := strings.ToLower(typed)
	var starts, contains []string
	for _, s := range list {
		l := strings.ToLower(s)
		switch {
		case l == t:
			return []string{s}
		case strings.HasPrefix(l, t):
			starts = append(starts, s)
		case strings.Contains(l, t):
			contains = append(contains, s)
		}
	}
	if len(starts) > 0 {
		return starts
	}
	return contains
}

func hostOf(f store.Flow) string {
	if f.Kind == store.KindTunnel {
		h, _, _ := strings.Cut(f.URL, ":")
		return strings.ToLower(h)
	}
	if u, err := url.Parse(f.URL); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// lastWord splits the filter before the word being typed, minding quotes.
func lastWord(s string) (head, word string) {
	quoted, cut := false, 0
	for i, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			cut = i + 1
		}
	}
	return s[:cut], s[cut:]
}

// quote keeps a match with spaces in one term.
func quote(s string) string {
	if strings.Contains(s, " ") {
		return `"` + s + `"`
	}
	return s
}

// commonPrefix is how far the matches agree, ignoring case, in the first one's spelling.
func commonPrefix(list []string) string {
	p := []rune(list[0])
	for _, s := range list[1:] {
		r := []rune(s)
		n := 0
		for n < len(p) && n < len(r) && unicode.ToLower(p[n]) == unicode.ToLower(r[n]) {
			n++
		}
		p = p[:n]
	}
	return string(p)
}

// noteFor names the matches for the footer, marking the one shown (at < 0: none).
func (m *Model) noteFor(list []string, at int) string {
	var parts []string
	start := 0
	if at >= maxNoted {
		start = at - maxNoted + 1
	}
	for i := start; i < len(list) && i < start+maxNoted; i++ {
		s := list[i]
		if i == at {
			s = "[" + s + "]"
		}
		parts = append(parts, s)
	}
	note := strings.Join(parts, "  ")
	if more := len(list) - len(parts); more > 0 {
		note += "  +" + strconv.Itoa(more)
	}
	return note
}
