package tui

import (
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/esuEdu/wraith/internal/store"
)

// The filter (/) is a list of terms, all of which must match a flow:
//   - a plain word matches its summary: source, method, URL, status, route, kind, error;
//   - body:<text> matches the request or response body, decoded as the details show it;
//   - header:<text> matches any request or response header name or value;
//   - op:<name> matches a GraphQL operation, e.g. op:GetCart or op:mutation.
// "quotes" keep spaces in a term: body:"user id".

type term struct {
	field string // "", "body" or "header"
	text  string // lower case
}

// parseFilter splits a filter into terms.
func parseFilter(q string) []term {
	var terms []term
	for _, w := range splitQuoted(q) {
		t := term{text: strings.ToLower(w)}
		for _, f := range []struct{ prefix, field string }{{"body:", "body"}, {"b:", "body"}, {"header:", "header"}, {"h:", "header"}, {"op:", "op"}} {
			if rest, ok := strings.CutPrefix(t.text, f.prefix); ok {
				t = term{field: f.field, text: strings.Trim(rest, `"`)}
				break
			}
		}
		if t.text != "" {
			terms = append(terms, t)
		}
	}
	return terms
}

// splitQuoted splits on spaces outside double quotes, dropping the quotes.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// matches reports whether every term of the filter matches f.
func (m *Model) matches(f store.Flow) bool {
	if len(m.terms) == 0 {
		return true
	}
	ops := strings.ToLower(store.GraphQLLabel(f.GraphQL))
	summary := strings.ToLower(fmt.Sprintf("%s %s %s %d %s %s %s", f.Source, f.Method, f.URL, f.Status, f.Route, f.Kind, f.Err)) + " " + ops
	for _, t := range m.terms {
		var hay string
		switch t.field {
		case "body":
			hay = m.bodyIndex(f)
		case "header":
			hay = headerText(f.ReqHeader) + "\n" + headerText(f.RespHeader)
		case "op":
			hay = ops
		default:
			hay = summary
		}
		if !strings.Contains(hay, t.text) {
			return false
		}
	}
	return true
}

func headerText(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(strings.ToLower(k) + ": " + strings.ToLower(v) + "\n")
		}
	}
	return b.String()
}

// maxIndexed is how much of each decoded body the search looks at.
const maxIndexed = 1 << 20

// bodyIndex is the request and response bodies of f, decoded and in lower case, kept
// per flow so a filter does not decode every body again as each new flow arrives.
func (m *Model) bodyIndex(f store.Flow) string {
	if s, ok := m.bodies[f.ID]; ok && f.ID != 0 {
		return s
	}
	text := func(b store.Body, h http.Header) string {
		d := store.Decode(b, h.Get("Content-Encoding"))
		data := d.Data
		if len(data) > maxIndexed {
			data = data[:maxIndexed]
		}
		if !utf8.Valid(data) {
			return ""
		}
		return strings.ToLower(string(data))
	}
	s := text(f.ReqBody, f.ReqHeader) + "\n" + text(f.RespBody, f.RespHeader)
	for _, msg := range f.Messages { // a WebSocket's messages count as its body
		if utf8.Valid(msg.Data) {
			s += "\n" + strings.ToLower(string(msg.Data))
		}
	}
	if f.ID != 0 {
		m.bodies[f.ID] = s
	}
	return s
}
