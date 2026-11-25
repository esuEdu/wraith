package tui

import (
	"maps"
	"net/http"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/esuEdu/wraith/internal/store"
)

// The details copy one part of a flow at a time: the body or the headers of the tab on
// screen, the URL, or the request as curl. Headers and URLs are redacted like exports;
// bodies are copied decoded, as shown.

func (m *Model) copyCurl() tea.Cmd {
	f, ok := m.selected()
	if !ok {
		return nil
	}
	if f.Kind != store.KindHTTP {
		m.say("a tunnel has no request to copy (it was not decrypted)")
		return nil
	}
	m.say("copied the request as curl (secrets redacted)")
	return tea.SetClipboard(m.act.Curl(f))
}

// part is the headers and body of the tab on screen, and its name.
func (m *Model) part(f store.Flow) (name string, h http.Header, b store.Body) {
	if m.tabOf(f) == tabRequest {
		return "request", f.ReqHeader, f.ReqBody
	}
	return "response", f.RespHeader, f.RespBody
}

func (m *Model) copyBody() tea.Cmd {
	f, ok := m.selected()
	if !ok || f.Kind != store.KindHTTP {
		return nil
	}
	name, h, body := m.part(f)
	if body.Size == 0 {
		m.say("the " + name + " has no body")
		return nil
	}
	d := store.Decode(body, h.Get("Content-Encoding"))
	text, _, ok := bodyText(d)
	if !ok {
		m.say("the " + name + " body is binary; nothing copied")
		return nil
	}
	msg := "copied the " + name + " body (" + size(int64(len(text))) + ")"
	if d.Partial {
		msg += "; only its start was captured"
	}
	m.say(msg)
	return tea.SetClipboard(text)
}

func (m *Model) copyHeaders() tea.Cmd {
	f, ok := m.selected()
	if !ok || f.Kind != store.KindHTTP {
		return nil
	}
	name, h, _ := m.part(f)
	if len(h) == 0 {
		m.say("the " + name + " has no headers")
		return nil
	}
	r := m.act.Redactor()
	var b strings.Builder
	var hidden []string
	for _, k := range slices.Sorted(maps.Keys(h)) {
		if r.Matches(k) {
			hidden = append(hidden, k)
		}
	}
	red := r.Header(h)
	for _, k := range slices.Sorted(maps.Keys(red)) {
		for _, v := range red[k] {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	msg := "copied the " + name + " headers"
	if len(hidden) > 0 {
		msg += " (" + strings.Join(hidden, ", ") + " redacted)"
	}
	m.say(msg)
	return tea.SetClipboard(b.String())
}

func (m *Model) copyURL() tea.Cmd {
	f, ok := m.selected()
	if !ok {
		return nil
	}
	if f.Kind != store.KindHTTP {
		m.say("copied the host")
		return tea.SetClipboard(f.URL)
	}
	u := m.act.Redactor().URL(f.URL)
	msg := "copied the URL"
	if u != f.URL {
		msg += " (secrets redacted)"
	}
	m.say(msg)
	return tea.SetClipboard(u)
}
