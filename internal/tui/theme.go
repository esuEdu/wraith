package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// DefaultTheme is the theme the live view starts with.
const DefaultTheme = "heliotrope-haze"

// Themes are the names SetTheme accepts.
var Themes = []string{"heliotrope-haze", "terminal"}

// theme is every style the live view draws with.
type theme struct {
	bg, fg color.Color // the screen's colors while wraith runs; nil keeps the terminal's

	dim        lipgloss.Style // rules, times, punctuation
	muted      lipgloss.Style // secondary text: paths, notes, hint descriptions
	bold       lipgloss.Style
	accent     lipgloss.Style
	accentBold lipgloss.Style
	mark       lipgloss.Style // the selection bar and the picker's cursor
	badge      lipgloss.Style // " wraith " in the header
	selected   lipgloss.Style // the selected row
	tabOn      lipgloss.Style
	tabOff     lipgloss.Style
	key        lipgloss.Style // header names

	ok, warn, bad, direct lipgloss.Style

	get, post, put, del lipgloss.Style // methods

	jsonKey, jsonStr, jsonNum, jsonLit, jsonPunct lipgloss.Style
}

// heliotropeHaze is Rex's Heliotrope Haze: a dark violet background with soft pastel
// colors, and heliotrope as the accent.
func heliotropeHaze() *theme {
	var (
		bg      = lipgloss.Color("#14101f")
		fg      = lipgloss.Color("#dcd2ee")
		surface = lipgloss.Color("#3a2b5c")
		bright  = lipgloss.Color("#f0eaf9")
		comment = lipgloss.Color("#6a5f85")
		soft    = lipgloss.Color("#b6abd0")
		helio   = lipgloss.Color("#c980f2")
		pink    = lipgloss.Color("#ff7edb")
		red     = lipgloss.Color("#f66e93")
		green   = lipgloss.Color("#72e0aa")
		yellow  = lipgloss.Color("#fdca6a")
		blue    = lipgloss.Color("#7a9bf5")
		cyan    = lipgloss.Color("#5fd0e5")
	)
	st := lipgloss.NewStyle
	return &theme{
		bg: bg, fg: fg,
		dim:        st().Foreground(comment),
		muted:      st().Foreground(soft),
		bold:       st().Bold(true).Foreground(bright),
		accent:     st().Foreground(helio),
		accentBold: st().Foreground(helio).Bold(true),
		mark:       st().Foreground(pink),
		badge:      st().Bold(true).Foreground(bg).Background(helio),
		selected:   st().Foreground(bright).Background(surface),
		tabOn:      st().Bold(true).Foreground(bg).Background(helio),
		tabOff:     st().Foreground(soft).Background(surface),
		key:        st().Foreground(blue),
		ok:         st().Foreground(green),
		warn:       st().Foreground(yellow),
		bad:        st().Foreground(red),
		direct:     st().Foreground(cyan),
		get:        st().Bold(true).Foreground(blue),
		post:       st().Bold(true).Foreground(green),
		put:        st().Bold(true).Foreground(yellow),
		del:        st().Bold(true).Foreground(red),
		jsonKey:    st().Foreground(blue),
		jsonStr:    st().Foreground(green),
		jsonNum:    st().Foreground(yellow),
		jsonLit:    st().Foreground(pink),
		jsonPunct:  st().Foreground(comment),
	}
}

// terminalTheme uses only the terminal's 16 ANSI colors plus bold, faint and reverse, so
// wraith looks like the rest of the terminal in any light or dark theme. Cyan is the
// accent.
func terminalTheme() *theme {
	st := lipgloss.NewStyle
	faint := st().Faint(true)
	return &theme{
		dim:        faint,
		muted:      faint,
		bold:       st().Bold(true),
		accent:     st().Foreground(lipgloss.Cyan),
		accentBold: st().Foreground(lipgloss.Cyan).Bold(true),
		mark:       st().Foreground(lipgloss.Cyan),
		badge:      st().Bold(true).Reverse(true).Foreground(lipgloss.Cyan),
		selected:   st().Reverse(true),
		tabOn:      st().Bold(true).Reverse(true).Foreground(lipgloss.Cyan),
		tabOff:     faint,
		key:        st().Foreground(lipgloss.Cyan),
		ok:         st().Foreground(lipgloss.Green),
		warn:       st().Foreground(lipgloss.Yellow),
		bad:        st().Foreground(lipgloss.Red),
		direct:     st().Foreground(lipgloss.Magenta),
		get:        st().Bold(true).Foreground(lipgloss.Blue),
		post:       st().Bold(true).Foreground(lipgloss.Green),
		put:        st().Bold(true).Foreground(lipgloss.Yellow),
		del:        st().Bold(true).Foreground(lipgloss.Red),
		jsonKey:    st().Foreground(lipgloss.Blue),
		jsonStr:    st().Foreground(lipgloss.Green),
		jsonNum:    st().Foreground(lipgloss.Yellow),
		jsonLit:    st().Foreground(lipgloss.Magenta),
		jsonPunct:  faint,
	}
}

func themeNamed(name string) (*theme, bool) {
	switch name {
	case "heliotrope-haze":
		return heliotropeHaze(), true
	case "terminal":
		return terminalTheme(), true
	}
	return nil, false
}

// method is the style for an HTTP method.
func (t *theme) method(m string) lipgloss.Style {
	switch strings.ToUpper(m) {
	case "GET", "HEAD":
		return t.get
	case "POST":
		return t.post
	case "PUT", "PATCH":
		return t.put
	case "DELETE":
		return t.del
	}
	return t.bold
}

// status is the style for a status code.
func (t *theme) status(code int) lipgloss.Style {
	switch {
	case code == 0 || code >= 500:
		return t.bad
	case code >= 400:
		return t.warn
	case code >= 300:
		return t.accent
	}
	return t.ok
}

// hints draws key/description pairs: " ↵ details  / filter …".
func (t *theme) hints(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, t.accentBold.Render(pairs[i])+" "+t.muted.Render(pairs[i+1]))
	}
	return " " + strings.Join(parts, "  ")
}
