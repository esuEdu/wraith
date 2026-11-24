package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// maxQuery is how much of a query string log lines keep (S3.3).
const maxQuery = 64

// formatFlow is one log-mode line: time, source, method, URL (query cut), status, size,
// duration and route. Never a header value or a body (S3.3). Tunnels show "tunnel"
// instead of a status when they opened.
func formatFlow(f store.Flow) string {
	var b strings.Builder
	b.WriteString(f.Start.Format("15:04:05"))
	if f.Source != "" {
		b.WriteString(" [" + f.Source + "]")
	}
	b.WriteString(" " + f.Method + " " + cutQuery(f.URL))
	switch {
	case f.Kind == store.KindTunnel && f.Status == 200:
		b.WriteString(" tunnel")
	case f.Status == 0:
		b.WriteString(" -")
	default:
		fmt.Fprintf(&b, " %d", f.Status)
	}
	if f.Kind == store.KindHTTP {
		b.WriteString(" " + humanSize(f.RespBody.Size) + " " + humanDuration(f.Duration))
	}
	if f.Route != "" {
		b.WriteString(" " + f.Route)
	}
	if f.Err != "" {
		b.WriteString(" (" + f.Err + ")")
	}
	return b.String()
}

// jsonFlow is the --json form of a log line: the same fields, nothing more (S3.3).
type jsonFlow struct {
	Time       string `json:"time"`
	Source     string `json:"source,omitempty"`
	Kind       string `json:"kind"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Size       int64  `json:"size"`
	DurationMS int64  `json:"duration_ms"`
	Route      string `json:"route,omitempty"`
	Error      string `json:"error,omitempty"`
}

func formatFlowJSON(f store.Flow) string {
	b, _ := json.Marshal(jsonFlow{
		Time: f.Start.Format(time.RFC3339Nano), Source: f.Source, Kind: f.Kind, Method: f.Method,
		URL: cutQuery(f.URL), Status: f.Status, Size: f.RespBody.Size,
		DurationMS: f.Duration.Milliseconds(), Route: f.Route, Error: f.Err,
	})
	return string(b)
}

// cutQuery keeps at most maxQuery characters of a URL's query string.
func cutQuery(u string) string {
	i := strings.IndexByte(u, '?')
	if i < 0 || len(u)-i-1 <= maxQuery {
		return u
	}
	return u[:i+1+maxQuery] + "…"
}

func humanSize(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d B", n)
	case n < 1000*1000:
		return fmt.Sprintf("%.1f kB", float64(n)/1000)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/1000/1000)
	}
}

func humanDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
