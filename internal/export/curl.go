package export

import (
	"sort"
	"strings"

	"github.com/esuEdu/wraith/internal/store"
)

// Curl renders a flow's request as a curl command that repeats it, secrets redacted by r.
// Hop-by-hop and length headers curl sets itself are left out.
func Curl(f store.Flow, r Redactor) string {
	parts := []string{"curl"}
	if f.Method != "" && f.Method != "GET" {
		parts = append(parts, "-X", f.Method)
	}
	parts = append(parts, shellQuote(r.URL(f.URL)))
	h := r.Header(f.ReqHeader)
	keys := make([]string, 0, len(h))
	for k := range h {
		switch strings.ToLower(k) {
		case "content-length", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "upgrade", "host":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			parts = append(parts, "-H", shellQuote(k+": "+v))
		}
	}
	if f.ReqBody.Size > 0 {
		parts = append(parts, "--data-binary", shellQuote(string(f.ReqBody.Data)))
	}
	cmd := strings.Join(parts, " ")
	if f.ReqBody.Truncated {
		cmd += " # request body truncated by wraith"
	}
	return cmd
}

// shellQuote quotes s for a POSIX shell: single quotes, with embedded ones escaped.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
