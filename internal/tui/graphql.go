package tui

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/esuEdu/wraith/internal/store"
)

type gqlPart struct {
	title, note, text string
	json              bool
}

// graphQLParts are a GraphQL request's query and variables, each on its own, as the
// app wrote them: the body shows the query as one JSON string full of \n.
func graphQLParts(f store.Flow) []gqlPart {
	type req struct {
		Query     string          `json:"query"`
		Variables json.RawMessage `json:"variables"`
	}
	var reqs []req
	if f.Method == "GET" {
		if u, err := url.Parse(f.URL); err == nil {
			q := u.Query()
			reqs = []req{{Query: q.Get("query"), Variables: json.RawMessage(q.Get("variables"))}}
		}
	} else {
		b := bytes.TrimSpace(store.Decode(f.ReqBody, f.ReqHeader.Get("Content-Encoding")).Data)
		if len(b) > 0 && b[0] == '[' {
			_ = json.Unmarshal(b, &reqs)
		} else {
			var one req
			if json.Unmarshal(b, &one) == nil {
				reqs = []req{one}
			}
		}
	}
	var parts []gqlPart
	for i, r := range reqs {
		note := ""
		if i < len(f.GraphQL) {
			note = f.GraphQL[i].String()
		}
		if q := strings.TrimSpace(r.Query); q != "" {
			parts = append(parts, gqlPart{title: "Query", note: note, text: q})
		} else {
			parts = append(parts, gqlPart{title: "Query", note: note, text: "(persisted: the server knows it by its hash)"})
		}
		var buf bytes.Buffer
		if v := bytes.TrimSpace(r.Variables); len(v) > 0 && !bytes.Equal(v, []byte("null")) && json.Indent(&buf, v, "", "  ") == nil {
			parts = append(parts, gqlPart{title: "Variables", text: buf.String(), json: true})
		}
	}
	return parts
}
