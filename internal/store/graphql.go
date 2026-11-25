package store

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// GraphQL apps send every request to one endpoint, so the URL says little: what matters
// is the operation in the body. These read it, for the list, the filter (op:) and mocks.

// GraphQLOp is one operation of a GraphQL request.
type GraphQLOp struct {
	Kind string // query, mutation or subscription; "" when only the name is known
	Name string // "" for an anonymous operation
}

func (o GraphQLOp) String() string {
	name := o.Name
	if name == "" {
		name = "(anonymous)"
	}
	if o.Kind == "" {
		return name
	}
	return o.Kind + " " + name
}

// GraphQLLabel writes a request's operations for the list: "query GetCart", or
// "query GetCart + mutation AddItem" for a batch.
func GraphQLLabel(ops []GraphQLOp) string {
	parts := make([]string, len(ops))
	for i, o := range ops {
		parts[i] = o.String()
	}
	return strings.Join(parts, " + ")
}

// maxGraphQLBody is the most of a body read to find its operations.
const maxGraphQLBody = 1 << 20

type gqlRequest struct {
	Query         *string         `json:"query"`
	OperationName string          `json:"operationName"`
	Extensions    json.RawMessage `json:"extensions"`
}

// GraphQLOperations finds the operations of a GraphQL request: a JSON body (or a batch
// of them) with a query, or a persisted query's name; or a GET with ?query=. Apollo's
// X-APOLLO-OPERATION-NAME and -TYPE headers fill in what the body leaves out. It returns
// nil for anything else.
func GraphQLOperations(method, rawURL string, h http.Header, body []byte) []GraphQLOp {
	var reqs []gqlRequest
	switch {
	case method == http.MethodGet:
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil
		}
		q := u.Query()
		if !q.Has("query") && !q.Has("operationName") {
			return nil
		}
		query := q.Get("query")
		reqs = []gqlRequest{{Query: &query, OperationName: q.Get("operationName")}}
	case len(body) > 0 && len(body) <= maxGraphQLBody:
		b := bytes.TrimSpace(body)
		if len(b) > 0 && b[0] == '[' {
			if json.Unmarshal(b, &reqs) != nil {
				return nil
			}
		} else {
			var one gqlRequest
			if json.Unmarshal(b, &one) != nil {
				return nil
			}
			reqs = []gqlRequest{one}
		}
	default:
		return nil
	}
	var ops []GraphQLOp
	for _, r := range reqs {
		persisted := len(r.Extensions) > 0 && bytes.Contains(r.Extensions, []byte(`"persistedQuery"`))
		if r.Query == nil && !persisted {
			return nil // not GraphQL: some other JSON
		}
		op := GraphQLOp{Name: r.OperationName}
		if r.Query != nil {
			op.Kind, op.Name = operationIn(*r.Query, r.OperationName)
		}
		ops = append(ops, op)
	}
	if len(ops) == 1 { // Apollo iOS names the operation in headers too
		if n := h.Get("X-Apollo-Operation-Name"); ops[0].Name == "" && n != "" {
			ops[0].Name = n
		}
		if k := strings.ToLower(h.Get("X-Apollo-Operation-Type")); ops[0].Kind == "" && graphQLKinds[k] {
			ops[0].Kind = k
		}
	}
	return ops
}

var (
	graphQLKinds = map[string]bool{"query": true, "mutation": true, "subscription": true}
	gqlComment   = regexp.MustCompile(`#[^\n]*`)
	gqlOperation = regexp.MustCompile(`(?:^|[\s}])(query|mutation|subscription)\b\s*([_A-Za-z][_0-9A-Za-z]*)?`)
)

// operationIn reads the kind and name of the operation a query document runs: the one
// called name, or its first operation. A document that starts with "{" is a query.
func operationIn(doc, name string) (kind, opName string) {
	doc = gqlComment.ReplaceAllString(doc, "")
	if strings.TrimSpace(doc) == "" {
		return "", name
	}
	matches := gqlOperation.FindAllStringSubmatch(doc, -1)
	for _, m := range matches {
		if name == "" || m[2] == name {
			if name == "" {
				name = m[2]
			}
			return m[1], name
		}
	}
	if strings.HasPrefix(strings.TrimSpace(doc), "{") || len(matches) == 0 {
		return "query", name
	}
	return "", name
}

// GraphQLErrors counts the errors a GraphQL response reports: GraphQL answers 200 even
// when the operation failed, with an "errors" list in the body.
func GraphQLErrors(body []byte) int {
	b := bytes.TrimSpace(body)
	if len(b) == 0 || len(b) > MaxDecoded {
		return 0
	}
	type resp struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if b[0] == '[' {
		var batch []resp
		if json.Unmarshal(b, &batch) != nil {
			return 0
		}
		n := 0
		for _, r := range batch {
			n += len(r.Errors)
		}
		return n
	}
	var r resp
	if json.Unmarshal(b, &r) != nil {
		return 0
	}
	return len(r.Errors)
}
