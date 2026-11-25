package store

import (
	"net/http"
	"testing"
)

func TestGraphQLOperationsAreFoundInRequests(t *testing.T) {
	post := func(body string, h http.Header) string {
		return GraphQLLabel(GraphQLOperations("POST", "https://api.x/graphql", h, []byte(body)))
	}
	cases := map[string]string{
		`{"operationName":"GetCart","query":"query GetCart($id: ID!) { cart(id: $id) { total } }"}`:    "query GetCart",
		`{"query":"mutation AddItem { add(sku: \"A1\") { ok } }"}`:                                     "mutation AddItem",
		`{"query":"{ me { name } }"}`:                                                                  "query (anonymous)",
		`{"query":"# a comment with query Fake\nsubscription OnCart { cart { total } }"}`:              "subscription OnCart",
		`{"operationName":"B","query":"query A { a } mutation B { b }"}`:                               "mutation B",
		`[{"query":"query A { a }"},{"query":"mutation B { b }"}]`:                                     "query A + mutation B",
		`{"query":"query Search { search(query: \"shoes\") { id } }"}`:                                 "query Search",
		`{"operationName":"GetCart","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`: "GetCart",
	}
	for body, want := range cases {
		if got := post(body, nil); got != want {
			t.Errorf("%s:\n got %q, want %q", body, got, want)
		}
	}
	// Apollo iOS names a persisted query's kind in a header.
	if got := post(`{"operationName":"GetCart","extensions":{"persistedQuery":{"version":1}}}`, http.Header{"X-Apollo-Operation-Type": {"query"}}); got != "query GetCart" {
		t.Errorf("persisted with headers: %q", got)
	}
	if got := GraphQLLabel(GraphQLOperations("GET", "https://api.x/graphql?query=query%20Me%20%7B%20me%20%7D", nil, nil)); got != "query Me" {
		t.Errorf("GET: %q", got)
	}
	for _, notGraphQL := range []string{`{"sku":"A1"}`, `[1,2]`, `not json`, ``, `{"operationName":"X"}`} {
		if ops := GraphQLOperations("POST", "https://api.x/v2/cart", nil, []byte(notGraphQL)); ops != nil {
			t.Errorf("%q taken for GraphQL: %v", notGraphQL, ops)
		}
	}
	if ops := GraphQLOperations("GET", "https://api.x/v2/cart?page=2", nil, nil); ops != nil {
		t.Errorf("a GET without ?query= taken for GraphQL: %v", ops)
	}
}

func TestGraphQLErrorsAreCounted(t *testing.T) {
	for body, want := range map[string]int{
		`{"data":{"cart":null},"errors":[{"message":"not found"},{"message":"again"}]}`: 2,
		`{"data":{"cart":{"total":1}}}`:              0,
		`[{"errors":[{"message":"a"}]},{"data":{}}]`: 1,
		`<html>`: 0,
	} {
		if got := GraphQLErrors([]byte(body)); got != want {
			t.Errorf("%s: %d, want %d", body, got, want)
		}
	}
	f := Flow{Kind: KindHTTP, Method: "POST", URL: "https://api.x/graphql",
		ReqBody: Body{Data: []byte(`{"query":"query GetCart { cart { total } }"}`)}, RespBody: Body{Data: []byte(`{"errors":[{}]}`)}}
	f.SetGraphQL()
	if GraphQLLabel(f.GraphQL) != "query GetCart" || f.GraphQLErrors != 1 {
		t.Fatalf("SetGraphQL: %v %d", f.GraphQL, f.GraphQLErrors)
	}
	plain := Flow{Kind: KindHTTP, Method: "POST", URL: "https://api.x/v2", ReqBody: Body{Data: []byte(`{}`)}, RespBody: Body{Data: []byte(`{"errors":[{}]}`)}}
	plain.SetGraphQL()
	if plain.GraphQL != nil || plain.GraphQLErrors != 0 {
		t.Fatalf("a REST call counted as GraphQL: %+v", plain)
	}
}

func FuzzGraphQLOperations(f *testing.F) {
	f.Add([]byte(`{"query":"query A { a }"}`))
	f.Add([]byte(`[{"query":"{ a }"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = GraphQLOperations("POST", "https://x/graphql", nil, b)
		_ = GraphQLErrors(b)
	})
}
