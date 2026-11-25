package proxy

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/esuEdu/wraith/internal/store"
)

func TestReplaySendsTheRequestAgainAndRecordsIt(t *testing.T) {
	type seen struct{ method, path, body, auth, hop, ctype string }
	got := make(chan seen, 4)
	ts := upstreamServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.URL.RequestURI(), string(b), r.Header.Get("Authorization"), r.Header.Get("X-Hop"), r.Header.Get("Content-Type")}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	e := startMITM(t, poolOf(ts.Certificate()), nil)

	orig := store.Flow{ID: 7, Kind: store.KindHTTP, Source: "sim iPhone 17 · Shop", Method: "POST", URL: ts.URL + "/v2/orders?x=1",
		ReqHeader: http.Header{"Authorization": {"Bearer s3cret"}, "Content-Type": {"application/json"}, "Connection": {"X-Hop"}, "X-Hop": {"drop"}, "Content-Length": {"999"}},
		ReqBody:   store.Body{Data: []byte(`{"item":42}`), Size: 11}}
	f, err := e.srv.Replay(context.Background(), orig)
	if err != nil {
		t.Fatal(err)
	}
	s := <-got
	if s != (seen{"POST", "/v2/orders?x=1", `{"item":42}`, "Bearer s3cret", "", "application/json"}) {
		t.Fatalf("upstream saw %+v", s)
	}
	if f.ID == 0 || f.Status != 201 || f.Source != "replay · sim iPhone 17 · Shop" || string(f.RespBody.Data) != `{"ok":true}` ||
		string(f.ReqBody.Data) != `{"item":42}` || f.URL != orig.URL {
		t.Fatalf("recorded %+v", f)
	}
	if flows := e.store.Flows(); len(flows) != 1 || flows[0].ID != f.ID {
		t.Fatalf("store %+v", flows)
	}

	// The upstream certificate is still verified (S2.3).
	strict := startMITM(t, x509.NewCertPool(), nil)
	if f, err := strict.srv.Replay(context.Background(), store.Flow{Kind: store.KindHTTP, Method: "GET", URL: ts.URL + "/"}); err == nil ||
		f.Status != http.StatusBadGateway || !strings.Contains(f.Err, "certificate") {
		t.Fatalf("unverified upstream: %+v %v", f, err)
	}

	for name, bad := range map[string]store.Flow{
		"tunnel":    {Kind: store.KindTunnel, Method: "CONNECT", URL: "pinned.test:443"},
		"cut body":  {Kind: store.KindHTTP, Method: "POST", URL: ts.URL, ReqBody: store.Body{Data: []byte("abc"), Size: 9000, Truncated: true}},
		"not a URL": {Kind: store.KindHTTP, Method: "GET", URL: "ftp://x"},
	} {
		if _, err := e.srv.Replay(context.Background(), bad); err == nil {
			t.Errorf("%s: resent", name)
		}
	}
}
