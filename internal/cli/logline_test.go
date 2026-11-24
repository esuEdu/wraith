package cli

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

func secretFlow() store.Flow {
	return store.Flow{
		Kind: store.KindHTTP, Start: time.Date(2026, 11, 23, 15, 4, 5, 0, time.UTC), Duration: 34 * time.Millisecond,
		Source: "sim iPhone 17 · Shop", Route: "direct", Method: "POST", Status: 201,
		URL:        "https://api.example.com/v1/login?session=" + strings.Repeat("s", 100) + "&token=SECRETQUERY",
		ReqHeader:  http.Header{"Authorization": {"Bearer SECRETHEADER"}, "Cookie": {"id=SECRETCOOKIE"}},
		RespHeader: http.Header{"Set-Cookie": {"id=SECRETSET"}},
		ReqBody:    store.Body{Data: []byte(`{"password":"SECRETBODY"}`), Size: 24},
		RespBody:   store.Body{Data: []byte(`{"token":"SECRETRESP"}`), Size: 1234},
	}
}

func TestS3_3_LogLinesNeverCarryHeadersOrBodies(t *testing.T) {
	f := secretFlow()
	for _, line := range []string{formatFlow(f), formatFlowJSON(f)} {
		if strings.Contains(line, "SECRET") {
			t.Fatalf("log line leaks a header value, body or long query:\n%s", line)
		}
		if !strings.Contains(line, "https://api.example.com/v1/login?session=") {
			t.Fatalf("method/host/path missing:\n%s", line)
		}
	}
	if got, want := formatFlow(f), "15:04:05 [sim iPhone 17 · Shop] POST https://api.example.com/v1/login?session="+strings.Repeat("s", 56)+"… 201 1.2 kB 34ms direct"; got != want {
		t.Fatalf("line\n%q\nwant\n%q", got, want)
	}
	short := store.Flow{Kind: store.KindTunnel, Method: "CONNECT", URL: "example.com:443", Status: 200, Route: "vpn"}
	if got := formatFlow(short); !strings.HasSuffix(got, " CONNECT example.com:443 tunnel vpn") {
		t.Fatalf("tunnel line %q", got)
	}
}

func TestLogModeJSON(t *testing.T) {
	ts, upstreamRoots := upstreamTLS(t)
	e := newEnv(t)
	e.origin = curl
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--source", "all", "--log", "--json")
	_, _ = fetch(t, addr, ts.URL+"/j", upstreamRoots) // Mac process, CA not trusted: a tunnel
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	var got map[string]any
	line := strings.TrimSpace(e.stdout.String())
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("not one JSON object per line: %q (%v)", line, err)
	}
	if got["kind"] != "tunnel" || got["method"] != "CONNECT" || got["source"] != "curl" || got["status"] != float64(200) {
		t.Fatalf("json %v", got)
	}
}

func TestR5_2_CapturedTrafficIsNeverWrittenToDisk(t *testing.T) {
	ts, _ := upstreamTLS(t)
	e := newEnv(t)
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--insecure-upstream", "127.0.0.1")
	files := func() []string {
		var out []string
		_ = filepath.WalkDir(e.dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				out = append(out, strings.TrimPrefix(p, e.dir))
			}
			return nil
		})
		slices.Sort(out)
		return out
	}
	before := files()
	roots := caPool(t, e)
	for i := range 5 {
		_, _ = fetch(t, addr, ts.URL+"/secret/"+string(rune('a'+i)), roots)
	}
	waitUntil(t, "the flow line", func() bool { return strings.Contains(e.stdout.String(), "/secret/e 200") })
	after := files()
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if !slices.Equal(before, after) {
		t.Fatalf("files changed while capturing:\nbefore %v\nafter  %v", before, after)
	}
	if !strings.Contains(e.stdout.String(), "/secret/e 200") {
		t.Fatalf("flows were not captured:\n%s", e.stdout)
	}
}

func TestS3_3_LogModeRedactsTokensInQueryStrings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	e := newEnv(t)
	e.origin = curl
	addr, done := e.startAsync("--port", freePort(t), "--no-system-proxy", "--source", "all")
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}}
	resp, err := c.Get(upstream.URL + "/cb?access_token=SECRETQ&page=2")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	waitUntil(t, "the flow line", func() bool { return strings.Contains(e.stdout.String(), "/cb?") })
	e.sigs <- syscall.SIGTERM
	waitExit(t, done)
	if out := e.stdout.String(); strings.Contains(out, "SECRETQ") || !strings.Contains(out, "access_token=REDACTED") {
		t.Fatalf("log line:\n%s", out)
	}
}
