package export

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

func secretFlow() store.Flow {
	return store.Flow{
		Kind: store.KindHTTP, Start: time.Date(2026, 11, 23, 18, 0, 0, 0, time.UTC), Duration: 42 * time.Millisecond,
		Source: "sim iPhone 17 · Shop", Throttle: "3g", Method: "POST", Proto: "HTTP/2.0", Status: 201,
		URL: "https://api.example.com/v1/login?access_token=SECRETQUERY&page=2",
		ReqHeader: http.Header{
			"Authorization": {"Bearer SECRETAUTH"}, "Cookie": {"id=SECRETCOOKIE"},
			"X-Csrf-Token": {"SECRETCSRF"}, "Content-Type": {"application/json"}, "Accept": {"*/*"},
		},
		RespHeader: http.Header{"Set-Cookie": {"id=SECRETSET"}, "Content-Type": {"application/json"}},
		ReqBody:    store.Body{Data: []byte(`{"user":"o'neil"}`), Size: 17},
		RespBody:   store.Body{Data: []byte(`{"ok":true}`), Size: 5000, Truncated: true},
	}
}

func TestR5_3_ExportsRedactSecretsByDefault(t *testing.T) {
	f := secretFlow()
	tunnel := store.Flow{Kind: store.KindTunnel, Method: "CONNECT", URL: "pinned.example.com:443", Status: 200}
	har, err := HAR([]store.Flow{f, tunnel}, NewRedactor(DefaultPatterns))
	if err != nil {
		t.Fatal(err)
	}
	curl := Curl(f, NewRedactor(DefaultPatterns))
	for name, out := range map[string]string{"HAR": string(har), "curl": curl} {
		if strings.Contains(out, "SECRET") {
			t.Errorf("%s leaks a secret:\n%s", name, out)
		}
		if !strings.Contains(out, Redacted) || !strings.Contains(out, "page=2") || !strings.Contains(out, "application/json") {
			t.Errorf("%s redacted too much or too little:\n%s", name, out)
		}
	}

	raw, _ := HAR([]store.Flow{f}, NewRedactor(nil)) // --no-redact
	for _, secret := range []string{"SECRETAUTH", "SECRETCOOKIE", "SECRETCSRF", "SECRETSET", "SECRETQUERY"} {
		if !strings.Contains(string(raw), secret) {
			t.Errorf("--no-redact lost %s", secret)
		}
	}
}

func TestHARStructure(t *testing.T) {
	f := secretFlow()
	f.RespBody = store.Body{Data: []byte{0xff, 0xfe, 0x00}, Size: 3}
	tunnel := store.Flow{Kind: store.KindTunnel}
	b, err := HAR([]store.Flow{f, tunnel}, NewRedactor(DefaultPatterns))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Version string
			Creator struct{ Name string }
			Comment string
			Entries []struct {
				StartedDateTime string
				Time            float64
				Comment         string
				Request         struct {
					Method, URL, HTTPVersion string
					Headers, QueryString     []struct{ Name, Value string }
					PostData                 struct{ MimeType, Text string }
				}
				Response struct {
					Status  int
					Content struct {
						Size           int64
						Text, Encoding string
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	l := doc.Log
	if l.Version != "1.2" || l.Creator.Name != "wraith" || len(l.Entries) != 1 || !strings.Contains(l.Comment, "1 tunnel(s)") {
		t.Fatalf("log %+v", l)
	}
	e := l.Entries[0]
	if e.StartedDateTime != "2026-11-23T18:00:00Z" || e.Time != 42 || e.Request.Method != "POST" ||
		e.Request.HTTPVersion != "HTTP/2.0" || e.Request.PostData.Text != `{"user":"o'neil"}` || e.Response.Status != 201 {
		t.Fatalf("entry %+v", e)
	}
	if e.Response.Content.Encoding != "base64" || e.Response.Content.Text != "//4A" {
		t.Fatalf("binary body: %+v", e.Response.Content)
	}
	if !strings.Contains(e.Comment, "source: sim iPhone 17 · Shop") || !strings.Contains(e.Comment, "slowed like 3g") {
		t.Fatalf("comment %q", e.Comment)
	}
	if len(e.Request.QueryString) != 2 {
		t.Fatalf("query %+v", e.Request.QueryString)
	}
}

func TestHARHoldsDecodedBodies(t *testing.T) {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write([]byte(`{"ok":true}`))
	_ = zw.Close()
	f := secretFlow()
	f.RespHeader.Set("Content-Encoding", "gzip")
	f.RespBody = store.Body{Data: z.Bytes(), Size: int64(z.Len())}
	g := secretFlow()
	g.RespHeader.Set("Content-Encoding", "br")
	g.RespBody = store.Body{Data: []byte{0x8b, 0x05}, Size: 2}
	b, err := HAR([]store.Flow{f, g}, NewRedactor(DefaultPatterns))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []struct {
				Comment  string
				Response struct {
					BodySize int64
					Content  struct {
						Size, Compression int64
						Text, Encoding    string
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Log.Entries[0].Response
	if r.Content.Text != `{"ok":true}` || r.Content.Encoding != "" || r.Content.Size != 11 ||
		r.BodySize != int64(z.Len()) || r.Content.Compression != 11-int64(z.Len()) {
		t.Fatalf("gzip response %+v", r)
	}
	e := doc.Log.Entries[1]
	if e.Response.Content.Encoding != "base64" || !strings.Contains(e.Comment, "response body left as sent: br is not decoded") {
		t.Fatalf("br response %+v, comment %q", e.Response.Content, e.Comment)
	}
}

func TestCurlCommandRepeatsTheRequest(t *testing.T) {
	cmd := Curl(secretFlow(), NewRedactor(nil))
	for _, want := range []string{
		"curl -X POST 'https://api.example.com/v1/login?access_token=SECRETQUERY&page=2'",
		`-H 'Authorization: Bearer SECRETAUTH'`,
		`--data-binary '{"user":"o'\''neil"}'`,
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("missing %q in\n%s", want, cmd)
		}
	}
	// The quoting must survive a real shell.
	out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+shellQuote(`a'b "c" $d`)).Output()
	if err != nil || string(out) != `a'b "c" $d` {
		t.Fatalf("shell got %q, %v", out, err)
	}
}

func TestS3_2_ExportFilesArePrivateAndNeverOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "flows.har")
	if err := WriteFile(p, []byte("one"), false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if err := WriteFile(p, []byte("two"), false); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite without force: %v", err)
	}
	_ = os.Chmod(p, 0o644)
	if err := WriteFile(p, []byte("two"), true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "two" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("force: %q mode %v", b, fi.Mode().Perm())
	}
}

func TestRedactorPatterns(t *testing.T) {
	r := NewRedactor(DefaultPatterns)
	for name, want := range map[string]bool{
		"authorization": true, "Cookie": true, "SET-COOKIE": true, "X-Auth-Token": true, "token": true,
		"access_token": true, "Accept": false, "Cookies": false, "Content-Type": false,
	} {
		if got := r.Matches(name); got != want {
			t.Errorf("Matches(%q) = %v", name, got)
		}
	}
	if got := r.URL("https://x.test/?a=1"); got != "https://x.test/?a=1" {
		t.Errorf("URL without secrets changed: %q", got)
	}
}

func TestHARHasTheTimingPhasesAndWebSocketMessages(t *testing.T) {
	t0 := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	flows := []store.Flow{
		{Kind: store.KindHTTP, Start: t0, Duration: 300 * time.Millisecond, Method: "GET", URL: "https://a.test/", Status: 200, Throttle: "3g",
			Timing: store.Timing{Known: true, DNS: 10 * time.Millisecond, Connect: 20 * time.Millisecond, TLS: 30 * time.Millisecond,
				Send: time.Millisecond, Wait: 200 * time.Millisecond, Receive: 39 * time.Millisecond}},
		{Kind: store.KindHTTP, Start: t0, Duration: 5 * time.Millisecond, Method: "GET", URL: "https://a.test/again", Status: 200,
			Timing: store.Timing{Known: true, Reused: true, Send: time.Millisecond, Wait: 3 * time.Millisecond, Receive: time.Millisecond}},
		{Kind: store.KindHTTP, Start: t0, Method: "GET", URL: "wss://a.test/live", Status: 101, MessagesDropped: 1, Messages: []store.Message{
			{At: t0, FromClient: true, Op: "text", Data: []byte("hi")},
			{At: t0.Add(time.Second), Op: "binary", Data: []byte{0xff, 0}},
		}},
		{Kind: store.KindHTTP, Start: t0, Method: "GET", URL: "https://a.test/cart", Status: 503, Mock: "GET https://a.test/cart"},
	}
	b, err := HAR(flows, NewRedactor(nil))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []struct {
				Timings map[string]float64 `json:"timings"`
				Comment string             `json:"comment"`
				WS      []struct {
					Type   string  `json:"type"`
					Time   float64 `json:"time"`
					Opcode int     `json:"opcode"`
					Data   string  `json:"data"`
				} `json:"_webSocketMessages"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	e := doc.Log.Entries
	if tm := e[0].Timings; tm["dns"] != 10 || tm["connect"] != 50 || tm["ssl"] != 30 || tm["wait"] != 200 || tm["receive"] != 39 || !strings.Contains(e[0].Comment, "throttled: 3g") {
		t.Fatalf("first: %v %q", tm, e[0].Comment)
	}
	if tm := e[1].Timings; tm["dns"] != -1 || tm["connect"] != -1 || tm["ssl"] != -1 || tm["wait"] != 3 {
		t.Fatalf("reused connection: %v", tm)
	}
	ws := e[2].WS
	if len(ws) != 2 || ws[0].Type != "send" || ws[0].Opcode != 1 || ws[0].Data != "hi" || ws[0].Time != float64(t0.Unix()) ||
		ws[1].Type != "receive" || ws[1].Opcode != 2 || ws[1].Data != "/wA=" || !strings.Contains(e[2].Comment, "1 older WebSocket messages not kept") {
		t.Fatalf("websocket: %+v %q", ws, e[2].Comment)
	}
	if !strings.Contains(e[3].Comment, "answered by the mock GET https://a.test/cart") || e[3].Timings["connect"] != -1 {
		t.Fatalf("mock: %q %v", e[3].Comment, e[3].Timings)
	}
}
