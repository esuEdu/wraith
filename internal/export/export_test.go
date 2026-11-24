package export

import (
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
		Source: "sim iPhone 17 · Shop", Route: "direct", Method: "POST", Proto: "HTTP/2.0", Status: 201,
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
	if !strings.Contains(e.Comment, "source: sim iPhone 17 · Shop") || !strings.Contains(e.Comment, "route: direct") {
		t.Fatalf("comment %q", e.Comment)
	}
	if len(e.Request.QueryString) != 2 {
		t.Fatalf("query %+v", e.Request.QueryString)
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
