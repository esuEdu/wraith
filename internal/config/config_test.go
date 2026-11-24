package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/esuEdu/wraith/internal/home"
)

func openHome(t *testing.T) *home.Home {
	t.Helper()
	h, err := home.Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestDefaultYAMLMatchesDefault(t *testing.T) {
	cfg, err := Parse([]byte(DefaultYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("DefaultYAML parses to\n%+v\nwant\n%+v", cfg, Default())
	}
}

func TestEmptyAndPartialFilesKeepDefaults(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil || !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("empty: %+v, %v", cfg, err)
	}
	cfg, err = Parse([]byte("port: 8888\ncapture:\n  max_flows: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Port, want.Capture.MaxFlows = 8888, 10
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("partial: %+v", cfg)
	}
}

func TestFirstRunWritesDefaultFile(t *testing.T) {
	h := openHome(t)
	cfg, created, err := Load(h)
	if err != nil || !created || !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("first Load = %+v, %v, %v", cfg, created, err)
	}
	fi, err := os.Stat(filepath.Join(h.Path(), FileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v, %v", fi, err)
	}

	if err := h.WriteFile(FileName, []byte("port: 7070\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, created, err = Load(h)
	if err != nil || created || cfg.Port != 7070 {
		t.Fatalf("second Load = port %d, %v, %v", cfg.Port, created, err)
	}
}

func TestR6_1_FlagsOverrideConfig(t *testing.T) {
	file, err := Parse([]byte("port: 7070\nsource: all\ninterface: en1\n"))
	if err != nil {
		t.Fatal(err)
	}
	port, src := 9999, "pid:42"
	var body int64 = 10
	cfg, err := file.With(Overrides{Port: &port, Source: &src, MaxBodyBytes: &body})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 9999 || cfg.Source != "pid:42" || cfg.Capture.MaxBodyBytes != 10 {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.Interface != "en1" {
		t.Fatalf("interface = %q, want the file's en1 (no flag given)", cfg.Interface)
	}

	bad := 0
	if _, err := file.With(Overrides{Port: &bad}); err == nil {
		t.Fatal("invalid flag value accepted")
	}
}

func TestS5_3_UnknownKeysAreErrors(t *testing.T) {
	for _, in := range []string{"prot: 9090\n", "capture:\n  max_flow: 1\n", "export:\n  redact: [x]\n"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestS5_3_OversizedConfigIsRefused(t *testing.T) {
	big := "# " + strings.Repeat("x", MaxSize) + "\n"
	if _, err := Parse([]byte(big)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestS5_3_MultipleDocumentsAreRefused(t *testing.T) {
	if _, err := Parse([]byte("port: 1\n---\nport: 2\n")); err == nil {
		t.Fatal("second document accepted")
	}
}

func TestS5_3_ValuesValidatedAtLoad(t *testing.T) {
	cases := map[string]string{
		"port zero":         "port: 0\n",
		"port too big":      "port: 70000\n",
		"source unknown":    "source: everything\n",
		"source pid text":   "source: pid:abc\n",
		"source empty app":  "source: 'app:'\n",
		"interface shell":   "interface: 'en0; rm -rf /'\n",
		"max_flows zero":    "capture:\n  max_flows: 0\n",
		"negative body":     "capture:\n  max_body_bytes: -1\n",
		"bypass with port":  "bypass: [example.com:443]\n",
		"bypass with url":   "bypass: ['https://example.com']\n",
		"bypass mid star":   "bypass: ['api.*.example.com']\n",
		"bypass bare star":  "bypass: ['*']\n",
		"bypass duplicate":  "bypass: [a.com, A.com.]\n",
		"no_decrypt label":  "no_decrypt: ['-bad.com']\n",
		"redact header bad": "export:\n  redact_headers: ['X Token']\n",
		"wrong type":        "port: abc\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatalf("%q accepted", in)
			}
		})
	}
}

func TestAllProblemsReportedTogether(t *testing.T) {
	_, err := Parse([]byte("port: 0\nsource: nope\n"))
	if err == nil || !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "source") {
		t.Fatalf("err = %v, want both port and source", err)
	}
}

func TestValidSourcesAndPatterns(t *testing.T) {
	for _, s := range []string{"all", "simulator", "simulator:iPhone 17", "simulator:196410F2-8977-4511-9257-C038A2AC78AA",
		"app:com.google.Chrome", "app:Safari", "pid:1234"} {
		if err := validSource(s); err != nil {
			t.Errorf("source %q rejected: %v", s, err)
		}
	}
	for raw, want := range map[string]string{
		"API.Example.com.": "api.example.com",
		"*.Example.com":    "*.example.com",
		"localhost":        "localhost",
		"10.0.0.1":         "10.0.0.1",
		"::1":              "::1",
		" a-b.io ":         "a-b.io",
	} {
		got, err := NormalizeHostPattern(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeHostPattern(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	cfg, err := Parse([]byte("bypass: ['*.Corp.Example.com']\n"))
	if err != nil || cfg.Bypass[0] != "*.corp.example.com" {
		t.Fatalf("bypass not normalized: %v %v", cfg.Bypass, err)
	}
}

func TestR2_5_NoDecryptPatternsMatch(t *testing.T) {
	patterns := Default().NoDecrypt // *.apple.com, *.icloud.com
	patterns = append(patterns, "api.partner.io")
	for host, want := range map[string]bool{
		"gateway.icloud.com": true,
		"a.b.apple.com":      true,
		"WWW.APPLE.COM.":     true,
		"apple.com":          false, // *.apple.com is subdomains only
		"notapple.com":       false,
		"api.partner.io":     true,
		"x.api.partner.io":   false,
		"example.com":        false,
	} {
		if got := MatchesAny(patterns, host); got != want {
			t.Errorf("MatchesAny(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestR6_2_BypassListIsWrittenBackKeepingComments(t *testing.T) {
	h := openHome(t)
	if _, _, err := Load(h); err != nil { // writes DefaultYAML
		t.Fatal(err)
	}
	if err := WriteBypass(h, []string{"*.corp.example.com", "api.partner.io"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.Bypass, ",") != "*.corp.example.com,api.partner.io" || cfg.Port != 9090 {
		t.Fatalf("after write: bypass %v port %d", cfg.Bypass, cfg.Port)
	}
	b, _ := h.ReadFile(FileName)
	for _, comment := range []string{"# wraith configuration", "# proxy port on 127.0.0.1 and ::1", "# always passed through, never decrypted"} {
		if !strings.Contains(string(b), comment) {
			t.Errorf("comment %q lost:\n%s", comment, b)
		}
	}
	if err := WriteBypass(h, nil); err != nil {
		t.Fatal(err)
	}
	if cfg, _, _ := Load(h); len(cfg.Bypass) != 0 {
		t.Fatalf("emptied list: %v", cfg.Bypass)
	}
	if b, _ := h.ReadFile(FileName); !strings.Contains(string(b), "bypass: []") {
		t.Fatalf("empty list not written as []:\n%s", b)
	}
}

func TestNoDecryptListIsWrittenBack(t *testing.T) {
	h := openHome(t)
	if err := WriteNoDecrypt(h, []string{"*.apple.com", "pinned.example.com"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(h)
	if err != nil || strings.Join(cfg.NoDecrypt, ",") != "*.apple.com,pinned.example.com" || len(cfg.Bypass) != 0 {
		t.Fatalf("cfg %+v, %v", cfg, err)
	}
}
