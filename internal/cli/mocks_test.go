package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/store"
)

func TestMockRulesMatch(t *testing.T) {
	e := newEnv(t)
	m := newMocks(e.home(), []config.Mock{
		{Match: "GET https://api.shop.test/v2/cart", Status: 500, Body: "boom"},
		{Match: "https://api.shop.test/v2/items/*", Body: "any item, any method"},
		{Match: "GET https://api.shop.test/search?q=shoes", Body: "only this query"},
		{Match: "GET https://api.shop.test/off", Body: "off", Off: true},
	}, func(string, ...any) {})
	for _, c := range []struct{ method, url, want string }{
		{"GET", "https://api.shop.test/v2/cart", "boom"},
		{"GET", "https://api.shop.test/v2/cart?page=2", "boom"}, // no ? in the rule: any query
		{"POST", "https://api.shop.test/v2/cart", ""},
		{"DELETE", "https://api.shop.test/v2/items/7", "any item, any method"},
		{"GET", "https://api.shop.test/search?q=shoes", "only this query"},
		{"GET", "https://api.shop.test/search?q=hats", ""},
		{"GET", "https://api.shop.test/off", ""},
		{"GET", "https://api.shop.test/v2/cart/extra", ""},
	} {
		r := m.For(c.method, c.url)
		got := ""
		if r != nil {
			got = string(r.Body)
		}
		if got != c.want {
			t.Errorf("%s %s: %q, want %q", c.method, c.url, got, c.want)
		}
	}
	if m.Count() != 3 {
		t.Fatalf("count %d, want the 3 that are on", m.Count())
	}
}

func TestMToggleWritesAMockToEditAndRemovesIt(t *testing.T) {
	e := newEnv(t)
	h := e.home()
	if _, _, err := config.Load(h); err != nil {
		t.Fatal(err)
	}
	m := newMocks(h, nil, func(string, ...any) {})
	f := store.Flow{Kind: store.KindHTTP, Method: "GET", URL: "https://api.shop.test/v2/cart?page=1", Status: 200,
		RespHeader: http.Header{"Content-Type": {"application/json"}}, RespBody: store.Body{Data: []byte(`{"items":[]}`), Size: 12}}

	msg, err := m.Toggle(f)
	file := filepath.Join(e.dir, "mocks", "api.shop.test-v2-cart.json")
	if err != nil || !strings.Contains(msg, "mocking GET https://api.shop.test/v2/cart with 200 from "+file) {
		t.Fatalf("toggle: %q %v", msg, err)
	}
	if r := m.For("GET", "https://api.shop.test/v2/cart?page=9"); r == nil || string(r.Body) != `{"items":[]}` || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("mock after toggle: %+v", r)
	}
	// The file is read on every request: an edit applies at once.
	if err := os.WriteFile(file, []byte(`{"items":[1]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := m.For("GET", "https://api.shop.test/v2/cart"); string(r.Body) != `{"items":[1]}` {
		t.Fatalf("after editing the file: %q", r.Body)
	}
	cfg, _, err := config.Load(h)
	if err != nil || len(cfg.Mocks) != 1 || cfg.Mocks[0].File != "api.shop.test-v2-cart.json" || cfg.Mocks[0].Match != "GET https://api.shop.test/v2/cart" {
		t.Fatalf("config.yaml: %+v %v", cfg.Mocks, err)
	}

	// An edit to config.yaml by hand applies too, once wraith looks again.
	b, _ := os.ReadFile(filepath.Join(e.dir, config.FileName))
	edited := strings.Replace(string(b), "status: 200", "status: 503\n    delay: 2s", 1)
	if edited == string(b) {
		t.Fatalf("no status to edit in:\n%s", b)
	}
	if err := os.WriteFile(filepath.Join(e.dir, config.FileName), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(e.dir, config.FileName), future, future)
	m.checked = time.Time{}
	if r := m.For("GET", "https://api.shop.test/v2/cart"); r.Status != 503 || r.Delay != 2*time.Second {
		t.Fatalf("after editing config.yaml: %+v", r)
	}

	// A mocked flow toggles its own rule off; the file stays.
	msg, err = m.Toggle(store.Flow{Kind: store.KindHTTP, Method: "GET", URL: "https://api.shop.test/v2/cart", Mock: "GET https://api.shop.test/v2/cart"})
	if err != nil || !strings.HasPrefix(msg, "stopped mocking GET https://api.shop.test/v2/cart") {
		t.Fatalf("toggle off: %q %v", msg, err)
	}
	if m.For("GET", "https://api.shop.test/v2/cart") != nil || m.Count() != 0 {
		t.Fatal("still mocked")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the body file went: %v", err)
	}
	// Mocking it again does not overwrite the old file.
	if _, err := m.Toggle(f); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "mocks", "api.shop.test-v2-cart-2.json")); err != nil {
		t.Fatalf("second file: %v", err)
	}
	if _, err := m.Toggle(store.Flow{Kind: store.KindTunnel}); err == nil {
		t.Fatal("a tunnel was mocked")
	}
}

func TestAMissingMockFileAnswersWhy(t *testing.T) {
	e := newEnv(t)
	m := newMocks(e.home(), []config.Mock{{Match: "https://x.test/*", File: "gone.json"}}, func(string, ...any) {})
	if r := m.For("GET", "https://x.test/a"); r == nil || !strings.Contains(r.Err, "gone.json") {
		t.Fatalf("%+v", r)
	}
}

func TestBadConfigEditsKeepTheMocks(t *testing.T) {
	e := newEnv(t)
	h := e.home()
	if err := config.WriteMocks(h, []config.Mock{{Match: "https://x.test/a", Body: "a"}}); err != nil {
		t.Fatal(err)
	}
	cfg, _, _ := config.Load(h)
	var notes []string
	m := newMocks(h, cfg.Mocks, func(f string, a ...any) { notes = append(notes, f) })
	if err := os.WriteFile(filepath.Join(e.dir, config.FileName), []byte("mocks: [{match: nope}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(e.dir, config.FileName), future, future)
	m.checked = time.Time{}
	if r := m.For("GET", "https://x.test/a"); r == nil || string(r.Body) != "a" || len(notes) != 1 {
		t.Fatalf("a config that does not load replaced the mocks: %+v %v", r, notes)
	}
}
