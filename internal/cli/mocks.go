package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/proxy"
	"github.com/esuEdu/wraith/internal/store"
)

// mocks holds the mock rules of config.yaml, compiled, and follows the file: edits to
// it apply within a second, without a restart. Bodies from files are read per request.
type mocks struct {
	h      *home.Home
	notice func(string, ...any)

	mu      sync.Mutex
	rules   []mockRule
	list    []config.Mock // as in config.yaml, for editing
	checked time.Time     // when config.yaml was last looked at
	mtime   time.Time     // its modification time then
	lastErr string
}

type mockRule struct {
	config.Mock
	method string // "" for any
	re     *regexp.Regexp
	query  bool // the pattern has a query, so the URL's is matched too
}

const mockRecheck = time.Second

func newMocks(h *home.Home, list []config.Mock, notice func(string, ...any)) *mocks {
	m := &mocks{h: h, notice: notice}
	m.set(list)
	if fi, err := os.Stat(filepath.Join(h.Path(), config.FileName)); err == nil {
		m.mtime = fi.ModTime()
	}
	m.checked = time.Now()
	return m
}

// compile turns a URL pattern into a regexp: * is anything, the rest is literal.
func compile(pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

func (m *mocks) set(list []config.Mock) {
	rules := make([]mockRule, 0, len(list))
	for _, c := range list {
		method, pattern := config.SplitMatch(c.Match)
		if method == "*" {
			method = ""
		}
		rules = append(rules, mockRule{Mock: c, method: method, re: compile(pattern), query: strings.Contains(pattern, "?")})
	}
	m.rules, m.list = rules, list
}

// reload reads config.yaml again when it changed. A file that does not load keeps the
// rules wraith had, and says why once.
func (m *mocks) reload() {
	if time.Since(m.checked) < mockRecheck {
		return
	}
	m.checked = time.Now()
	fi, err := os.Stat(filepath.Join(m.h.Path(), config.FileName))
	if err != nil || fi.ModTime().Equal(m.mtime) {
		return
	}
	m.mtime = fi.ModTime()
	b, err := m.h.ReadFile(config.FileName)
	if err == nil {
		var cfg config.Config
		if cfg, err = config.Parse(b); err == nil {
			m.set(cfg.Mocks)
			m.lastErr = ""
			return
		}
	}
	if err.Error() != m.lastErr {
		m.lastErr = err.Error()
		m.notice("mocks: %s did not load, the mocks stay as they were: %v", config.FileName, err)
	}
}

// For is the proxy's Mock function: the response of the first rule that matches. The
// body is read only for a rule that names a GraphQL operation.
func (m *mocks) For(req proxy.MockRequest) *proxy.MockResponse {
	m.mu.Lock()
	m.reload()
	rules := m.rules
	m.mu.Unlock()
	noQuery, _, _ := strings.Cut(req.URL, "?")
	var ops []store.GraphQLOp
	opsRead := false
	for _, r := range rules {
		if r.Off || r.method != "" && r.method != req.Method {
			continue
		}
		u := noQuery
		if r.query {
			u = req.URL
		}
		if !r.re.MatchString(u) {
			continue
		}
		if r.Operation != "" {
			if !opsRead {
				opsRead = true
				var body []byte
				if req.Body != nil {
					body = req.Body()
				}
				ops = store.GraphQLOperations(req.Method, req.URL, req.Header, body)
			}
			if len(ops) != 1 || !strings.EqualFold(ops[0].Name, r.Operation) {
				continue
			}
		}
		return m.response(r.Mock)
	}
	return nil
}

// ruleLabel names a rule on the flows it answers: its match, and its operation.
func ruleLabel(c config.Mock) string {
	if c.Operation != "" {
		return c.Match + " · " + c.Operation
	}
	return c.Match
}

func (m *mocks) response(c config.Mock) *proxy.MockResponse {
	resp := &proxy.MockResponse{Rule: ruleLabel(c), Status: c.Status, Header: http.Header{}, Body: []byte(c.Body), Delay: c.Delay}
	for k, v := range c.Headers {
		resp.Header.Set(k, v)
	}
	if c.File != "" {
		dir, err := m.h.Sub(mocksDir)
		if err == nil {
			defer func() { _ = dir.Close() }()
			resp.Body, err = dir.ReadFile(c.File)
		}
		if err != nil {
			resp.Err = fmt.Sprintf("mock %q: reading %s: %v", c.Match, c.File, err)
		}
		if resp.Header.Get("Content-Type") == "" {
			if t := mime.TypeByExtension(filepath.Ext(c.File)); t != "" {
				resp.Header.Set("Content-Type", t)
			}
		}
	}
	return resp
}

// Count is how many rules are on.
func (m *mocks) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reload()
	n := 0
	for _, r := range m.rules {
		if !r.Off {
			n++
		}
	}
	return n
}

const mocksDir = "mocks"

// ruleFor is the rule m makes for a flow: its method and URL without the query, and for a
// single GraphQL operation, its name.
func ruleFor(f store.Flow) config.Mock {
	u, _, _ := strings.Cut(f.URL, "?")
	c := config.Mock{Match: f.Method + " " + u}
	if len(f.GraphQL) == 1 && f.GraphQL[0].Name != "" {
		c.Operation = f.GraphQL[0].Name
	}
	return c
}

// Toggle mocks f with its own response, or stops mocking it if a rule for it is there.
// The response body goes to a file in ~/.wraith/mocks, to edit; the rule goes first in
// config.yaml, so it wins over broader ones.
func (m *mocks) Toggle(f store.Flow) (string, error) {
	if f.Kind != store.KindHTTP {
		return "", errors.New("a tunnel was not decrypted: there is no request to mock")
	}
	c := ruleFor(f)
	label := ruleLabel(c)
	if f.Mock != "" {
		label = f.Mock // the rule that answered it
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checked = time.Time{}
	m.reload()
	list := append([]config.Mock(nil), m.list...)
	for i, c := range list {
		if ruleLabel(c) == label {
			list = append(list[:i], list[i+1:]...)
			if err := m.write(list); err != nil {
				return "", err
			}
			msg := "stopped mocking " + label
			if c.File != "" {
				msg += "; " + filepath.Join(m.h.Path(), mocksDir, c.File) + " is kept"
			}
			return msg, nil
		}
	}

	c.Status, c.Headers = f.Status, map[string]string{}
	if c.Status == 0 || c.Status == http.StatusSwitchingProtocols {
		c.Status = http.StatusOK
	}
	ct := f.RespHeader.Get("Content-Type")
	if ct != "" {
		c.Headers["Content-Type"] = ct
	}
	body := store.Decode(f.RespBody, f.RespHeader.Get("Content-Encoding")).Data
	dir, err := m.h.Sub(mocksDir)
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	name := f.URL
	if c.Operation != "" {
		name = strings.TrimSuffix(name, "/") + "/" + c.Operation
	}
	c.File = mockFileName(dir, name, ct)
	if err := dir.WriteFile(c.File, body, 0o600); err != nil {
		return "", err
	}
	if err := m.write(append([]config.Mock{c}, list...)); err != nil {
		_ = dir.Remove(c.File)
		return "", err
	}
	path := filepath.Join(m.h.Path(), mocksDir, c.File)
	note := ""
	if f.RespBody.Truncated {
		note = " (only the start of the body was captured)"
	}
	return fmt.Sprintf("mocking %s with %d from %s%s; edit the file, or the rule in config.yaml", label, c.Status, path, note), nil
}

// write saves the list to config.yaml and uses it. The caller holds mu.
func (m *mocks) write(list []config.Mock) error {
	if err := config.WriteMocks(m.h, list); err != nil {
		return err
	}
	m.set(list)
	if fi, err := os.Stat(filepath.Join(m.h.Path(), config.FileName)); err == nil {
		m.mtime = fi.ModTime()
	}
	return nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// mockFileName names a new mock body after its URL, e.g. api.shop.example-v2-cart.json,
// and does not overwrite one that is there.
func mockFileName(dir *home.Home, rawURL, contentType string) string {
	base := "mock"
	if u, err := url.Parse(rawURL); err == nil {
		base = strings.Trim(unsafeName.ReplaceAllString(u.Hostname()+u.Path, "-"), "-.")
	}
	if len(base) > 80 {
		base = base[:80]
	}
	if base == "" {
		base = "mock"
	}
	ext := ".txt"
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case strings.HasSuffix(mt, "json"):
		ext = ".json"
	case mt == "text/html":
		ext = ".html"
	case strings.HasSuffix(mt, "xml"):
		ext = ".xml"
	case strings.HasPrefix(mt, "image/"), mt == "application/octet-stream", strings.HasPrefix(mt, "application/x-protobuf"):
		ext = ".bin"
	}
	name := base + ext
	for i := 2; ; i++ {
		if _, err := dir.ReadFile(name); errors.Is(err, fs.ErrNotExist) {
			return name
		}
		name = fmt.Sprintf("%s-%d%s", base, i, ext)
	}
}
