// Package config loads and validates ~/.wraith/config.yaml (R6.1). Loading is strict:
// unknown keys, oversized files and invalid values are errors at load time (S5.3).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/esuEdu/wraith/internal/home"
)

// FileName is the config file's name in the home directory.
const FileName = "config.yaml"

// MaxSize is the largest config file wraith reads (S5.3).
const MaxSize = 1 << 20

// Config is the content of config.yaml.
type Config struct {
	Port      int      `yaml:"port"`
	Source    string   `yaml:"source"`
	Interface string   `yaml:"interface"`
	Capture   Capture  `yaml:"capture"`
	Bypass    []string `yaml:"bypass"`
	NoDecrypt []string `yaml:"no_decrypt"`
	Export    Export   `yaml:"export"`
	Theme     string   `yaml:"theme"`
	Throttle  string   `yaml:"throttle"`
	Mocks     []Mock   `yaml:"mocks"`
}

// Throttles are the slow-network profiles (the proxy's), and off.
var Throttles = []string{"off", "lte", "3g", "edge", "very-bad"}

// Mock answers requests that match it instead of their upstream. Match is
// "[METHOD ]URL", where * stands for anything; a URL without "?" matches any query.
// The body is Body, or the file File in ~/.wraith/mocks, read on every request so edits
// apply at once.
type Mock struct {
	Match   string            `yaml:"match"`
	Status  int               `yaml:"status,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
	File    string            `yaml:"file,omitempty"`
	Delay   time.Duration     `yaml:"delay,omitempty"`
	Off     bool              `yaml:"off,omitempty"`
}

// MaxMockDelay is the longest a mock may wait before answering.
const MaxMockDelay = time.Minute

// SplitMatch splits a mock's Match into its method ("" for any) and URL pattern.
func SplitMatch(match string) (method, url string) {
	m, u, ok := strings.Cut(strings.TrimSpace(match), " ")
	if !ok {
		return "", m
	}
	return strings.ToUpper(m), strings.TrimSpace(u)
}

var (
	methodRe   = regexp.MustCompile(`^[A-Z]+$`)
	mockFileRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func (m Mock) check() error {
	method, u := SplitMatch(m.Match)
	var errs []error
	if method != "" && method != "*" && !methodRe.MatchString(method) {
		errs = append(errs, fmt.Errorf("match: %q is not a method", method))
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		errs = append(errs, fmt.Errorf("match: %q must start with http:// or https://", u))
	}
	if m.Status != 0 && (m.Status < 100 || m.Status > 599) {
		errs = append(errs, fmt.Errorf("status: %d is not an HTTP status", m.Status))
	}
	for k := range m.Headers {
		if !headerRe.MatchString(k) {
			errs = append(errs, fmt.Errorf("headers: %q is not a header name", k))
		}
	}
	if m.Body != "" && m.File != "" {
		errs = append(errs, errors.New("body and file: give one or the other"))
	}
	if m.File != "" && (!mockFileRe.MatchString(m.File) || m.File == "." || m.File == "..") {
		errs = append(errs, fmt.Errorf("file: %q must be a file name in ~/.wraith/mocks, without a path", m.File))
	}
	if m.Delay < 0 || m.Delay > MaxMockDelay {
		errs = append(errs, fmt.Errorf("delay: %s must be between 0 and %s", m.Delay, MaxMockDelay))
	}
	return errors.Join(errs...)
}

// Themes are the live view's color themes: Rex's Heliotrope Haze, or the terminal's own
// 16 colors.
var Themes = []string{"heliotrope-haze", "terminal"}

// Capture holds the in-memory capture limits (R5.1).
type Capture struct {
	MaxFlows     int   `yaml:"max_flows"`
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
}

// Export holds export settings (R5.3).
type Export struct {
	RedactHeaders []string `yaml:"redact_headers"`
}

// Default returns the built-in configuration. DefaultYAML spells out the same values.
func Default() Config {
	return Config{
		Port:      9090,
		Source:    "simulator",
		Interface: "auto",
		Capture:   Capture{MaxFlows: 5000, MaxBodyBytes: 1 << 20},
		Bypass:    []string{},
		NoDecrypt: []string{"*.apple.com", "*.icloud.com"},
		Export:    Export{RedactHeaders: []string{"Authorization", "Cookie", "Set-Cookie", "*token*"}},
		Theme:     "heliotrope-haze",
		Throttle:  "off",
		Mocks:     []Mock{},
	}
}

// DefaultYAML is written to config.yaml on first run.
const DefaultYAML = `# wraith configuration. Command-line flags override these values.
# Docs: https://github.com/esuEdu/wraith

port: 9090                  # proxy port on 127.0.0.1 and ::1
source: simulator           # all | simulator | simulator:<udid|name> | app:<name|bundle-id> | pid:<pid> | device | device:<ip>
interface: auto             # physical interface for bypassed hosts: auto, or en0, en1, ...

capture:
  max_flows: 5000           # flows kept in memory
  max_body_bytes: 1048576   # bodies above this are truncated

bypass: []                  # hosts that skip the VPN, e.g. ["*.example.com", "api.partner.io"]

no_decrypt:                 # always passed through, never decrypted
  - "*.apple.com"
  - "*.icloud.com"

export:
  redact_headers: [Authorization, Cookie, Set-Cookie, "*token*"]

theme: heliotrope-haze      # live view colors: heliotrope-haze, or terminal for its own palette

throttle: off               # slow network for the capture source: off, lte, 3g, edge, very-bad (t in the live view)

# Mocks answer the capture source's requests instead of their upstream (m in the live
# view mocks the selected request with its response). The first match wins.
#   - match: "GET https://api.example.com/v2/cart"   # [METHOD ]URL; * is anything
#     status: 500
#     headers: {Content-Type: application/json}
#     body: '{"error": "boom"}'      # or file: cart.json, in ~/.wraith/mocks
#     delay: 2s
#     off: true                     # keep it, but answer from the upstream
mocks: []
`

// Parse decodes and validates a config file's content. Keys left out keep their default.
func Parse(b []byte) (Config, error) {
	cfg := Default()
	if len(b) > MaxSize {
		return cfg, fmt.Errorf("config is %d bytes; the limit is %d", len(b), MaxSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Default(), err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Default(), errors.New("config must be a single YAML document")
	}
	if cfg.Bypass == nil {
		cfg.Bypass = []string{}
	}
	if cfg.NoDecrypt == nil {
		cfg.NoDecrypt = []string{}
	}
	if cfg.Mocks == nil {
		cfg.Mocks = []Mock{}
	}
	if err := cfg.normalize(); err != nil {
		return Default(), err
	}
	return cfg, nil
}

// Load reads config.yaml from h. On first run, when it does not exist, it writes
// DefaultYAML (mode 0600) and returns the defaults with created set.
func Load(h *home.Home) (cfg Config, created bool, err error) {
	b, err := h.ReadFile(FileName)
	if errors.Is(err, fs.ErrNotExist) {
		if err := h.WriteFile(FileName, []byte(DefaultYAML), 0o600); err != nil {
			return Default(), false, err
		}
		return Default(), true, nil
	}
	if err != nil {
		return Default(), false, err
	}
	cfg, err = Parse(b)
	if err != nil {
		return cfg, false, fmt.Errorf("%s: %w", FileName, err)
	}
	return cfg, false, nil
}

// Overrides are values from command-line flags; nil fields leave the config value.
type Overrides struct {
	Port         *int
	Source       *string
	Interface    *string
	MaxFlows     *int
	MaxBodyBytes *int64
	Throttle     *string
}

// With returns cfg with o applied, validated again (R6.1: flags override the file).
func (c Config) With(o Overrides) (Config, error) {
	if o.Port != nil {
		c.Port = *o.Port
	}
	if o.Source != nil {
		c.Source = *o.Source
	}
	if o.Interface != nil {
		c.Interface = *o.Interface
	}
	if o.MaxFlows != nil {
		c.Capture.MaxFlows = *o.MaxFlows
	}
	if o.MaxBodyBytes != nil {
		c.Capture.MaxBodyBytes = *o.MaxBodyBytes
	}
	if o.Throttle != nil {
		c.Throttle = *o.Throttle
	}
	if err := c.normalize(); err != nil {
		return c, err
	}
	return c, nil
}

var (
	ifaceRe  = regexp.MustCompile(`^[a-z]+[0-9]+$`)
	labelRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)
)

// normalize validates every field and lower-cases host patterns in place. It reports all
// problems at once.
func (c *Config) normalize() error {
	var errs []error
	bad := func(field, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{field}, args...)...))
	}

	if c.Port < 1 || c.Port > 65535 {
		bad("port", "%d is not between 1 and 65535", c.Port)
	}
	if err := validSource(c.Source); err != nil {
		bad("source", "%v", err)
	}
	if c.Interface != "auto" && !ifaceRe.MatchString(c.Interface) {
		bad("interface", "%q must be auto or an interface name like en0", c.Interface)
	}
	if c.Capture.MaxFlows < 1 {
		bad("capture.max_flows", "must be at least 1, got %d", c.Capture.MaxFlows)
	}
	if c.Capture.MaxBodyBytes < 0 {
		bad("capture.max_body_bytes", "must not be negative, got %d", c.Capture.MaxBodyBytes)
	}
	for _, list := range []struct {
		name string
		p    *[]string
	}{{"bypass", &c.Bypass}, {"no_decrypt", &c.NoDecrypt}} {
		seen := map[string]bool{}
		for i, raw := range *list.p {
			p, err := NormalizeHostPattern(raw)
			if err != nil {
				bad(fmt.Sprintf("%s[%d]", list.name, i), "%v", err)
				continue
			}
			if seen[p] {
				bad(fmt.Sprintf("%s[%d]", list.name, i), "%q is listed twice", p)
			}
			seen[p] = true
			(*list.p)[i] = p
		}
	}
	for i, h := range c.Export.RedactHeaders {
		if !headerRe.MatchString(h) {
			bad(fmt.Sprintf("export.redact_headers[%d]", i), "%q is not a header name or pattern", h)
		}
	}
	if !slices.Contains(Themes, c.Theme) {
		bad("theme", "%q must be one of %s", c.Theme, strings.Join(Themes, ", "))
	}
	if !slices.Contains(Throttles, c.Throttle) {
		bad("throttle", "%q must be one of %s", c.Throttle, strings.Join(Throttles, ", "))
	}
	for i, m := range c.Mocks {
		if err := m.check(); err != nil {
			bad(fmt.Sprintf("mocks[%d]", i), "%v", err)
		}
	}
	return errors.Join(errs...)
}

func validSource(s string) error {
	kind, arg, hasArg := strings.Cut(s, ":")
	switch {
	case s == "all" || s == "simulator" || s == "device":
		return nil
	case kind == "device" && hasArg:
		if net.ParseIP(arg) != nil {
			return nil
		}
		return fmt.Errorf("%q: device must be an IP address", s)
	case kind == "simulator" && hasArg && arg != "":
		return nil
	case kind == "app" && hasArg && arg != "":
		return nil
	case kind == "pid" && hasArg:
		if n, err := strconv.Atoi(arg); err == nil && n > 0 {
			return nil
		}
		return fmt.Errorf("%q: pid must be a positive number", s)
	}
	return fmt.Errorf("%q must be all, simulator, simulator:<udid|name>, app:<name|bundle-id>, pid:<pid>, device or device:<ip>", s)
}

// NormalizeHostPattern checks a bypass or no-decrypt entry and returns it lower-cased
// without a trailing dot. Valid: an exact host (api.x.com), a wildcard for subdomains
// (*.x.com), or an IP address. Ports, schemes and other wildcards are not allowed.
func NormalizeHostPattern(raw string) (string, error) {
	p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if p == "" {
		return "", errors.New("empty host")
	}
	if net.ParseIP(p) != nil {
		return p, nil
	}
	host := strings.TrimPrefix(p, "*.")
	if strings.Contains(host, "*") {
		return "", fmt.Errorf("%q: only a leading *. wildcard is allowed", raw)
	}
	for label := range strings.SplitSeq(host, ".") {
		if !labelRe.MatchString(label) {
			return "", fmt.Errorf("%q is not a host name (no scheme, port or path)", raw)
		}
	}
	return p, nil
}

// MatchesAny reports whether host matches one of patterns, which NormalizeHostPattern has
// already checked: an exact host, or "*.domain" for any subdomain of domain (not domain
// itself). Matching ignores case and a trailing dot.
func MatchesAny(patterns []string, host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range patterns {
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(h, "."+suffix) {
				return true
			}
		} else if h == p {
			return true
		}
	}
	return false
}

// WriteBypass replaces the bypass list in config.yaml with patterns (R6.2).
func WriteBypass(h *home.Home, patterns []string) error { return writeList(h, "bypass", patterns) }

// WriteNoDecrypt replaces the no_decrypt list in config.yaml with patterns.
func WriteNoDecrypt(h *home.Home, patterns []string) error {
	return writeList(h, "no_decrypt", patterns)
}

// WriteMocks replaces the mocks list in config.yaml.
func WriteMocks(h *home.Home, mocks []Mock) error {
	var seq yaml.Node
	if err := seq.Encode(mocks); err != nil {
		return err
	}
	if len(mocks) == 0 {
		seq.Style = yaml.FlowStyle
	}
	return writeKey(h, "mocks", &seq)
}

// writeList replaces one top-level list of strings in config.yaml. patterns must
// already be normalized.
func writeList(h *home.Home, key string, patterns []string) error {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if len(patterns) == 0 {
		seq.Style = yaml.FlowStyle // key: []
	}
	for _, p := range patterns {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p, Style: yaml.DoubleQuotedStyle})
	}
	return writeKey(h, key, seq)
}

// writeKey replaces one top-level value in config.yaml, editing the YAML document in
// place so the rest of the file and its comments stay. A missing file starts from
// DefaultYAML.
func writeKey(h *home.Home, key string, value *yaml.Node) error {
	b, err := h.ReadFile(FileName)
	if errors.Is(err, fs.ErrNotExist) {
		b = []byte(DefaultYAML)
	} else if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", FileName, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		if err := yaml.Unmarshal([]byte(DefaultYAML), &doc); err != nil {
			return err
		}
	}
	root := doc.Content[0]
	found := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			old := root.Content[i+1]
			value.LineComment, value.HeadComment, value.FootComment = old.LineComment, old.HeadComment, old.FootComment
			root.Content[i+1] = value
			found = true
			break
		}
	}
	if !found {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if _, err := Parse(out.Bytes()); err != nil {
		return fmt.Errorf("the edited config would not load: %w", err)
	}
	return h.WriteFile(FileName, out.Bytes(), 0o600)
}
