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
	"strconv"
	"strings"

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
}

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
	}
}

// DefaultYAML is written to config.yaml on first run.
const DefaultYAML = `# wraith configuration. Command-line flags override these values.
# Docs: https://github.com/esuEdu/wraith

port: 9090                  # proxy port on 127.0.0.1 and ::1
source: simulator           # all | simulator | simulator:<udid|name> | app:<name|bundle-id> | pid:<pid>
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
	return errors.Join(errs...)
}

func validSource(s string) error {
	kind, arg, hasArg := strings.Cut(s, ":")
	switch {
	case s == "all" || s == "simulator":
		return nil
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
	return fmt.Errorf("%q must be all, simulator, simulator:<udid|name>, app:<name|bundle-id> or pid:<pid>", s)
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

// WriteBypass replaces the bypass list in config.yaml with patterns (R6.2), editing the
// YAML document in place so the rest of the file and its comments stay. patterns must
// already be normalized. A missing file starts from DefaultYAML.
func WriteBypass(h *home.Home, patterns []string) error {
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
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if len(patterns) == 0 {
		seq.Style = yaml.FlowStyle // bypass: []
	}
	for _, p := range patterns {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p, Style: yaml.DoubleQuotedStyle})
	}
	found := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "bypass" {
			old := root.Content[i+1]
			seq.LineComment, seq.HeadComment, seq.FootComment = old.LineComment, old.HeadComment, old.FootComment
			root.Content[i+1] = seq
			found = true
			break
		}
	}
	if !found {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "bypass"}, seq)
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
