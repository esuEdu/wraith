// Package sysproxytest provides a stateful fake of the macOS tools sysproxy drives
// (networksetup and scutil --proxy). It answers in the real tools' formats, recorded on a
// Mac in testdata/tools, and keeps the proxy settings it is told to set, so a test can
// check that wraith puts back exactly what it found.
package sysproxytest

import (
	"embed"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
)

//go:embed testdata/tools/*.txt
var fixtures embed.FS

// Fixture returns a recorded tool output from testdata/tools.
func Fixture(name string) string {
	b, err := fixtures.ReadFile("testdata/tools/" + name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Proxy is one proxy setting. It has the same fields as sysproxy.Setting, so the two
// convert directly.
type Proxy struct {
	Enabled bool
	Server  string
	Port    int
	Auth    bool
}

// Mac is the fake. Its exported fields may be set before use; while code under test runs
// concurrently, use the methods.
type Mac struct {
	mu            sync.Mutex
	Order         []string
	Disabled      map[string]bool
	Web, Secure   map[string]Proxy
	PAC           map[string]string // service -> PAC URL, when enabled
	AutoDiscovery map[string]bool
	Scutil        string
	FailOn        string // command line prefix that fails
	BeforeSet     func() // called once, before the first set command
	setSeen       bool
}

// NewMac returns a Mac with three services: a disabled USB LAN, a Thunderbolt Bridge with
// an enabled corporate web proxy, and Wi-Fi with a disabled proxy at 127.0.0.1:8888 (as
// recorded on a real Mac).
func NewMac() *Mac {
	return &Mac{
		Order:    []string{"USB 10/100/1000 LAN", "Thunderbolt Bridge", "Wi-Fi"},
		Disabled: map[string]bool{"USB 10/100/1000 LAN": true},
		Web: map[string]Proxy{
			"Wi-Fi":               {Server: "127.0.0.1", Port: 8888},
			"Thunderbolt Bridge":  {Enabled: true, Server: "proxy.corp.example", Port: 3128},
			"USB 10/100/1000 LAN": {},
		},
		Secure: map[string]Proxy{
			"Wi-Fi":               {Server: "127.0.0.1", Port: 8888},
			"Thunderbolt Bridge":  {},
			"USB 10/100/1000 LAN": {},
		},
		PAC:           map[string]string{},
		AutoDiscovery: map[string]bool{},
		Scutil:        Fixture("scutil-proxy-none.txt"),
	}
}

// SetFailOn makes command lines starting with prefix fail; "" turns it off.
func (m *Mac) SetFailOn(prefix string) {
	m.mu.Lock()
	m.FailOn = prefix
	m.mu.Unlock()
}

// Settings returns copies of the web and secure web proxy settings.
func (m *Mac) Settings() (web, secure map[string]Proxy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	web, secure = map[string]Proxy{}, map[string]Proxy{}
	maps.Copy(web, m.Web)
	maps.Copy(secure, m.Secure)
	return web, secure
}

// Run answers one command; use it as execx.Fake.Handler.
func (m *Mac) Run(tool string, args []string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	line := strings.Join(append([]string{tool}, args...), " ")
	if m.FailOn != "" && strings.HasPrefix(line, m.FailOn) {
		return nil, fmt.Errorf("fake failure: %s", line)
	}
	if tool == "scutil" && len(args) == 1 && args[0] == "--proxy" {
		return []byte(m.Scutil), nil
	}
	if tool != "networksetup" || len(args) == 0 {
		return nil, fmt.Errorf("unexpected call %q", line)
	}
	verb := args[0]
	if verb == "-listallnetworkservices" {
		var b strings.Builder
		b.WriteString("An asterisk (*) denotes that a network service is disabled.\n")
		for _, s := range m.Order {
			if m.Disabled[s] {
				b.WriteString("*")
			}
			b.WriteString(s)
			b.WriteString("\n")
		}
		return []byte(b.String()), nil
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("unexpected call %q", line)
	}
	svc := args[1]
	if _, ok := m.Web[svc]; !ok {
		return nil, fmt.Errorf("** Error: The parameters were not valid. (%s)", line)
	}
	if strings.HasPrefix(verb, "-set") && !m.setSeen {
		m.setSeen = true
		if m.BeforeSet != nil {
			m.mu.Unlock()
			m.BeforeSet()
			m.mu.Lock()
		}
	}
	pick := func(secure bool) map[string]Proxy {
		if secure {
			return m.Secure
		}
		return m.Web
	}
	switch verb {
	case "-getwebproxy", "-getsecurewebproxy":
		p := pick(verb == "-getsecurewebproxy")[svc]
		enabled, auth := "No", 0
		if p.Enabled {
			enabled = "Yes"
		}
		if p.Auth {
			auth = 1
		}
		return fmt.Appendf(nil, "Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: %d\n",
			enabled, p.Server, p.Port, auth), nil
	case "-setwebproxy", "-setsecurewebproxy":
		if len(args) != 4 {
			return nil, fmt.Errorf("unexpected call %q", line)
		}
		port, err := strconv.Atoi(args[3])
		if err != nil {
			return nil, err
		}
		set := pick(verb == "-setsecurewebproxy")
		p := set[svc]
		p.Server, p.Port, p.Enabled = args[2], port, true
		set[svc] = p
		return nil, nil
	case "-setwebproxystate", "-setsecurewebproxystate":
		set := pick(verb == "-setsecurewebproxystate")
		p := set[svc]
		p.Enabled = args[2] == "on"
		set[svc] = p
		return nil, nil
	case "-getautoproxyurl":
		if u, ok := m.PAC[svc]; ok {
			return []byte("URL: " + u + "\nEnabled: Yes\n"), nil
		}
		return []byte(Fixture("getautoproxyurl-off.txt")), nil
	case "-getproxyautodiscovery":
		if m.AutoDiscovery[svc] {
			return []byte("Auto Proxy Discovery: On\n"), nil
		}
		return []byte(Fixture("getproxyautodiscovery-off.txt")), nil
	}
	return nil, fmt.Errorf("unexpected call %q", line)
}
