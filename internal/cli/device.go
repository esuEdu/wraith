package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/proxy"
)

// devices lets physical devices on the local network use wraith (S2.6). A device on the
// Mac's own network may open the setup page; it may use the proxy once it opened the
// setup link with the key from the QR code (new each run), or was named with
// --allow-device. A device that opened the link is remembered by its address on that
// network for later runs, until it has not been seen for rememberFor. Anything off that
// network is refused.
type devices struct {
	addr    string     // ip:port a device sets as its proxy
	subnet  *net.IPNet // the Mac's network on that interface
	key     string     // the setup key in the QR code, new each run
	allowed func(ip, why string)
	notice  func(format string, args ...any)
	save    func([]rememberedDevice) error // writes the remembered devices

	mu      sync.Mutex
	ok      map[string]bool             // allowed addresses, this run
	known   map[string]rememberedDevice // remembered devices on this network, by address
	others  []rememberedDevice          // remembered on other networks, kept as they are
	outside map[string]bool             // refused for being off the subnet, said once
}

// rememberedDevice is a device that opened the setup link, kept in devices.json. macOS
// does not show wraith the network's hardware addresses, so a device is known by its IP
// address on the network it was set up on; at a new address it needs the QR code again.
type rememberedDevice struct {
	IP       string    `json:"ip"`
	Network  string    `json:"network"` // e.g. 192.168.15.0/24
	Kind     string    `json:"kind"`    // iPhone, iPad or device
	Allowed  time.Time `json:"allowed"`
	LastSeen time.Time `json:"last_seen"`
}

// rememberFor is how long a remembered device that is not seen stays remembered.
const rememberFor = 30 * 24 * time.Hour

const devicesFile = "devices.json"

// deviceState is devices.json: the remembered devices.
type deviceState struct {
	Devices []rememberedDevice `json:"devices"`
}

func newDevices(addr string, subnet *net.IPNet, allow []net.IP, known []rememberedDevice,
	save func([]rememberedDevice) error, allowed func(ip, why string), notice func(string, ...any)) *devices {
	d := &devices{addr: addr, subnet: subnet, key: newKey(), allowed: allowed, notice: notice, save: save,
		ok: map[string]bool{}, known: map[string]rememberedDevice{}, outside: map[string]bool{}}
	for _, ip := range allow {
		d.ok[ip.String()] = true
	}
	for _, k := range known {
		switch {
		case time.Since(k.LastSeen) > rememberFor: // forgotten
		case k.Network == d.network():
			d.known[k.IP] = k
		default:
			d.others = append(d.others, k)
		}
	}
	return d
}

// network names the Mac's network, so a device is only recognised on the network it was
// set up on.
func (d *devices) network() string {
	return (&net.IPNet{IP: d.subnet.IP.Mask(d.subnet.Mask), Mask: d.subnet.Mask}).String()
}

// newKey is a random setup key: 50 bits, short enough for a small QR code.
func newKey() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return strings.ToLower(base32.StdEncoding.EncodeToString(b))[:10]
}

// SetupURL is what the QR code opens: the setup page, with the key.
func (d *devices) SetupURL() string {
	return "http://" + d.addr + "/?key=" + url.QueryEscape(d.key)
}

// Admit is the proxy's Admit.
func (d *devices) Admit(peer net.IP) proxy.Access {
	ip := peer.String()
	d.mu.Lock()
	switch {
	case !d.subnet.Contains(peer):
		if !d.outside[ip] {
			d.outside[ip] = true
			d.notice("refused %s: it is not on this Mac's network %s", ip, d.subnet)
		}
		d.mu.Unlock()
		return proxy.Refused
	case d.ok[ip]:
		d.mu.Unlock()
		return proxy.Allowed
	}
	k, found := d.known[ip]
	if !found {
		d.mu.Unlock()
		return proxy.SetupOnly
	}
	d.ok[ip] = true // seen this run: remembered for another rememberFor
	k.LastSeen = time.Now().UTC()
	d.known[ip] = k
	list := d.listLocked()
	d.mu.Unlock()
	d.persist(list)
	d.allowed(ip, "the "+k.Kind+" set up on "+k.Allowed.Local().Format("2 Jan")+" is back")
	return proxy.Allowed
}

// Unlock is the proxy's Unlock: the right key allows the device that sent it, and
// remembers it for later runs.
func (d *devices) Unlock(peer net.IP, key, userAgent string) bool {
	if subtle.ConstantTimeCompare([]byte(key), []byte(d.key)) != 1 || !d.subnet.Contains(peer) {
		return false
	}
	ip := peer.String()
	now := time.Now().UTC()
	d.mu.Lock()
	first := !d.ok[ip]
	d.ok[ip] = true
	k, found := d.known[ip]
	if !found {
		k = rememberedDevice{IP: ip, Network: d.network(), Allowed: now}
	}
	k.Kind = deviceKind(userAgent)
	k.LastSeen = now
	d.known[ip] = k
	list := d.listLocked()
	d.mu.Unlock()
	d.persist(list)
	if first {
		d.allowed(ip, "it opened the setup link; remembered for next time")
	}
	return true
}

func (d *devices) persist(list []rememberedDevice) {
	if err := d.save(list); err != nil {
		d.notice("could not remember the device: %v", err)
	}
}

func (d *devices) listLocked() []rememberedDevice {
	list := append(make([]rememberedDevice, 0, len(d.known)+len(d.others)), d.others...)
	for _, k := range d.known {
		list = append(list, k)
	}
	slices.SortFunc(list, func(a, b rememberedDevice) int { return strings.Compare(a.Network+" "+a.IP, b.Network+" "+b.IP) })
	return list
}

// deviceKind names a device from its browser's User-Agent.
func deviceKind(ua string) string {
	for _, k := range []string{"iPad", "iPhone", "Android"} {
		if strings.Contains(ua, k) {
			return k
		}
	}
	return "device"
}

// Allowed lists the addresses allowed this run, sorted.
func (d *devices) Allowed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for ip := range d.ok {
		out = append(out, ip)
	}
	slices.Sort(out)
	return out
}

// loadDeviceState reads devices.json; a missing file is an empty state.
func loadDeviceState(h *home.Home) (deviceState, error) {
	var st deviceState
	b, err := h.ReadFile(devicesFile)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return deviceState{}, fmt.Errorf("%s: %w", devicesFile, err)
	}
	return st, nil
}

// updateDeviceState changes devices.json under a lock.
var deviceStateMu sync.Mutex

func updateDeviceState(h *home.Home, change func(*deviceState)) error {
	deviceStateMu.Lock()
	defer deviceStateMu.Unlock()
	st, err := loadDeviceState(h)
	if err != nil {
		st = deviceState{} // unreadable: start over rather than never saving again
	}
	change(&st)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return h.WriteFile(devicesFile, append(b, '\n'), 0o600)
}

func loadDevices(h *home.Home) ([]rememberedDevice, error) {
	st, err := loadDeviceState(h)
	return st.Devices, err
}

func saveDevices(h *home.Home, list []rememberedDevice) error {
	return updateDeviceState(h, func(st *deviceState) { st.Devices = list })
}

// deviceNet is the Mac's private IPv4 address on the named interface and its subnet, for
// devices to reach.
func deviceNet(iface string) (*net.IPNet, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			return &net.IPNet{IP: n.IP.To4(), Mask: n.Mask}, nil
		}
	}
	return nil, errors.New(iface + " has no private IPv4 address; join the same Wi-Fi as the device")
}

// parseDeviceIPs checks the --allow-device values.
func parseDeviceIPs(raw []string) ([]net.IP, error) {
	var out []net.IP
	for _, r := range raw {
		ip := net.ParseIP(r)
		if ip == nil || !ip.IsPrivate() {
			return nil, fmt.Errorf("--allow-device %q: give a device's private IP address, e.g. 192.168.0.23", r)
		}
		out = append(out, ip)
	}
	return out, nil
}

// firewallWarning says when the macOS firewall will keep devices out, and how to fix it;
// "" when it will not, or when that cannot be told.
func firewallWarning(ctx context.Context, run execx.Runner, exe string) string {
	q := func(args ...string) string {
		out, err := run.Run(ctx, "socketfilterfw", args...)
		if err != nil {
			return ""
		}
		return string(out)
	}
	if !strings.Contains(q("--getglobalstate"), "enabled") {
		return ""
	}
	if strings.Contains(q("--getblockall"), "enabled") {
		return "the macOS firewall blocks all incoming connections, so devices cannot reach wraith: turn off \"Block all incoming connections\" in System Settings › Network › Firewall › Options"
	}
	if exe != "" && strings.Contains(q("--getappblocked", exe), "blocked") {
		return "the macOS firewall blocks wraith, so devices cannot reach it: in System Settings › Network › Firewall › Options, set wraith to \"Allow incoming connections\""
	}
	return ""
}
