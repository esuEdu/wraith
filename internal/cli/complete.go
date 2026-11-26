package cli

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/source"
)

// Shell completion: cobra completes commands and flags (wraith st<tab> → start), and
// these complete the values that come from the machine: sources, simulators, interfaces
// and remembered devices. They only read: no ~/.wraith or config.yaml is created by
// pressing tab.

type completeFunc = func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective)

// completeTimeout bounds what one tab may wait for, e.g. simctl.
const completeTimeout = 3 * time.Second

// withPrefix keeps the completions that start with typed (before any tab description).
func withPrefix(list []cobra.Completion, typed string) []cobra.Completion {
	return slices.DeleteFunc(list, func(c cobra.Completion) bool {
		v, _, _ := strings.Cut(c, "\t")
		return !strings.HasPrefix(strings.ToLower(v), strings.ToLower(typed))
	})
}

func values(f func(ctx context.Context) []cobra.Completion) completeFunc {
	return func(cmd *cobra.Command, _ []string, typed string) ([]cobra.Completion, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(context.Background(), completeTimeout)
		defer cancel()
		return withPrefix(f(ctx), typed), cobra.ShellCompDirectiveNoFileComp
	}
}

// peekHome opens ~/.wraith only if it already exists, for completions.
func (a *app) peekHome() (*home.Home, bool) {
	if a.d.Geteuid() == 0 {
		return nil, false
	}
	dir := a.d.HomeDir
	if dir == "" {
		var err error
		if dir, err = home.Dir(); err != nil {
			return nil, false
		}
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, false
	}
	h, err := home.Open(dir)
	return h, err == nil
}

// completeSources offers --source values: the fixed ones, then booted simulators, the
// apps running in them and on the Mac, and remembered devices.
func (a *app) completeSources(ctx context.Context) []cobra.Completion {
	list := []cobra.Completion{
		cobra.CompletionWithDesc("simulator", "every booted simulator"),
		cobra.CompletionWithDesc("all", "every client of the proxy"),
		cobra.CompletionWithDesc("device", "iPhones and iPads on this Wi-Fi (with --device)"),
	}
	for _, d := range a.bootedSims(ctx) {
		list = append(list, cobra.CompletionWithDesc("simulator:"+d.UDID, d.Name))
	}
	seen := map[string]bool{}
	if apps, err := source.RunningSimApps(); err == nil {
		for _, app := range apps {
			if !seen[app.Name] {
				seen[app.Name] = true
				list = append(list, cobra.CompletionWithDesc("app:"+app.Name, "app in a simulator"))
			}
		}
	}
	if apps, err := source.RunningApps(); err == nil {
		for _, app := range apps {
			if !seen[app.Name] {
				seen[app.Name] = true
				list = append(list, cobra.CompletionWithDesc("app:"+app.Name, "Mac app"))
			}
		}
	}
	for _, ip := range a.rememberedIPs() {
		list = append(list, cobra.CompletionWithDesc("device:"+ip, "remembered device"))
	}
	return list
}

type bootedSim struct{ UDID, Name string }

func (a *app) bootedSims(ctx context.Context) []bootedSim {
	sm, err := a.simManager()
	if err != nil {
		return nil
	}
	devs, err := sm.BootedDevices(ctx)
	if err != nil {
		return nil
	}
	out := make([]bootedSim, 0, len(devs))
	for _, d := range devs {
		out = append(out, bootedSim{d.UDID, d.Name + " (" + runtimeName(d.Runtime) + ")"})
	}
	return out
}

func (a *app) completeSims(ctx context.Context) []cobra.Completion {
	var list []cobra.Completion
	for _, d := range a.bootedSims(ctx) {
		list = append(list, cobra.CompletionWithDesc(d.UDID, d.Name))
	}
	return list
}

// completeIfaces offers auto and the Mac's interfaces that are up and have an address.
func completeIfaces(context.Context) []cobra.Completion {
	list := []cobra.Completion{cobra.CompletionWithDesc("auto", "the interface of the default route")}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || !strings.HasPrefix(i.Name, "en") {
			continue
		}
		if addrs, _ := i.Addrs(); len(addrs) > 0 {
			list = append(list, i.Name)
		}
	}
	return list
}

func (a *app) rememberedIPs() []string {
	h, ok := a.peekHome()
	if !ok {
		return nil
	}
	defer func() { _ = h.Close() }()
	list, err := loadDevices(h)
	if err != nil {
		return nil
	}
	var ips []string
	for _, d := range list {
		ips = append(ips, d.IP)
	}
	return ips
}

func (a *app) completeDevices(context.Context) []cobra.Completion {
	return append([]cobra.Completion{cobra.CompletionWithDesc("all", "every remembered device")}, a.rememberedIPs()...)
}

// noArgs is for commands that take no arguments, so tab offers no file names.
func noArgs(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// setCompletions adds value completion to the commands under root.
func (a *app) setCompletions(root *cobra.Command) {
	find := func(path ...string) *cobra.Command {
		c, _, err := root.Find(path)
		if err != nil || c == root {
			panic("completion for a missing command: " + strings.Join(path, " "))
		}
		return c
	}
	flag := func(c *cobra.Command, name string, f completeFunc) {
		if err := c.RegisterFlagCompletionFunc(name, f); err != nil {
			panic(err)
		}
	}
	start := find("start")
	flag(start, "source", values(a.completeSources))
	flag(start, "iface", values(completeIfaces))
	flag(start, "throttle", values(func(context.Context) []cobra.Completion { return slices.Clone(config.Throttles) }))
	flag(start, "allow-device", values(func(context.Context) []cobra.Completion { return a.rememberedIPs() }))
	for _, name := range []string{"port", "max-flows", "max-body", "insecure-upstream"} {
		flag(start, name, noArgs)
	}
	flag(find("ca", "install"), "sim", values(a.completeSims))
	find("devices", "forget").ValidArgsFunction = values(a.completeDevices)

	// Commands without arguments complete nothing rather than file names.
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if c.ValidArgsFunction == nil && c.Runnable() && !takesPath(c) {
			c.ValidArgsFunction = noArgs
		}
	}
	walk(root)
}

// takesPath reports whether a command's argument is a file, which the shell completes.
func takesPath(c *cobra.Command) bool {
	return strings.Contains(c.Use, "<path>")
}
