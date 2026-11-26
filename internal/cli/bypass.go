package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/config"
	"github.com/esuEdu/wraith/internal/route"
)

// bypassDeprecated is printed wherever the VPN bypass is used: it is removed in v2.0.0,
// when wraith becomes an inspector only.
const bypassDeprecated = "the VPN bypass is deprecated and will be removed in wraith v2.0.0; " +
	"see https://esuedu.github.io/wraith/docs/#bypass"

func (a *app) bypassCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bypass",
		Short: "Hosts that skip the VPN: add | rm | list (deprecated, removed in v2.0.0)",
		Long: "Deprecated: the VPN bypass will be removed in wraith v2.0.0.\n\n" +
			"Bypassed hosts are resolved and dialed on the physical interface (Wi-Fi or\n" +
			"Ethernet) instead of through the VPN, IPv6 first. If that fails, the connection\n" +
			"fails: it never goes through the VPN instead. Patterns: api.example.com, *.example.com.",
		PersistentPreRun: func(*cobra.Command, []string) { a.info("warning: %s", bypassDeprecated) },
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "add <host>...",
			Short: "Add hosts or *.domain patterns to the bypass list",
			Args:  cobra.MinimumNArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return a.editBypass(args, true) },
		},
		&cobra.Command{
			Use:   "rm <host>...",
			Short: "Remove entries from the bypass list",
			Args:  cobra.MinimumNArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return a.editBypass(args, false) },
		},
		&cobra.Command{
			Use:   "list",
			Short: "Show the bypass list and the interface it uses",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, _ []string) error { return a.listBypass(cmd.Context()) },
		},
	)
	return cmd
}

// editBypass adds or removes entries and writes the list back to config.yaml (R6.2).
func (a *app) editBypass(args []string, add bool) error {
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	cfg, _, err := config.Load(h)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	list := slices.Clone(cfg.Bypass)
	changed := 0
	for _, raw := range args {
		p, err := config.NormalizeHostPattern(raw)
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		i := slices.Index(list, p)
		switch {
		case add && i >= 0:
			a.info("%s is already on the bypass list", p)
		case add:
			list = append(list, p)
			changed++
			a.info("added %s", p)
		case i < 0:
			a.info("%s is not on the bypass list", p)
		default:
			list = slices.Delete(list, i, i+1)
			changed++
			a.info("removed %s", p)
		}
	}
	if changed == 0 {
		if add {
			return nil
		}
		return fail(ExitRuntime, "nothing removed")
	}
	if err := config.WriteBypass(h, list); err != nil {
		return fail(ExitRuntime, "%v", err)
	}
	if l, lerr := h.Lock(); lerr != nil {
		a.info("a running wraith uses the new list after it restarts")
	} else {
		_ = l.Unlock()
	}
	return nil
}

func (a *app) listBypass(ctx context.Context) error {
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	cfg, _, err := config.Load(h)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if len(cfg.Bypass) == 0 {
		a.info("the bypass list is empty; add hosts with `wraith bypass add <host>`")
	}
	for _, p := range cfg.Bypass {
		_, _ = fmt.Fprintln(a.d.Stdout, p)
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ifi, err := route.DetectIface(dctx, a.d.Runner, cfg.Interface)
	if err != nil {
		a.info("interface: %v (bypassed hosts would fail)", err)
		return nil
	}
	addrs := make([]string, 0, len(ifi.Addrs))
	for _, ip := range ifi.Addrs {
		addrs = append(addrs, ip.String())
	}
	a.info("interface: %s (%s)", ifi.Name, strings.Join(addrs, ", "))
	return nil
}
