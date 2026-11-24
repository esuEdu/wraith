package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/home"
)

func (a *app) devicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "iPhones and iPads remembered by wraith start --device: list | forget",
		Long: "A device that presented a setup key (the QR code's, or the setup profile's) is\n" +
			"remembered by its IP address on that network, and gets in again on later runs\n" +
			"without the code, until it has not been seen for 30 days. These commands list and\n" +
			"forget them.",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "Show the remembered devices",
			Args:  cobra.NoArgs,
			RunE:  func(*cobra.Command, []string) error { return a.listDevices() },
		},
		&cobra.Command{
			Use:   "forget <ip|all>...",
			Short: "Forget devices; they need the QR code again",
			Args:  cobra.MinimumNArgs(1),
			RunE:  func(_ *cobra.Command, args []string) error { return a.forgetDevices(args) },
		},
	)
	return cmd
}

func (a *app) listDevices() error {
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	list, err := loadDevices(h)
	if err != nil {
		return fail(ExitState, "%v", err)
	}
	if len(list) == 0 {
		a.info("no remembered devices; `wraith start --device` shows a QR code to set one up")
		return nil
	}
	for _, d := range list {
		_, _ = fmt.Fprintf(a.d.Stdout, "%-15s %-7s on %-18s set up %s, last seen %s\n", d.IP, d.Kind, d.Network,
			d.Allowed.Local().Format("2006-01-02"), d.LastSeen.Local().Format("2006-01-02 15:04"))
	}
	return nil
}

func (a *app) forgetDevices(args []string) error {
	h, err := a.openHome()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	lock, err := h.Lock() // a running wraith keeps its own list and writes it back
	if errors.Is(err, home.ErrLocked) {
		return fail(ExitRuntime, "wraith is running; stop it first, then forget devices")
	}
	if err != nil {
		return fail(ExitRuntime, "%v", err)
	}
	defer func() { _ = lock.Unlock() }()
	list, err := loadDevices(h)
	if err != nil {
		return fail(ExitState, "%v", err)
	}
	keep := list[:0:0]
	gone := 0
	for _, d := range list {
		if slices.Contains(args, "all") || slices.ContainsFunc(args, func(s string) bool { return strings.TrimSpace(s) == d.IP }) {
			gone++
			continue
		}
		keep = append(keep, d)
	}
	if gone == 0 {
		return fail(ExitUsage, "no remembered device matches; see `wraith devices list`")
	}
	if err := saveDevices(h, keep); err != nil {
		return fail(ExitState, "%v", err)
	}
	a.info("forgot %d device(s); they need the QR code again", gone)
	return nil
}
