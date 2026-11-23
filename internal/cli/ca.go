package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/ca"
	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/sim"
)

func (a *app) caCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the wraith CA: install, remove, export, rotate",
		Long: "wraith decrypts HTTPS with its own CA, created on this Mac in ~/.wraith/ca/.\n" +
			"By default it is trusted by iOS simulators only, never by the Mac itself.",
	}
	cmd.AddCommand(a.caInstallCmd(), a.caRemoveCmd(), a.caExportCmd(), a.caRotateCmd())
	for _, name := range []string{"trust", "untrust"} {
		cmd.AddCommand(&cobra.Command{
			Use:                name,
			Short:              name + " the CA in the Mac keychain (planned, M2 #21)",
			DisableFlagParsing: true,
			RunE: func(*cobra.Command, []string) error {
				return fail(ExitUsage, "ca %s is not implemented yet", name)
			},
		})
	}
	return cmd
}

func (a *app) simManager() (*sim.Manager, error) {
	m, err := sim.New(a.d.Runner, a.d.SimDevicesDir)
	if err != nil {
		return nil, fail(ExitRuntime, "%v", err)
	}
	return m, nil
}

func certPath(h *home.Home) string { return filepath.Join(h.Path(), ca.Dir, ca.CertFile) }

func (a *app) caInstallCmd() *cobra.Command {
	var udid string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the CA into booted simulators (or one, with --sim)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := a.openHome()
			if err != nil {
				return err
			}
			defer func() { _ = h.Close() }()
			c, created, err := ca.Load(h)
			if err != nil {
				return fail(ExitState, "CA: %v", err)
			}
			if created {
				a.info("created the wraith CA (fingerprint %s)", c.Fingerprint())
			}
			sm, err := a.simManager()
			if err != nil {
				return err
			}
			devs, err := a.targetDevices(cmd.Context(), sm, udid)
			if err != nil {
				return err
			}
			var failed int
			for _, d := range devs {
				added, err := sm.Install(cmd.Context(), d, certPath(h), c.SHA256())
				switch {
				case err != nil:
					failed++
					a.info("%s: %v", d, err)
				case added:
					a.info("%s: installed the wraith CA", d)
				default:
					a.info("%s: already trusts the wraith CA", d)
				}
			}
			if failed > 0 {
				return fail(ExitState, "the CA could not be installed into %d simulator(s)", failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&udid, "sim", "", "only this simulator (UDID)")
	return cmd
}

// targetDevices returns the booted simulators, or the one named by udid.
func (a *app) targetDevices(ctx context.Context, sm *sim.Manager, udid string) ([]sim.Device, error) {
	if udid != "" {
		if err := execx.CheckUDID(udid); err != nil {
			return nil, fail(ExitUsage, "--sim: %v", err)
		}
		all, err := sm.Devices(ctx)
		if err != nil {
			return nil, fail(ExitRuntime, "listing simulators: %v", err)
		}
		for _, d := range all {
			if d.UDID == udid {
				if !d.Booted() {
					return nil, fail(ExitRuntime, "%s is not booted; boot it first (xcrun simctl boot %s)", d, d.UDID)
				}
				return []sim.Device{d}, nil
			}
		}
		return nil, fail(ExitUsage, "no simulator with UDID %s", udid)
	}
	booted, err := sm.BootedDevices(ctx)
	if err != nil {
		return nil, fail(ExitRuntime, "listing simulators: %v", err)
	}
	if len(booted) == 0 {
		return nil, fail(ExitRuntime, "no booted simulator; boot one, or run `wraith start --decrypt`, which installs the CA into simulators as they boot")
	}
	return booted, nil
}

func (a *app) caRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Remove the CA from every simulator, booted or not",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := a.openHome()
			if err != nil {
				return err
			}
			defer func() { _ = h.Close() }()
			cert, err := ca.Peek(h)
			if errors.Is(err, fs.ErrNotExist) {
				a.info("there is no wraith CA; nothing to remove")
				return nil
			}
			if err != nil {
				return fail(ExitState, "CA: %v", err)
			}
			n, err := a.removeFromSimulators(cmd.Context(), sha256.Sum256(cert.Raw))
			if err != nil {
				return err
			}
			if n == 0 {
				a.info("no simulator trusted the wraith CA")
			}
			return nil
		},
	}
}

// removeFromSimulators removes the certificate with SHA-256 fp from every simulator and
// returns how many had it (S4.5).
func (a *app) removeFromSimulators(ctx context.Context, fp [32]byte) (int, error) {
	sm, err := a.simManager()
	if err != nil {
		return 0, err
	}
	devs, err := sm.Devices(ctx)
	if err != nil {
		return 0, fail(ExitRuntime, "listing simulators: %v", err)
	}
	n, failed := 0, 0
	for _, d := range devs {
		removed, err := sm.Remove(ctx, d, fp)
		switch {
		case err != nil:
			failed++
			a.info("%s: %v", d, err)
		case removed && d.Booted():
			n++
			a.info("%s: removed the wraith CA; restart the simulator for it to take effect", d)
		case removed:
			n++
			a.info("%s: removed the wraith CA", d)
		}
	}
	if failed > 0 {
		return n, fail(ExitState, "the CA could not be removed from %d simulator(s)", failed)
	}
	return n, nil
}

func (a *app) caExportCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "export <path>",
		Short: "Write the CA certificate (PEM) for installing by hand; never the key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := a.openHome()
			if err != nil {
				return err
			}
			defer func() { _ = h.Close() }()
			c, _, err := ca.Load(h)
			if err != nil {
				return fail(ExitState, "CA: %v", err)
			}
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			f, err := os.OpenFile(args[0], flags, 0o644) // #nosec G302 G304 -- a public certificate, at a path the user named
			if errors.Is(err, fs.ErrExist) {
				return fail(ExitRuntime, "%s exists; use --force to overwrite it", args[0])
			}
			if err != nil {
				return fail(ExitRuntime, "%v", err)
			}
			if _, err := f.Write(c.CertPEM()); err != nil {
				_ = f.Close()
				return fail(ExitRuntime, "%v", err)
			}
			if err := f.Close(); err != nil {
				return fail(ExitRuntime, "%v", err)
			}
			a.info("wrote the wraith CA certificate to %s (SHA-256 %s)", args[0], c.Fingerprint())
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}

func (a *app) caRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Replace the CA: remove the old one from simulators, install the new one into booted ones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := a.openHome()
			if err != nil {
				return err
			}
			defer func() { _ = h.Close() }()
			lock, err := h.Lock()
			if err != nil {
				return fail(ExitRuntime, "stop wraith before rotating the CA: %v", err)
			}
			defer func() { _ = lock.Unlock() }()

			var old *x509.Certificate
			if old, err = ca.Peek(h); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fail(ExitState, "CA: %v", err)
			}
			c, err := ca.Rotate(h)
			if err != nil {
				return fail(ExitState, "CA: %v", err)
			}
			a.info("new wraith CA, fingerprint %s", c.Fingerprint())
			if old != nil {
				if _, err := a.removeFromSimulators(cmd.Context(), sha256.Sum256(old.Raw)); err != nil {
					return err
				}
			}
			sm, err := a.simManager()
			if err != nil {
				return err
			}
			booted, err := sm.BootedDevices(cmd.Context())
			if err != nil {
				return fail(ExitRuntime, "listing simulators: %v", err)
			}
			for _, d := range booted {
				if _, err := sm.Install(cmd.Context(), d, certPath(h), c.SHA256()); err != nil {
					a.info("%s: %v", d, err)
					continue
				}
				a.info("%s: installed the new CA", d)
			}
			a.info("if you trusted the old CA on the Mac or a device by hand, replace it there too")
			return nil
		},
	}
}
