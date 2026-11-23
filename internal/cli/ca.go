package cli

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- certificate identifier for `security`, not a security hash
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/ca"
	"github.com/esuEdu/wraith/internal/execx"
	"github.com/esuEdu/wraith/internal/home"
	"github.com/esuEdu/wraith/internal/keychain"
	"github.com/esuEdu/wraith/internal/sim"
)

func (a *app) caCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the wraith CA: install, remove, export, rotate",
		Long: "wraith decrypts HTTPS with its own CA, created on this Mac in ~/.wraith/ca/.\n" +
			"By default it is trusted by iOS simulators only, never by the Mac itself.",
	}
	cmd.AddCommand(a.caInstallCmd(), a.caRemoveCmd(), a.caExportCmd(), a.caRotateCmd(),
		a.caTrustCmd(), a.caUntrustCmd())
	return cmd
}

// trustWarning is shown before the Mac is told to trust the CA (S1.5).
const trustWarning = `This makes the Mac itself trust the wraith CA. Then:
  - wraith can decrypt HTTPS from every app on this Mac that uses the system trust store;
  - anyone who obtains ~/.wraith/ca/ca.key can impersonate any website to this Mac.
Undo it any time with: wraith ca untrust --mac
`

func (a *app) caTrustCmd() *cobra.Command {
	var mac, yes bool
	cmd := &cobra.Command{
		Use:   "trust --mac",
		Short: "Make the Mac trust the CA, so Mac apps can be decrypted (asks first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !mac {
				return fail(ExitUsage, "ca trust needs --mac (simulators get the CA with `wraith ca install`)")
			}
			h, err := a.openHome()
			if err != nil {
				return err
			}
			defer func() { _ = h.Close() }()
			if _, _, err := ca.Load(h); err != nil {
				return fail(ExitState, "CA: %v", err)
			}
			k, err := keychain.New(a.d.Runner)
			if err != nil {
				return fail(ExitRuntime, "%v", err)
			}
			if ok, err := k.Trusted(cmd.Context(), certPath(h)); err != nil {
				return fail(ExitState, "checking the keychain: %v", err)
			} else if ok {
				a.info("the Mac already trusts the wraith CA")
				return nil
			}
			_, _ = io.WriteString(a.d.Stderr, trustWarning)
			if !yes && !a.confirm("Trust the wraith CA on this Mac?") {
				return fail(ExitRuntime, "not changed")
			}
			a.info("macOS will ask for your password to change trust settings")
			if err := k.Trust(cmd.Context(), certPath(h)); err != nil {
				return fail(ExitState, "adding the CA to the keychain: %v", err)
			}
			a.info("the Mac now trusts the wraith CA; Mac apps can be decrypted with `wraith start --decrypt`")
			return nil
		},
	}
	cmd.Flags().BoolVar(&mac, "mac", false, "the Mac keychain (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func (a *app) caUntrustCmd() *cobra.Command {
	var mac bool
	cmd := &cobra.Command{
		Use:   "untrust --mac",
		Short: "Remove the CA from the Mac keychain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !mac {
				return fail(ExitUsage, "ca untrust needs --mac (simulators: `wraith ca remove`)")
			}
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
			k, err := keychain.New(a.d.Runner)
			if err != nil {
				return fail(ExitRuntime, "%v", err)
			}
			sum := sha1.Sum(cert.Raw) // #nosec G401 -- how `security` names certificates
			removed, err := k.Untrust(cmd.Context(), certPath(h), strings.ToUpper(hex.EncodeToString(sum[:])))
			if err != nil {
				return fail(ExitState, "removing the CA from the keychain: %v", err)
			}
			if removed {
				a.info("the Mac no longer trusts the wraith CA")
			} else {
				a.info("the Mac did not trust the wraith CA; nothing to remove")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&mac, "mac", false, "the Mac keychain (required)")
	return cmd
}

// confirm asks a yes/no question on stderr and reads the answer from stdin; anything but
// y or yes, including end of input, is no.
func (a *app) confirm(question string) bool {
	_, _ = fmt.Fprintf(a.d.Stderr, "%s [y/N] ", question)
	line, _ := bufio.NewReader(a.d.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
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
