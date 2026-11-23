// Package keychain adds the wraith CA to the Mac's trusted roots and removes it, through
// /usr/bin/security and the login keychain. wraith never does this on its own: only
// `wraith ca trust --mac`, after the user confirms, adds it (R2.3, S1.5).
package keychain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/esuEdu/wraith/internal/execx"
)

// promptTimeout leaves the user time to answer macOS's password dialog.
const promptTimeout = 5 * time.Minute

// Keychain drives `security` against the user's login keychain.
type Keychain struct {
	run   execx.Runner
	login string
}

// New returns a Keychain for the current user's login keychain.
func New(run execx.Runner) (*Keychain, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Keychain{run: run, login: filepath.Join(h, "Library", "Keychains", "login.keychain-db")}, nil
}

// Trusted reports whether the Mac trusts the certificate at certPath as a root.
func (k *Keychain) Trusted(ctx context.Context, certPath string) (bool, error) {
	_, err := k.run.Run(ctx, "security", "verify-cert", "-c", certPath, "-L", "-q")
	if err == nil {
		return true, nil
	}
	var xe *execx.Error
	if errors.As(err, &xe) && xe.ExitCode > 0 {
		return false, nil // CSSMERR_TP_NOT_TRUSTED and friends
	}
	return false, err
}

// Trust adds the certificate to the login keychain as a trusted root for SSL. macOS asks
// the user for their password; this waits up to five minutes for them.
func (k *Keychain) Trust(ctx context.Context, certPath string) error {
	ctx, cancel := context.WithTimeout(ctx, promptTimeout)
	defer cancel()
	_, err := k.run.Run(ctx, "security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", k.login, certPath)
	return err
}

// Untrust removes the certificate's trust settings and deletes it (by SHA-1, as
// `security` identifies certificates) from the login keychain. It reports whether there
// was anything to remove.
func (k *Keychain) Untrust(ctx context.Context, certPath, sha1Hex string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, promptTimeout)
	defer cancel()
	_, errTrust := k.run.Run(ctx, "security", "remove-trusted-cert", certPath)
	_, errCert := k.run.Run(ctx, "security", "delete-certificate", "-Z", sha1Hex, k.login)
	if errTrust == nil || errCert == nil {
		return true, nil
	}
	// Neither step found anything: fine if the Mac indeed does not trust it.
	trusted, err := k.Trusted(ctx, certPath)
	if err != nil {
		return false, err
	}
	if trusted {
		return false, errors.Join(errTrust, errCert)
	}
	return false, nil
}
