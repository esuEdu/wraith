// Package home manages wraith's home directory (~/.wraith, or $WRAITH_HOME): checking its
// owner and mode, reading and writing files in it without following symlinks, and the
// lock that keeps one instance running at a time.
package home

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// EnvVar overrides the home directory; tests and the nightly run point it at a temp dir.
const EnvVar = "WRAITH_HOME"

// MaxFileSize caps what ReadFile reads from the home directory.
const MaxFileSize = 1 << 20

// Dir returns $WRAITH_HOME, or ~/.wraith.
func Dir() (string, error) {
	if d := os.Getenv(EnvVar); d != "" {
		return filepath.Abs(d)
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".wraith"), nil
}

// Home is an opened, checked home directory. All file access goes through it.
type Home struct {
	path string
	root *os.Root
}

// Open creates dir with mode 0700 if it does not exist, then checks that it is a real
// directory (not a symlink), owned by the current user, and not readable or writable by
// anyone else (S1.2). It refuses rather than fixing the mode, and says how to fix it.
func Open(dir string) (*Home, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(dir, fi, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Home{path: dir, root: root}, nil
}

// Sub opens the subdirectory name (creating it with mode 0700), with the same checks as
// Open. It is how the CA gets its own private directory (R2.1, S1.2).
func (h *Home) Sub(name string) (*Home, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if err := h.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	path := filepath.Join(h.path, name)
	fi, err := h.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(path, fi, true); err != nil {
		return nil, err
	}
	root, err := h.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &Home{path: path, root: root}, nil
}

// CheckPrivate returns an error unless name is a regular file (not a symlink) owned by
// the current user with no group or other permissions (S1.2). The error says how to fix it.
func (h *Home) CheckPrivate(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	fi, err := h.root.Lstat(name)
	if err != nil {
		return err
	}
	return checkPrivate(filepath.Join(h.path, name), fi, false)
}

func checkPrivate(path string, fi fs.FileInfo, dir bool) error {
	what, fix := "file", "600"
	if dir {
		what, fix = "directory", "700"
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; wraith needs a real %s there", path, what)
	}
	if dir && !fi.IsDir() || !dir && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a %s", path, what)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not you (uid %d)", path, st.Uid, os.Getuid())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; other users must not reach it. Fix with: chmod %s %q", path, perm, fix, path)
	}
	return nil
}

// Path returns the directory's path.
func (h *Home) Path() string { return h.path }

// Close releases the directory handle. Locks taken with Lock stay held until unlocked.
func (h *Home) Close() error { return h.root.Close() }

func checkName(name string) error {
	if name == "" || strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return fmt.Errorf("invalid file name %q", name)
	}
	return nil
}

// ReadFile reads name from the home directory. A symlink is an error (S4.4), and so is a
// file larger than MaxFileSize. A missing file returns an error matching fs.ErrNotExist.
func (h *Home) ReadFile(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	f, err := h.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, h.symlinkErr(name, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, MaxFileSize)
	}
	return b, nil
}

// WriteFile replaces name atomically (S4.4): it writes a temp file in the same directory
// with perm, syncs it, and renames it over name. Readers see the old or the new content,
// never a mix, and a symlink at name is replaced, never followed.
func (h *Home) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if err := checkName(name); err != nil {
		return err
	}
	tmp := "." + name + ".tmp-" + strconv.Itoa(os.Getpid())
	f, err := h.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = h.root.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil { // umask may have narrowed it; make it exact
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := h.root.Rename(tmp, name); err != nil {
		_ = h.root.Remove(tmp)
		ok = true // already cleaned up
		return err
	}
	ok = true
	return nil
}

// Remove deletes name; a missing file is not an error.
func (h *Home) Remove(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := h.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// symlinkErr turns an open failure caused by a symlink at name into a clear error. os.Root
// reports one pointing outside as "path escapes", O_NOFOLLOW one inside as ELOOP.
func (h *Home) symlinkErr(name string, err error) error {
	if fi, lerr := h.root.Lstat(name); errors.Is(err, syscall.ELOOP) || (lerr == nil && fi.Mode()&fs.ModeSymlink != 0) {
		return fmt.Errorf("%s is a symlink; wraith does not follow symlinks in its home directory", name)
	}
	return err
}
