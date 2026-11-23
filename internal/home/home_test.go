package home

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTemp(t *testing.T) *Home {
	t.Helper()
	h, err := Open(filepath.Join(t.TempDir(), "wraith"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestDirUsesEnvOverride(t *testing.T) {
	d := t.TempDir()
	t.Setenv(EnvVar, d)
	got, err := Dir()
	if err != nil || got != d {
		t.Fatalf("Dir() = %q, %v; want %q", got, err, d)
	}
	t.Setenv(EnvVar, "")
	got, err = Dir()
	if err != nil || filepath.Base(got) != ".wraith" {
		t.Fatalf("Dir() without env = %q, %v", got, err)
	}
}

func TestOpenCreatesPrivateDir(t *testing.T) {
	h := openTemp(t)
	fi, err := os.Stat(h.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %04o, want 0700", fi.Mode().Perm())
	}
}

func TestS1_2_RefusesHomeDirReachableByOthers(t *testing.T) {
	for _, mode := range []fs.FileMode{0o755, 0o750, 0o701, 0o770} {
		dir := filepath.Join(t.TempDir(), "wraith")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		_, err := Open(dir)
		if err == nil || !strings.Contains(err.Error(), "chmod 700") {
			t.Errorf("mode %04o: err = %v, want a refusal with the chmod fix", mode, err)
		}
	}
}

func TestS4_4_RefusesSymlinkedHomeDir(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "wraith")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink refusal", err)
	}
}

func TestS4_4_WriteFileIsAtomicAndPrivate(t *testing.T) {
	h := openTemp(t)
	if err := h.WriteFile("state.json", []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.WriteFile("state.json", []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := h.ReadFile("state.json")
	if err != nil || string(b) != `{"v":2}` {
		t.Fatalf("ReadFile = %q, %v", b, err)
	}
	fi, err := os.Stat(filepath.Join(h.Path(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(h.Path())
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestS4_4_DoesNotFollowSymlinks(t *testing.T) {
	h := openTemp(t)
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.Path(), "config.yaml")); err != nil {
		t.Fatal(err)
	}

	if _, err := h.ReadFile("config.yaml"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ReadFile through symlink: err = %v, want refusal", err)
	}
	if err := h.WriteFile("config.yaml", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "original" {
		t.Fatalf("write followed the symlink: target now %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(h.Path(), "config.yaml")); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		t.Fatalf("config.yaml should now be a regular file: %v %v", fi, err)
	}
}

func TestReadFileLimits(t *testing.T) {
	h := openTemp(t)
	if _, err := h.ReadFile("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: err = %v", err)
	}
	if err := h.WriteFile("big", make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadFile("big"); err == nil {
		t.Fatal("oversized file read without error")
	}
	for _, name := range []string{"", ".", "..", "a/b", "../x"} {
		if _, err := h.ReadFile(name); err == nil {
			t.Errorf("ReadFile(%q) accepted", name)
		}
	}
}

func TestR4_5_OneInstanceAtATime(t *testing.T) {
	h := openTemp(t)
	l1, err := h.Lock()
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.Lock()
	var le *LockedError
	if !errors.Is(err, ErrLocked) || !errors.As(err, &le) || le.PID != os.Getpid() {
		t.Fatalf("second Lock: err = %v, want ErrLocked naming pid %d", err, os.Getpid())
	}

	if err := l1.Unlock(); err != nil {
		t.Fatal(err)
	}
	l2, err := h.Lock()
	if err != nil {
		t.Fatalf("Lock after Unlock: %v", err)
	}
	_ = l2.Unlock()
}
