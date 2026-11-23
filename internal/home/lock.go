package home

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// LockFile is the name of the single-instance lock in the home directory.
const LockFile = "wraith.lock"

// ErrLocked means another wraith instance holds the lock.
var ErrLocked = errors.New("another wraith instance is running")

// LockedError carries the PID written by the instance holding the lock, when readable.
type LockedError struct{ PID int }

func (e *LockedError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("%v (pid %d)", ErrLocked, e.PID)
	}
	return ErrLocked.Error()
}

func (e *LockedError) Unwrap() error { return ErrLocked }

// Lock is a held single-instance lock (R4.5). The kernel drops it when the process exits,
// so a crash never leaves a stale lock behind.
type Lock struct{ f *os.File }

// Lock takes the single-instance lock without waiting. If another process holds it, the
// error matches ErrLocked and is a *LockedError with that process's PID.
func (h *Home) Lock() (*Lock, error) {
	f, err := h.root.OpenFile(LockFile, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, h.symlinkErr(LockFile, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		pid := readPID(f)
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &LockedError{PID: pid}
		}
		return nil, fmt.Errorf("lock %s: %w", LockFile, err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &Lock{f: f}, nil
}

// Unlock releases the lock. The file stays; the next instance reuses it.
func (l *Lock) Unlock() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = l.f.Truncate(0)
	err := l.f.Close() // closing the descriptor releases the flock
	l.f = nil
	return err
}

func readPID(f *os.File) int {
	b, err := io.ReadAll(io.LimitReader(f, 32))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return pid
}
