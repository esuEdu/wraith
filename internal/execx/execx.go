// Package execx is the one way wraith runs external tools (networksetup, simctl, scutil,
// lsof, ps, security, sqlite3, plutil, socketfilterfw, route). Tools are looked up by
// name in a fixed table of absolute paths and run with an argument list, never through a shell (S4.2). Arguments are checked by the
// validators in this package before they reach a tool (S4.3).
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runner runs a named tool and returns its standard output.
type Runner interface {
	Run(ctx context.Context, tool string, args ...string) ([]byte, error)
}

// DefaultTools maps the tools wraith may run to their absolute paths. Nothing else runs.
var DefaultTools = map[string]string{
	"networksetup": "/usr/sbin/networksetup",
	"scutil":       "/usr/sbin/scutil",
	"lsof":         "/usr/sbin/lsof",
	"ps":           "/bin/ps",
	"xcrun":        "/usr/bin/xcrun",
	"security":     "/usr/bin/security",
	"sqlite3":      "/usr/bin/sqlite3", // simulator trust stores (wraith ca remove)
	"plutil":       "/usr/bin/plutil",  // app bundle ids (source filter)
	// whether the firewall keeps devices out (--device); read-only queries
	"socketfilterfw": "/usr/libexec/ApplicationFirewall/socketfilterfw",
	"route":          "/sbin/route", // scoped default routes: the Wi-Fi interface (--device)
}

const (
	// DefaultTimeout applies when ctx has no deadline.
	DefaultTimeout = 30 * time.Second
	// MaxOutput caps captured stdout; a tool that writes more is killed.
	MaxOutput = 16 << 20
	maxStderr = 4 << 10
)

// Exec runs real tools from a fixed table.
type Exec struct {
	tools     map[string]string
	maxOutput int
}

// New returns an Exec limited to tools. Every path must be absolute; use DefaultTools
// outside tests.
func New(tools map[string]string) (*Exec, error) {
	t := make(map[string]string, len(tools))
	for name, path := range tools {
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("tool %s: path %q is not absolute", name, path)
		}
		t[name] = path
	}
	return &Exec{tools: t, maxOutput: MaxOutput}, nil
}

// Default returns an Exec for DefaultTools.
func Default() *Exec {
	e, err := New(DefaultTools)
	if err != nil {
		panic(err) // DefaultTools is a constant table; a bad entry is a programming error
	}
	return e
}

// Error is a tool that ran and failed, or could not be started.
type Error struct {
	Tool     string
	Args     []string
	ExitCode int    // -1 when the tool did not run to completion
	Stderr   string // first 4 KiB
	Err      error
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("%s %s", e.Tool, strings.Join(e.Args, " "))
	if e.ExitCode >= 0 {
		msg += fmt.Sprintf(": exit status %d", e.ExitCode)
	} else if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if s := strings.TrimSpace(e.Stderr); s != "" {
		msg += ": " + s
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// ErrUnknownTool means a tool name is not in the table.
var ErrUnknownTool = errors.New("tool is not allowed")

// Run runs tool with args, with LC_ALL=C so output is stable to parse, no stdin, and
// DefaultTimeout unless ctx sets a deadline. It returns stdout, or an *Error.
func (e *Exec) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	path, ok := e.tools[tool]
	if !ok {
		return nil, &Error{Tool: tool, Args: args, ExitCode: -1, Err: ErrUnknownTool}
	}
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return nil, &Error{Tool: tool, Args: args, ExitCode: -1, Err: errors.New("argument contains a NUL byte")}
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	ctx, kill := context.WithCancel(ctx)
	defer kill()

	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- path from a fixed table, argv only, no shell
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	stdout := &capWriter{max: e.maxOutput, onFull: kill}
	stderr := &capWriter{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	if stdout.full {
		return nil, &Error{Tool: tool, Args: args, ExitCode: -1, Stderr: stderr.String(),
			Err: fmt.Errorf("output exceeded %d bytes", e.maxOutput)}
	}
	if err != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) && ctx.Err() == nil {
			code = ee.ExitCode()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, &Error{Tool: tool, Args: args, ExitCode: code, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// capWriter keeps up to max bytes. Past that it drops the rest and calls onFull once.
// The buffer is a named field, not embedded: an embedded bytes.Buffer would expose
// ReadFrom, which io.Copy prefers over Write, and the cap would never apply.
type capWriter struct {
	buf    bytes.Buffer
	max    int
	full   bool
	onFull func()
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.full {
		return len(p), nil
	}
	if room := w.max - w.buf.Len(); len(p) > room {
		w.buf.Write(p[:max(room, 0)])
		w.full = true
		if w.onFull != nil {
			w.onFull()
		}
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *capWriter) Bytes() []byte  { return w.buf.Bytes() }
func (w *capWriter) String() string { return w.buf.String() }
