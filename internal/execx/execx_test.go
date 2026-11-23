package execx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testExec(t *testing.T, tools map[string]string) *Exec {
	t.Helper()
	e, err := New(tools)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestS4_2_DefaultToolsAreAbsoluteAndNoShell(t *testing.T) {
	for name, path := range DefaultTools {
		if !filepath.IsAbs(path) {
			t.Errorf("%s: %q is not absolute", name, path)
		}
		switch filepath.Base(path) {
		case "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "env", "osascript":
			t.Errorf("%s: %q runs arbitrary commands", name, path)
		}
	}
	if _, err := New(map[string]string{"ps": "ps"}); err == nil {
		t.Fatal("relative tool path accepted")
	}
}

func TestS4_2_UnknownToolIsRefused(t *testing.T) {
	_, err := Default().Run(context.Background(), "sh", "-c", "true")
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("err = %v, want ErrUnknownTool", err)
	}
}

func TestS4_2_ArgumentsAreNotInterpretedByAShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	e := testExec(t, map[string]string{"echo": "/bin/echo"})
	args := []string{"a; touch " + marker, "$(touch " + marker + ")", "`id`", "*"}
	out, err := e.Run(context.Background(), "echo", args...)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(out)), strings.Join(args, " "); got != want {
		t.Fatalf("echo printed %q, want the arguments verbatim %q", got, want)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("an argument was executed")
	}
}

func TestS4_2_NULInArgumentIsRefused(t *testing.T) {
	e := testExec(t, map[string]string{"echo": "/bin/echo"})
	if _, err := e.Run(context.Background(), "echo", "a\x00b"); err == nil {
		t.Fatal("NUL byte accepted")
	}
}

func TestRunsRealToolWithCLocale(t *testing.T) {
	out, err := Default().Run(context.Background(), "ps", "-o", "pid=", "-p", strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("ps printed %q", out)
	}
	env, err := testExec(t, map[string]string{"env": "/usr/bin/env"}).Run(context.Background(), "env")
	if err != nil || !strings.Contains(string(env), "LC_ALL=C\n") {
		t.Fatalf("LC_ALL=C not set: %v", err)
	}
}

func TestFailureCarriesExitCodeAndStderr(t *testing.T) {
	e := testExec(t, map[string]string{"ls": "/bin/ls"})
	_, err := e.Run(context.Background(), "ls", "/definitely/not/here")
	var xe *Error
	if !errors.As(err, &xe) || xe.ExitCode <= 0 || !strings.Contains(xe.Stderr, "No such file") {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(err.Error(), "ls /definitely/not/here: exit status") {
		t.Fatalf("message = %q", err.Error())
	}
}

func TestTimeoutKillsTool(t *testing.T) {
	e := testExec(t, map[string]string{"sleep": "/bin/sleep"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.Run(ctx, "sleep", "10")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}

func TestOutputLimitKillsTool(t *testing.T) {
	e := testExec(t, map[string]string{"yes": "/usr/bin/yes"})
	if e.maxOutput != MaxOutput {
		t.Fatalf("default limit = %d, want %d", e.maxOutput, MaxOutput)
	}
	e.maxOutput = 64 << 10 // keep the test fast; the mechanism is the same at 16 MiB
	start := time.Now()
	_, err := e.Run(context.Background(), "yes")
	if err == nil || !strings.Contains(err.Error(), "output exceeded") || time.Since(start) > 10*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}

func TestS4_3_Validators(t *testing.T) {
	good := []error{
		CheckUDID("196410F2-8977-4511-9257-C038A2AC78AA"),
		CheckInterface("en0"), CheckInterface("utun12"),
		CheckPort(1), CheckPort(65535),
		CheckService("Wi-Fi", []string{"Wi-Fi", "Thunderbolt Bridge"}),
		CheckService("USB 10/100/1000 LAN", []string{"USB 10/100/1000 LAN"}),
	}
	for i, err := range good {
		if err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
	bad := []error{
		CheckUDID("booted"), CheckUDID("196410F2-8977-4511-9257-C038A2AC78AA; ls"), CheckUDID(""),
		CheckInterface("EN0"), CheckInterface("en0 "), CheckInterface("-en0"), CheckInterface("en"),
		CheckPort(0), CheckPort(65536),
		CheckService("Ethernet", []string{"Wi-Fi"}),
		CheckService("-setwebproxy", []string{"-setwebproxy"}),
		CheckService("Wi-Fi\n-x", []string{"Wi-Fi\n-x"}),
		CheckService("", []string{""}),
	}
	for i, err := range bad {
		if err == nil {
			t.Errorf("bad[%d] accepted", i)
		}
	}
}

func TestFakeScriptsAndRecords(t *testing.T) {
	f := NewFake().On("networksetup -listallnetworkservices", "Wi-Fi\n", nil)
	out, err := f.Run(context.Background(), "networksetup", "-listallnetworkservices")
	if err != nil || string(out) != "Wi-Fi\n" {
		t.Fatalf("scripted: %q %v", out, err)
	}
	if _, err := f.Run(context.Background(), "scutil", "--dns"); err == nil {
		t.Fatal("unscripted call succeeded")
	}
	f.Handler = func(tool string, args []string) ([]byte, error) { return []byte(tool), nil }
	if out, _ := f.Run(context.Background(), "lsof"); string(out) != "lsof" {
		t.Fatalf("handler: %q", out)
	}
	want := []string{"networksetup -listallnetworkservices", "scutil --dns", "lsof"}
	if got := f.Calls(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q", got)
	}
}
