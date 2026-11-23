package keychain

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
)

// fakeSecurity keeps whether the Mac trusts the certificate.
func fakeSecurity(trusted *bool, failRemoval bool) *execx.Fake {
	f := execx.NewFake()
	f.Handler = func(tool string, args []string) ([]byte, error) {
		if tool != "security" {
			return nil, errors.New("unexpected tool " + tool)
		}
		switch args[0] {
		case "verify-cert":
			if *trusted {
				return nil, nil
			}
			return nil, &execx.Error{Tool: tool, Args: args, ExitCode: 2, Stderr: "CSSMERR_TP_NOT_TRUSTED"}
		case "add-trusted-cert":
			*trusted = true
			return nil, nil
		case "remove-trusted-cert", "delete-certificate":
			if failRemoval || !*trusted {
				return nil, &execx.Error{Tool: tool, Args: args, ExitCode: 1, Stderr: "not found"}
			}
			if args[0] == "remove-trusted-cert" {
				*trusted = false
			}
			return nil, nil
		}
		return nil, errors.New("unexpected " + strings.Join(args, " "))
	}
	return f
}

func TestR2_3_TrustAndUntrust(t *testing.T) {
	trusted := false
	f := fakeSecurity(&trusted, false)
	k, err := New(f)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, err := k.Trusted(ctx, "/h/ca/ca.pem"); err != nil || ok {
		t.Fatalf("Trusted before = %v, %v", ok, err)
	}
	if err := k.Trust(ctx, "/h/ca/ca.pem"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := k.Trusted(ctx, "/h/ca/ca.pem"); !ok {
		t.Fatal("not trusted after Trust")
	}
	add := f.Calls()[1]
	if !strings.Contains(add, "add-trusted-cert -r trustRoot -p ssl -k ") || !strings.HasSuffix(add, "login.keychain-db /h/ca/ca.pem") {
		t.Fatalf("add call %q", add)
	}

	removed, err := k.Untrust(ctx, "/h/ca/ca.pem", "ABCDEF")
	if err != nil || !removed || trusted {
		t.Fatalf("Untrust = %v, %v (trusted %v)", removed, err, trusted)
	}
	if !strings.Contains(strings.Join(f.Calls(), "\n"), "delete-certificate -Z ABCDEF ") {
		t.Fatalf("calls %q", f.Calls())
	}
	removed, err = k.Untrust(ctx, "/h/ca/ca.pem", "ABCDEF")
	if err != nil || removed {
		t.Fatalf("second Untrust = %v, %v; want nothing to do", removed, err)
	}
}

func TestUntrustFailureWhileStillTrustedIsReported(t *testing.T) {
	trusted := true
	k, _ := New(fakeSecurity(&trusted, true))
	if _, err := k.Untrust(context.Background(), "/h/ca/ca.pem", "ABCDEF"); err == nil {
		t.Fatal("failure hidden although the Mac still trusts the CA")
	}
}

func TestTrustedReportsToolFailures(t *testing.T) {
	f := execx.NewFake() // no handler: the call fails without an exit code
	k, _ := New(f)
	if _, err := k.Trusted(context.Background(), "/h/ca/ca.pem"); err == nil {
		t.Fatal("a failure to run security was reported as untrusted")
	}
}
