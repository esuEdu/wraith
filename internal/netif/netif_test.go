package netif

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/esuEdu/wraith/internal/execx"
)

func TestDetectIfaceUsesScopedDefaultRoutes(t *testing.T) {
	ifs, _ := net.Interfaces()
	var name string
	for _, i := range ifs {
		if physical.MatchString(i.Name) && i.Flags&net.FlagUp != 0 {
			if a, _ := i.Addrs(); len(a) > 0 {
				name = i.Name
				break
			}
		}
	}
	if name == "" {
		t.Skip("no en* interface up on this machine")
	}
	f := execx.NewFake()
	f.Handler = func(tool string, args []string) ([]byte, error) {
		if args[len(args)-2] == name {
			return []byte("   route to: default\n  interface: " + name + "\n"), nil
		}
		return nil, errors.New("route: writing to routing socket: not in table")
	}
	got, err := DetectIface(context.Background(), f, "auto")
	if err != nil || got.Name != name || got.Index == 0 {
		t.Fatalf("DetectIface = %+v, %v; want %s", got, err, name)
	}
	none := execx.NewFake() // no scoped route anywhere
	if _, err := DetectIface(context.Background(), none, "auto"); !errors.Is(err, ErrNoInterface) {
		t.Fatalf("no routes: err = %v", err)
	}
	if _, err := DetectIface(context.Background(), f, "en0; ls"); err == nil {
		t.Fatal("bad interface name accepted")
	}
}
