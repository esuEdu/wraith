// Command wraith inspects traffic from a chosen source and routes chosen domains around
// the VPN. See docs/SPEC.md.
package main

import (
	"context"
	"os"

	"github.com/esuEdu/wraith/internal/cli"
)

func main() {
	os.Exit(cli.Main(context.Background(), os.Args[1:], cli.Deps{}))
}
