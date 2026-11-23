// Command wraith inspects traffic from a chosen source and routes chosen
// domains around the VPN. See docs/SPEC.md.
package main

import (
	"fmt"
	"os"

	"github.com/esuEdu/wraith/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("wraith %s (%s, %s)\n", version.Version, version.Commit, version.Date)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "wraith: %q is not implemented yet\n", os.Args[1])
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: wraith <command>

commands (planned, see docs/SPEC.md):
  start     start the proxy and the live view
  stop      restore system proxy settings
  bypass    add | rm | list hosts that skip the VPN
  ca        install | remove | trust | untrust | export
  doctor    check proxy, CA and bypass
  export    save captured flows as HAR
  version   print version`)
}
