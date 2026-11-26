package cli

import (
	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/config"
)

// bypassRemoved explains the VPN bypass of wraith 1.x, removed in v2.0.0.
const bypassRemoved = "the VPN bypass was removed in wraith v2.0.0; wraith only inspects traffic now " +
	"(https://esuedu.github.io/wraith/docs/#limits)"

// bypassCmd answers the old `wraith bypass` commands with why they are gone, instead of
// cobra's "unknown command". It is hidden from help and completion.
func (a *app) bypassCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "bypass",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(*cobra.Command, []string) error {
			return fail(ExitUsage, "%s", bypassRemoved)
		},
	}
}

// warnOldBypass warns when config.yaml still has the bypass list of wraith 1.x, which is
// read and ignored.
func (a *app) warnOldBypass(cfg config.Config) {
	if len(cfg.Bypass) > 0 {
		a.info("warning: config.yaml still has a bypass list of %d host(s), now ignored: %s; delete the bypass: line to stop this warning",
			len(cfg.Bypass), bypassRemoved)
	}
}
