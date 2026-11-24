package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/esuEdu/wraith/internal/control"
	"github.com/esuEdu/wraith/internal/export"
)

func (a *app) exportCmd() *cobra.Command {
	var har string
	var noRedact, force bool
	cmd := &cobra.Command{
		Use:   "export --har <file>",
		Short: "Save the running wraith's captured flows as HAR",
		Long: "Captured flows live only in the running wraith's memory; export asks it for them\n" +
			"over a private socket. Authorization, Cookie, Set-Cookie and *token* headers (the\n" +
			"export.redact_headers setting), and query parameters with those names, are\n" +
			"redacted unless --no-redact. The file is written 0600 and never over an existing\n" +
			"one without --force.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if har == "" {
				return fail(ExitUsage, "give a file: wraith export --har <file>")
			}
			h, err := a.openHome()
			if err != nil {
				return err
			}
			defer func() { _ = h.Close() }()
			b, err := control.FetchHAR(cmd.Context(), h, !noRedact)
			if errors.Is(err, control.ErrNotRunning) {
				return fail(ExitRuntime, "%v", err)
			}
			if err != nil {
				return fail(ExitRuntime, "asking wraith for its flows: %v", err)
			}
			if err := export.WriteFile(har, b, force); err != nil {
				return fail(ExitRuntime, "%v", err)
			}
			if noRedact {
				a.info("wrote %s WITHOUT redacting secrets; keep it private", har)
			} else {
				a.info("wrote %s (secrets redacted)", har)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&har, "har", "", "write HAR 1.2 to this file")
	cmd.Flags().BoolVar(&noRedact, "no-redact", false, "keep Authorization, cookies and tokens in the export")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}
