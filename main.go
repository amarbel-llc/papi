// Command papi is the Personal API (PAPI) conformance tool. This first cut
// discovers and introspects a domain's PAPI (RFC-0001 §4.1, §1), emitting an
// ndjson-crap result stream; pipe it to `crap-present` to render. Conformance
// checks and the auth handshake (RFC-0001 §2, §5) land in a later cut.
package main

import (
	"fmt"
	"os"

	"github.com/amarbel-llc/papi/internal/inspect"
	"github.com/spf13/cobra"
)

// version is injected via -ldflags at build time (eng-versioning(7)); it stays
// "dev" for a plain `go build`.
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:           "papi",
		Short:         "Personal API (PAPI) conformance tool",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newValidateCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "papi:", err)
		os.Exit(1)
	}
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <domain>",
		Short: "Discover and introspect a domain's PAPI, emitting ndjson-crap",
		Long: "Fetch <domain>'s PAPI discovery document and projected document and " +
			"report what the domain publishes as an ndjson-crap stream. Accepts a " +
			"bare domain (https assumed) or a full URL. Conformance verdicts and the " +
			"piggy challenge/response handshake are added in a later cut.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return inspect.Run(cmd.Context(), cmd.OutOrStdout(), args[0])
		},
	}
}
