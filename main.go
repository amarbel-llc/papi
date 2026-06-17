// Command papi is the Personal API (PAPI) conformance tool. This first cut
// discovers and introspects a domain's PAPI (RFC-0001 §4.1, §1), emitting an
// ndjson-crap result stream; pipe it to `crap-present` to render. Conformance
// checks and the auth handshake (RFC-0001 §2, §5) land in a later cut.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/amarbel-llc/papi/internal/inspect"
	"github.com/amarbel-llc/papi/internal/papi"
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
	root.AddCommand(newPiggyIDsCmd())

	if err := root.Execute(); err != nil {
		// A non-conformant verdict is already reported in the ndjson-crap stream;
		// just set the exit code rather than printing an extra error line.
		if !errors.Is(err, inspect.ErrNonConformant) {
			fmt.Fprintln(os.Stderr, "papi:", err)
		}
		os.Exit(1)
	}
}

func newValidateCmd() *cobra.Command {
	var opts inspect.Options
	cmd := &cobra.Command{
		Use:   "validate <domain>",
		Short: "Validate a domain's PAPI against RFC-0001, emitting ndjson-crap",
		Long: "Fetch <domain>'s PAPI, report what it publishes, and check it against the " +
			"RFC-0001 conformance contract — discovery, the {data,meta} envelope and " +
			"meta.visibility, acl-strip, projection, the text endpoints, the auth error " +
			"codes, and the §10 document signature — as an ndjson-crap stream (pipe to " +
			"crap-present). Accepts a bare domain (https assumed) or a full URL, and exits " +
			"non-zero on a MUST violation. Pass --recipient (and --decrypt-cmd) to also run " +
			"the §5 challenge/response handshake and validate the authenticated/scoped tier.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return inspect.Run(cmd.Context(), cmd.OutOrStdout(), args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.Recipient, "recipient", "",
		"piggy recipient id to authenticate as; runs the §5 handshake + scoped-tier checks")
	cmd.Flags().StringVar(&opts.DecryptCmd, "decrypt-cmd", "",
		"shell command that reads the challenge ebox (base64) on stdin and writes the nonce on stdout (e.g. a pivy-box/piggy decrypt wrapper)")
	return cmd
}

func newPiggyIDsCmd() *cobra.Command {
	var recipientsOnly bool
	cmd := &cobra.Command{
		Use:   "piggy-ids <domain>",
		Short: "Print a domain's PAPI piggy-ids file (optionally only encryption recipients)",
		Long: "Fetch <domain>'s GET /papi/piggy-ids and print it verbatim — the piggy-ids " +
			"file: comment lines, then slot-9D encryption recipients and slot-9A SSH auth " +
			"ids. With --recipients-only, emit just the slot-9D encryption recipients " +
			"(RFC-0001 §5.1), ready to feed as a recipient set to an encryptor.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			body, _, err := c.PiggyIDs(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !recipientsOnly {
				_, err = out.Write(body)
				return err
			}
			for _, line := range papi.FilterRecipients(body) {
				if _, err := fmt.Fprintln(out, line); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&recipientsOnly, "recipients-only", false,
		"emit only slot-9D encryption recipients (drop comments and slot-9A auth ids)")
	return cmd
}
