package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"code.linenisgreat.com/papi/internal/alfa/papi"
	"code.linenisgreat.com/papi/internal/bravo/inspect"
)

// sessionView is `papi auth`'s default output: the §5.2 response payload.
type sessionView struct {
	Session   string   `json:"session"`
	Principal string   `json:"principal"`
	Groups    []string `json:"groups"`
	ExpiresAt int64    `json:"expires_at"`
}

// newAuthCmd is the FDR 0012 one-shot: run the §5 handshake and print the minted
// session so an operator sitting can hand it to a script. One card operation, no
// further requests. The session is the only thing written to stdout; nothing about
// it goes to stderr.
func newAuthCmd() *cobra.Command {
	var raw, header bool
	var af authFlags
	cmd := &cobra.Command{
		Use:   "auth <domain> --auth-key-id <slot-9A id> [--raw | --header]",
		Short: "Authenticate to a domain and print the minted session (one card operation)",
		Long: "Run the full RFC-0001 §5 handshake against <domain> (discovery, challenge, sign, " +
			"response) and print the minted session, then exit. It performs ONE card operation " +
			"and makes no further requests; the session (about 15 minutes, §5.2) is the caller's " +
			"to present as `Authorization: PiggySession <id>` (§5.3). It is not stored or " +
			"refreshed: re-run for a new one.\n\n" +
			"Output: by default the §5.2 payload as JSON ({session, principal, groups, " +
			"expires_at}); --header prints the ready-to-use Authorization header line; --raw " +
			"prints the bare session id. The session is a bearer credential: it is written to " +
			"stdout only, so capture it (SESSION=$(papi auth … --raw)) rather than letting it " +
			"land in a terminal log.\n\n" +
			"Signing uses the same flags as `repos`/`validate` (--auth-key-id with the signer " +
			"flags; or the legacy --recipient/--decrypt-cmd for servers advertising " +
			"piggy-challenge-response). Credentials are checked before the card is touched.",
		Args: cobra.ExactArgs(1),
		// stdout carries only the session: a failure must not print usage text
		// there, or SESSION=$(papi auth ...) would capture it.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if raw && header {
				return errors.New("--raw and --header are mutually exclusive")
			}
			if !af.active() {
				return errors.New("pass --auth-key-id <slot-9A id> (or the legacy --recipient/--decrypt-cmd): " +
					"`papi auth` needs a credential to authenticate with")
			}
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			opts, err := af.options(cmd.Context())
			if err != nil {
				return err
			}
			sess, err := inspect.Handshake(cmd.Context(), c, opts)
			if err != nil {
				return fmt.Errorf("authenticate to %s: %w", args[0], err)
			}
			out := cmd.OutOrStdout()
			switch {
			case raw:
				_, err = fmt.Fprintln(out, sess.ID)
			case header:
				_, err = fmt.Fprintf(out, "Authorization: PiggySession %s\n", sess.ID)
			default:
				groups := sess.Groups
				if groups == nil {
					groups = []string{}
				}
				err = json.NewEncoder(out).Encode(sessionView{
					Session: sess.ID, Principal: sess.Principal, Groups: groups, ExpiresAt: sess.ExpiresAt,
				})
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&raw, "raw", false, "print only the bare session id")
	cmd.Flags().BoolVar(&header, "header", false, "print the ready-to-use `Authorization: PiggySession <id>` line")
	af.register(cmd)
	return cmd
}
