package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"code.linenisgreat.com/papi/internal/alfa/logingrant"
)

// defaultGrantWarnWindow is how close to expiry `forge grant check` starts failing.
const defaultGrantWarnWindow = 48 * time.Hour

func newForgeGrantCheckCmd() *cobra.Command {
	var warnWithin time.Duration
	cmd := &cobra.Command{
		Use:   "check FILE [--warn-within 48h]",
		Short: "Read-only offline check of a signed login grant's shape and expiry",
		Long: "Parse FILE as a signed login grant and print its principal, id, validity window and " +
			"the time left. Exits nonzero when the grant is malformed, not yet valid, expired, or " +
			"within --warn-within of expiring, so a timer or card-day verify step can fail loudly " +
			"before a grant lapses.\n\n" +
			"Offline and read-only: no card, no agent, no network. It checks the grant's shape only, " +
			"not that the card signature verifies (only a verifier holding the registry can say " +
			"that), and it does not say whether the verifier allows the principal.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if warnWithin < 0 {
				return fmt.Errorf("--warn-within must not be negative")
			}
			data, _, err := readRegularFile(args[0], maxGrantFileBytes, "login grant")
			if err != nil {
				return err
			}
			text, _, err := logingrant.ParseSigned(data)
			if err != nil {
				return fmt.Errorf("login grant %s: %w", args[0], err)
			}
			g, err := logingrant.Parse(text)
			if err != nil {
				return fmt.Errorf("login grant %s: %w", args[0], err)
			}
			now := grantSignNow().UTC().Truncate(time.Second)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "grant %s: principal %s, domain %s, valid %s to %s (exclusive), sessions up to %s\n",
				g.ID(), g.Principal, g.Domain, g.NotBefore.Format(time.RFC3339), g.Expires.Format(time.RFC3339), g.MaxSession)
			if err := g.ValidAt(now); err != nil {
				return fmt.Errorf("FAIL: %w (valid %s to %s)", err,
					g.NotBefore.Format(time.RFC3339), g.Expires.Format(time.RFC3339))
			}
			left := g.Expires.Sub(now)
			if left < warnWithin {
				return fmt.Errorf("FAIL: expires in %s, under the %s warning window; renew it", left, warnWithin)
			}
			fmt.Fprintf(out, "PASS: expires in %s (warning window %s)\n", left, warnWithin)
			return nil
		},
	}
	cmd.Flags().DurationVar(&warnWithin, "warn-within", defaultGrantWarnWindow,
		"fail when the grant expires within this long")
	return cmd
}
