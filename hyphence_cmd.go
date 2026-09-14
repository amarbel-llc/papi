package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"code.linenisgreat.com/papi/internal/alfa/papi"
	"code.linenisgreat.com/papi/internal/bravo/inspect"
)

// hyphenceSignSignerFn is the signer-resolution seam for `papi hyphence sign`.
var hyphenceSignSignerFn = signChallengeSigner

const hyphenceSignedInputHelp = "The signed input is the document's metadata with every " +
	"`- <purpose>@…` line removed, re-emitted in hyphence canonical form, followed — when " +
	"the document has a body — by the blank separator line and the body bytes verbatim " +
	"(RFC-0001 §15.1). A body-less document's signed input is exactly the §14.2 pigpen input."

func newHyphenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "hyphence",
		Short:         "Sign and verify hyphence documents, body included, with slot-9A",
		Long:          "Subcommands that produce and check RFC-0001 §15 signed hyphence documents: a slot-9A ECDSA P-256 signature over the whole document, body included, carried as a `- <purpose>@ecdsa_p256_sig-…` metadata line and verified against a domain's published /papi/piggy-ids keys.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newHyphenceSignCmd())
	cmd.AddCommand(newHyphenceVerifyCmd())
	cmd.AddCommand(newHyphenceResolveCmd())
	return cmd
}

func newHyphenceSignCmd() *cobra.Command {
	var purpose, guid, pin, signerMode string
	cmd := &cobra.Command{
		Use:   "sign --purpose <purpose>",
		Short: "Sign a hyphence document, body included, with slot-9A",
		Long: "Read a hyphence document on stdin, sign it with the caller's PIV slot-9A key " +
			"(ECDSA P-256 over SHA-256), and print it on stdout re-emitted in canonical form " +
			"with a `- <purpose>@ecdsa_p256_sig-…` line inserted immediately before its `!` " +
			"type line. " + hyphenceSignedInputHelp + " --purpose names the signature and is " +
			"owned by the document's domain (e.g. conformist-profile-sig-v1). Refuses a document " +
			"that already carries a line for that purpose or that has no `!` line. The signer " +
			"is chosen by --signer: auto (the default) signs through the SSH agent at " +
			"$SSH_AUTH_SOCK when it is set — piggy-agent, local or forwarded — and otherwise " +
			"directly over PCSC via `piggy sign-bytes --slot 9a`, which needs the card attached " +
			"locally; agent and pcsc force one path. With no --guid the pcsc path uses the sole " +
			"provisioned card; --pin passes the slot-9A PIN to piggy. `papi hyphence verify` " +
			"and `papi hyphence resolve` are the consumer-side inverses.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			raw, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read hyphence document from stdin: %w", err)
			}
			signer, signGUID, err := hyphenceSignSignerFn(ctx, signerMode, guid, pin, "")
			if err != nil {
				return err
			}
			signed, err := inspect.SignHyphence(ctx, signer, signGUID, purpose, raw)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(signed)
			return err
		},
	}
	cmd.Flags().StringVar(&purpose, "purpose", "", "markl purpose of the signature line (required)")
	_ = cmd.MarkFlagRequired("purpose")
	cmd.Flags().StringVar(&guid, "guid", "",
		"GUID of the slot-9A card to sign with (default: the sole provisioned card)")
	cmd.Flags().StringVar(&pin, "pin", "",
		"PIV PIN for slot-9A signing (passed to piggy sign-bytes -P; may be required by the card's PIN policy)")
	cmd.Flags().StringVar(&signerMode, "signer", "auto",
		"slot-9A signer: auto ($SSH_AUTH_SOCK agent if set, else piggy sign-bytes), agent, or pcsc")
	return cmd
}

func newHyphenceVerifyCmd() *cobra.Command {
	var purpose, domain string
	cmd := &cobra.Command{
		Use:   "verify --purpose <purpose> --domain <domain>",
		Short: "Verify a signed hyphence document on stdin against a domain's keys",
		Long: "Read a signed hyphence document on stdin, verify its `- <purpose>@…` signature " +
			"against every slot-9A key <domain> publishes on /papi/piggy-ids, and on success " +
			"print the document bytes verbatim. " + hyphenceSignedInputHelp + " Every failure " +
			"is an error: a malformed document, no signature line for the purpose, more than " +
			"one, a malformed signature, no published slot-9A key, or a signature no published " +
			"key verifies.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read hyphence document from stdin: %w", err)
			}
			c, err := papi.NewClient(domain)
			if err != nil {
				return err
			}
			if _, err := inspect.VerifyHyphenceForDomain(cmd.Context(), c, raw, purpose); err != nil {
				return fmt.Errorf("hyphence: verify against %s: %w", domain, err)
			}
			_, err = cmd.OutOrStdout().Write(raw)
			return err
		},
	}
	cmd.Flags().StringVar(&purpose, "purpose", "", "markl purpose of the signature line (required)")
	cmd.Flags().StringVar(&domain, "domain", "", "PAPI domain whose /papi/piggy-ids keys must verify the signature (required)")
	_ = cmd.MarkFlagRequired("purpose")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

func newHyphenceResolveCmd() *cobra.Command {
	var purpose, path string
	cmd := &cobra.Command{
		Use:   "resolve <locator> --purpose <purpose> --path <path>",
		Short: "Fetch and verify a domain's signed hyphence document",
		Long: "Fetch <locator>'s <path> (e.g. /papi/conformist-profile), verify its " +
			"`- <purpose>@…` signature against the same domain's live /papi/piggy-ids slot-9A " +
			"keys, and on success print the fetched bytes verbatim. " + hyphenceSignedInputHelp +
			" A fetch error, any non-200 status, and an unsigned or unverifiable document are " +
			"all errors.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			body, err := inspect.ResolveHyphence(cmd.Context(), c, path, purpose)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
	cmd.Flags().StringVar(&purpose, "purpose", "", "markl purpose of the signature line (required)")
	cmd.Flags().StringVar(&path, "path", "", "document path under the serving base, e.g. /papi/conformist-profile (required)")
	_ = cmd.MarkFlagRequired("purpose")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}
