package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/alfa/logingrant"
)

// grantSignNow is the clock `forge grant sign` uses for the default --not-before and the
// already-expired check. A seam so tests do not depend on the real date.
var grantSignNow = time.Now

func newForgeGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Create login grants that let an expiring software key log in without a card",
		Long: "A login grant (RFC-0001 §5.2.1) is signed once at the card and then lets one ed25519 " +
			"software key log in to the papi forward-auth verifier as a restricted principal until it " +
			"expires, so a host with no card can mint session-scoped forge tokens with " +
			"`papi forge token mint --login-grant`.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newForgeGrantSignCmd())
	return cmd
}

func newForgeGrantSignCmd() *cobra.Command {
	var (
		principal, keyFile, domain, notBefore, expires, out string
		maxSession                                          time.Duration
		signer                                              signerFlags
	)
	cmd := &cobra.Command{
		Use:   "sign --principal P --key-file KEY.pub --domain D --expires T [--not-before T] [--max-session 1h] [--out FILE]",
		Short: "Sign a login grant with the card (one card operation)",
		Long: "Build a login grant for the ed25519 public key in --key-file and sign it with the slot-9A " +
			"card: one signature, then no card is needed for the grant's whole life. Everything is " +
			"validated BEFORE the card is touched, so a refused request costs nothing at the card.\n\n" +
			"The grant lets the key log in as --principal, which the verifier must be configured to " +
			"allow for grants (--allow-grant-principal) and which must not be a card's principal. " +
			"--domain is the host the verifier binds signatures to (its external URL host) and is " +
			"never defaulted: a mismatch fails as an indistinguishable 401. Times are RFC 3339 UTC " +
			"with a literal Z; the window is at most 168h and expires is exclusive. The grant file " +
			"is not secret (the private key is) and goes to --out or stdout; an existing --out is " +
			"never overwritten.\n\n" +
			"Revoke before expiry by adding the grant id (printed to stderr) to the verifier's " +
			"--grant-deny-file.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			g, err := buildGrantFromFlags(principal, keyFile, domain, notBefore, expires, maxSession)
			if err != nil {
				return err
			}
			text, err := logingrant.Build(g)
			if err != nil {
				return err
			}
			if out != "" {
				// Fail before the card is touched, not after.
				if _, err := os.Stat(out); err == nil {
					return fmt.Errorf("--out %s already exists; refusing to overwrite", out)
				}
			}
			cardSigner, guid, err := signer.signer(cmd.Context())
			if err != nil {
				return err
			}
			sig, err := logingrant.SignGrant(cmd.Context(), cardSigner, guid, text)
			if err != nil {
				return err
			}
			file := logingrant.MarshalSigned(text, sig)
			if out == "" {
				_, err = cmd.OutOrStdout().Write(file)
			} else {
				err = os.WriteFile(out, file, 0o644)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "grant %s: principal %s, valid %s to %s (exclusive), sessions up to %s\n",
				g.ID(), g.Principal, g.NotBefore.Format(time.RFC3339), g.Expires.Format(time.RFC3339), g.MaxSession)
			return nil
		},
	}
	cmd.Flags().StringVar(&principal, "principal", "", "restricted principal the key logs in as (required)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "OpenSSH public key file (ssh-ed25519) to authorize (required)")
	cmd.Flags().StringVar(&domain, "domain", "",
		"host[:port] the verifier binds signatures to — its external URL host (required, never defaulted)")
	cmd.Flags().StringVar(&notBefore, "not-before", "", "start of validity, RFC 3339 UTC with Z (default: now)")
	cmd.Flags().StringVar(&expires, "expires", "", "end of validity, exclusive, RFC 3339 UTC with Z (required)")
	cmd.Flags().DurationVar(&maxSession, "max-session", time.Hour, "longest login session this grant may open")
	cmd.Flags().StringVar(&out, "out", "", "write the signed grant here (default stdout); never overwrites")
	signer.register(cmd, "signing the grant", false)
	return cmd
}

// buildGrantFromFlags assembles and checks a grant from the sign command's flags,
// without touching the card.
func buildGrantFromFlags(principal, keyFile, domain, notBefore, expires string, maxSession time.Duration) (logingrant.Grant, error) {
	for _, req := range []struct{ name, val string }{
		{"principal", principal}, {"key-file", keyFile}, {"domain", domain}, {"expires", expires},
	} {
		if req.val == "" {
			return logingrant.Grant{}, fmt.Errorf("--%s is required", req.name)
		}
	}
	key, err := readGrantPublicKey(keyFile)
	if err != nil {
		return logingrant.Grant{}, err
	}
	now := grantSignNow().UTC().Truncate(time.Second)
	start := now
	if notBefore != "" {
		if start, err = parseGrantTime("--not-before", notBefore); err != nil {
			return logingrant.Grant{}, err
		}
	}
	end, err := parseGrantTime("--expires", expires)
	if err != nil {
		return logingrant.Grant{}, err
	}
	if !end.After(now) {
		return logingrant.Grant{}, fmt.Errorf("--expires %s is not in the future", expires)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return logingrant.Grant{}, err
	}
	return logingrant.Grant{
		Principal:  principal,
		Key:        key,
		Domain:     domain,
		NotBefore:  start,
		Expires:    end,
		MaxSession: maxSession,
		Nonce:      logingrant.EncodeSig(nonce),
	}, nil
}

// parseGrantTime accepts only the grant's own time syntax, so what is typed is what is
// signed.
func parseGrantTime(flag, v string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05Z", v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q: want RFC 3339 UTC with a literal Z, e.g. 2026-11-18T00:00:00Z", flag, v)
	}
	return t, nil
}

// readGrantPublicKey reads exactly one OpenSSH public key and nothing else: a private
// key handed here by mistake is refused rather than parsed.
func readGrantPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--key-file: %w", err)
	}
	if strings.Contains(string(data), "PRIVATE KEY") {
		return nil, errors.New("--key-file holds a private key; pass the .pub file")
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("--key-file %s: %w", path, err)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("--key-file must hold exactly one key")
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("--key-file is a %s key; only ssh-ed25519 may be granted", pub.Type())
	}
	return pub, nil
}
