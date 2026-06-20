// Command papi is the Personal API (PAPI) conformance tool. `validate` discovers,
// introspects, and checks a domain's PAPI against RFC-0001 (emitting an
// ndjson-crap stream; pipe to `crap-present`), running the §5 challenge/response
// handshake when given a --recipient. The `piggy-ids`, `ssh-keys`, and `person`
// subcommands surface a domain's published identity material for downstream
// consumption (e.g. identity bootstrap).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
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
	root.AddCommand(newSSHKeysCmd())
	root.AddCommand(newPersonCmd())

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

// guidAnnotation matches the `guid=<HEX>` annotation a PAPI server stamps on each
// /papi/ssh-authorized-keys line (RFC-0001 §4.2). The hex run is case-insensitive
// so a card guid printed either way matches.
var guidAnnotation = regexp.MustCompile(`\bguid=([0-9A-Fa-f]+)\b`)

func newSSHKeysCmd() *cobra.Command {
	var guid string
	cmd := &cobra.Command{
		Use:   "ssh-keys <domain>",
		Short: "Print a domain's PAPI ssh-authorized-keys (optionally one slot-9A key by guid)",
		Long: "Fetch <domain>'s GET /papi/ssh-authorized-keys and print it verbatim — one " +
			"OpenSSH authorized_keys line per visible slot-9A key, each annotated with " +
			"guid=<HEX> and cn=<name> (RFC-0001 §4.2). With --guid <HEX>, print only the " +
			"line whose guid= annotation matches <HEX> (case-insensitively), erroring if no " +
			"line matches — the affordance a bootstrapping client uses to pin its own card's " +
			"signing key.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			body, _, err := c.SSHAuthorizedKeys(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if guid == "" {
				_, err = out.Write(body)
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				m := guidAnnotation.FindStringSubmatch(line)
				if m != nil && strings.EqualFold(m[1], guid) {
					_, err := fmt.Fprintln(out, strings.TrimRight(line, "\r"))
					return err
				}
			}
			return fmt.Errorf("no ssh-authorized-keys line with guid=%s", guid)
		},
	}
	cmd.Flags().StringVar(&guid, "guid", "",
		"print only the slot-9A key whose guid=<HEX> annotation matches (case-insensitive)")
	return cmd
}

// personView is the projected subset of person the `person` command prints:
// handle, the display name (display_name preferred, name as fallback), and the
// contact email when the principal's projection reveals the gated contact node.
type personView struct {
	Handle      string `json:"handle,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

func newPersonCmd() *cobra.Command {
	var recipient, decryptCmd string
	cmd := &cobra.Command{
		Use:   "person <domain>",
		Short: "Print a domain's PAPI person block (handle, display name, contact email)",
		Long: "Fetch <domain>'s GET /papi and print its person block as JSON — handle, " +
			"display name, and contact email. Anonymously the ACL-gated person.contact is " +
			"stripped, so no email shows (RFC-0001 §2, §6). Pass --recipient (and " +
			"--decrypt-cmd) to run the §5 challenge/response handshake and fetch the scoped " +
			"projection, revealing contact.email — the identity-bootstrap affordance a " +
			"downstream consumer sources name/email from.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			var p *papi.Person
			if recipient == "" {
				doc, _, _, derr := c.Document(cmd.Context())
				if derr != nil {
					return derr
				}
				p = doc.Person
			} else {
				p, err = authedPerson(cmd.Context(), c, recipient, decryptCmd)
				if err != nil {
					return err
				}
			}
			return printPerson(cmd.OutOrStdout(), p)
		},
	}
	cmd.Flags().StringVar(&recipient, "recipient", "",
		"piggy recipient id to authenticate as; runs the §5 handshake so contact.email projects")
	cmd.Flags().StringVar(&decryptCmd, "decrypt-cmd", "",
		"shell command that reads the challenge ebox (base64) on stdin and writes the nonce on stdout (e.g. a pivy-box/piggy decrypt wrapper)")
	return cmd
}

// authedPerson runs the §5 handshake as recipient and fetches the scoped /papi so
// the ACL-gated person.contact projects in, returning the authenticated person.
func authedPerson(ctx context.Context, c *papi.Client, recipient, decryptCmd string) (*papi.Person, error) {
	sess, err := inspect.Handshake(ctx, c, inspect.Options{Recipient: recipient, DecryptCmd: decryptCmd})
	if err != nil {
		return nil, err
	}
	resp, err := c.FetchAuthed(ctx, "/papi", sess.ID)
	if err != nil {
		return nil, err
	}
	var env struct {
		Data struct {
			Person *papi.Person `json:"person"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return nil, fmt.Errorf("/papi (authed) data: %w", err)
	}
	return env.Data.Person, nil
}

// printPerson renders the person block as the personView JSON. A nil person (a
// document with no person block) prints an empty object rather than failing.
func printPerson(out io.Writer, p *papi.Person) error {
	var v personView
	if p != nil {
		v.Handle = p.Handle
		v.DisplayName = p.DisplayName
		if v.DisplayName == "" {
			v.DisplayName = p.Name
		}
		if p.Contact != nil {
			v.Email = p.Contact.Email
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
