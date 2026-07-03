// Command papi is the Personal API (PAPI) conformance tool. `validate` discovers,
// introspects, and checks a domain's PAPI against RFC-0001 (emitting an
// ndjson-crap stream; pipe to `crap-present`), running the §5 challenge/response
// handshake when given a --recipient. The `piggy-ids`, `ssh-keys`, `person`,
// `repos`, and `forges` subcommands surface a domain's published identity material,
// repositories, and forge identities for downstream consumption (e.g. identity
// bootstrap); the projected ones take --recipient/--decrypt-cmd to run the same §5
// handshake and reveal the full scoped set.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/crap/go-crap/v2/viewport"
	"github.com/amarbel-llc/papi/internal/0/identity"
	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/authproxy"
	"github.com/amarbel-llc/papi/internal/alfa/enroll"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
	"github.com/amarbel-llc/papi/internal/alfa/signchallenge"
	"github.com/itchyny/gojq"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// version and commit are injected via -ldflags at build time (eng-versioning(7),
// via igloo's buildGoApplication from version.env + src.rev); they stay
// "dev"/"unknown" for a plain `go build`.
var (
	version = "dev"
	commit  = "unknown"
)

// selfID is the eng-versioning(7) self-identification line, "papi VERSION+COMMIT"
// — papi pins no downstream components, so the version subcommand emits only it.
// igloo burns in the full src.rev; the line shows a short commit to match the
// family style (e.g. "papi 0.2.0+974a56a").
func selfID() string {
	c := commit
	if len(c) > 7 {
		c = c[:7]
	}
	return fmt.Sprintf("papi %s+%s", version, c)
}

func main() {
	root := &cobra.Command{
		Use:           "papi",
		Short:         "Personal API (PAPI) conformance tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newValidateCmd())
	root.AddCommand(newPiggyIDsCmd())
	root.AddCommand(newSSHKeysCmd())
	root.AddCommand(newSSHCopyIDCmd())
	root.AddCommand(newSSHSyncCmd())
	root.AddCommand(newVerifiedRecipientsCmd())
	root.AddCommand(newBootstrapCmd())
	root.AddCommand(newGHCheckCmd())
	root.AddCommand(newGHAuthCmd())
	root.AddCommand(newPersonCmd())
	root.AddCommand(newReposCmd())
	root.AddCommand(newForgesCmd())
	root.AddCommand(newProfilesCmd())
	root.AddCommand(newQueryCmd())
	root.AddCommand(newEnrollCmd())
	root.AddCommand(newVerifyReceiptCmd())
	root.AddCommand(newSignChallengeCmd())
	root.AddCommand(newIdentityCmd())
	root.AddCommand(newSignChallengeServeCmd())
	root.AddCommand(newAuthVerifierCmd())
	root.AddCommand(newVersionCmd())

	if err := root.Execute(); err != nil {
		// A non-conformant verdict is already reported in the ndjson-crap stream;
		// just set the exit code rather than printing an extra error line.
		if !errors.Is(err, inspect.ErrNonConformant) {
			fmt.Fprintln(os.Stderr, "papi:", err)
		}
		os.Exit(1)
	}
}

// newVersionCmd prints the eng-versioning(7) self-identification line.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print papi's version and commit",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), selfID())
		},
	}
}

// newIdentityCmd is the parent of the local identity.toml readers (`get` and
// `domain`). papi owns the read MECHANISM only — TOML parse, dotted-path lookup,
// default-on-absent, XDG resolution — and attaches no meaning to any field (the
// schema is the consumer's, e.g. eng's host.*). See FDR-0009.
func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Read fields from the local identity.toml",
		Long: "Read scalar fields from the person's local identity.toml " +
			"($XDG_CONFIG_HOME/identity.toml, else ~/.config/identity.toml). papi owns the " +
			"read mechanism only — TOML parse, dotted-path lookup, default-on-absent, XDG " +
			"resolution — and attaches no meaning to any field; the schema is the consumer's. " +
			"See FDR-0009.",
	}
	cmd.AddCommand(newIdentityGetCmd())
	cmd.AddCommand(newIdentityDomainCmd())
	return cmd
}

// identityFilePath resolves which identity.toml to read: the --file override
// when set, else the XDG default.
func identityFilePath(file string) (string, error) {
	if file != "" {
		return file, nil
	}
	return identity.DefaultPath()
}

func newIdentityGetCmd() *cobra.Command {
	var def, file string
	cmd := &cobra.Command{
		Use:   "get <dotted.path>",
		Short: "Print the scalar at a dotted identity.toml path",
		Long: "Read identity.toml and print the scalar at <dotted.path> (e.g. " +
			"host.privilege-escalation, papi.domain), with a trailing newline. When the file " +
			"or the key is absent, print --default (empty if unset) and exit 0 — mirroring a " +
			"nix `... or \"<default>\"` read, so it is safe under set -e. A present empty " +
			"string is printed as-is (the default does NOT fire). A path resolving to a " +
			"table/array, or a malformed/unreadable file, exits non-zero.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := identityFilePath(file)
			if err != nil {
				return err
			}
			value, found, err := identity.Lookup(path, args[0])
			if err != nil {
				return err
			}
			if !found {
				value = def // empty string when --default is unset
			}
			fmt.Fprintln(cmd.OutOrStdout(), value)
			return nil
		},
	}
	cmd.Flags().StringVar(&def, "default", "",
		"value to print when the file or key is absent (exit 0)")
	cmd.Flags().StringVar(&file, "file", "",
		"identity.toml path to read (default: $XDG_CONFIG_HOME/identity.toml, else ~/.config/identity.toml)")
	return cmd
}

func newIdentityDomainCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Print this host's PAPI identity domain from identity.toml",
		Long: "Print the canonical PAPI identity domain — identity.toml's [papi] domain " +
			"(dotted path papi.domain). Sugar over `papi identity get papi.domain`. papi " +
			"carries NO built-in domain default and this accessor has no --default: an absent " +
			"key prints empty and exits 0 (the value's single source of truth is " +
			"identity.toml, not papi's binary — FDR-0009). For a fallback, use " +
			"`papi identity get papi.domain --default <d>`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := identityFilePath(file)
			if err != nil {
				return err
			}
			// found is intentionally ignored: an absent key yields the empty value,
			// which is printed (empty line, exit 0). Only a non-scalar/parse error
			// returns non-nil err.
			value, _, err := identity.Lookup(path, "papi.domain")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), value)
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "",
		"identity.toml path to read (default: $XDG_CONFIG_HOME/identity.toml, else ~/.config/identity.toml)")
	return cmd
}

func newValidateCmd() *cobra.Command {
	var opts inspect.Options
	cmd := &cobra.Command{
		Use:   "validate <domain>",
		Short: "Validate a domain's PAPI against RFC-0001, emitting ndjson-crap",
		Long: "Fetch <domain>'s PAPI, report what it publishes, and check it against the " +
			"RFC-0001 conformance contract — discovery, the {data,meta} envelope and " +
			"meta.visibility, acl-strip, projection, the text endpoints, the auth error " +
			"codes, identity-ownership proofs (§9), key co-location proofs (§9.6), the " +
			"document signatures (§10), and the nix cache entry schema (§11) — as an " +
			"ndjson-crap stream (pipe to " +
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

func newBootstrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap <domain>",
		Short: "Print a domain's PAPI self-bootstrap shim (GET /papi/bootstrap)",
		Long: "Fetch <domain>'s GET /papi/bootstrap and print the self-bootstrap shim verbatim — " +
			"the small POSIX-sh script a cold, YubiKey-provisioned host runs to clone eng (over " +
			"HTTPS) and exec its provisioner. This is the inspect-before-you-run affordance for " +
			"the cold-host entrypoint `curl -fsSL https://<domain>/papi/bootstrap | sh`: review the " +
			"body, then pipe it to sh yourself. The shim's contents are owned and version-controlled " +
			"in eng (bin/provision.sh); PAPI only hosts them. Optional per-domain.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			body, _, err := c.Bootstrap(cmd.Context())
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
	return cmd
}

// sshLineMaterial reduces an SSH public-key line (authorized_keys form, or a bare
// "type base64") to its canonical "type base64" material — comments/annotations
// dropped — so the same key compares equal regardless of how it was framed.
func sshLineMaterial(line string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

// domainKey is one of a domain's published slot-9A keys: its canonical material
// plus a short label (the guid= annotation, else the line) for display.
type domainKey struct {
	material string
	label    string
}

// domainKeyMaterials parses a /papi/ssh-authorized-keys body into domainKeys in
// body order, skipping comments/blanks and unparseable lines.
func domainKeyMaterials(body []byte) []domainKey {
	var out []domainKey
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		mat, err := sshLineMaterial(line)
		if err != nil {
			continue
		}
		label := line
		if m := guidAnnotation.FindStringSubmatch(line); m != nil {
			label = "guid=" + m[1]
		}
		out = append(out, domainKey{material: mat, label: label})
	}
	return out
}

// ghKeysFn is the GitHub-key lister behind a seam, swapped in tests so gh-check's
// reconciliation runs without a real gh.
var ghKeysFn = enroll.ListGitHubKeys

func newGHCheckCmd() *cobra.Command {
	var showOrphans bool
	cmd := &cobra.Command{
		Use:   "gh-check <domain>",
		Short: "Reconcile your GitHub SSH keys against a domain's published slot-9A keys",
		Long: "Cross-check <domain>'s published slot-9A keys — the source of truth — against " +
			"the SSH keys on your authenticated GitHub account (both authentication and " +
			"signing, via `gh api`), matching by key material. The check: every " +
			"domain-published key MUST be registered on GitHub, so a published key MISSING " +
			"from GitHub is a failure (a gap — an enrolled card that can't use GitHub). Extra " +
			"keys on GitHub (not from the domain) are fine and never fail; --show-orphans " +
			"lists them as informational notes. Presented via the crap-TUI; exits non-zero " +
			"only on a gap. Needs gh authenticated with the admin:public_key (auth keys) and " +
			"admin:ssh_signing_key (signing keys) scopes — or the read: variants; a missing " +
			"scope SKIPS that key kind (surfacing gh's `gh auth refresh -s …` hint) rather " +
			"than failing. Grant both at once with `papi gh-auth`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			produce := func(rep *crap.Reporter) error {
				body, _, err := c.SSHAuthorizedKeys(ctx)
				if err != nil {
					return err
				}
				domain := domainKeyMaterials(body)
				domainSet := make(map[string]bool, len(domain))
				for _, d := range domain {
					domainSet[d.material] = true
				}

				type check struct {
					desc   string
					ok     bool
					skip   bool
					reason string         // for a skip
					diag   map[string]any // for a NotOk
				}
				var checks []check

				// Read GitHub's keys: which materials are present, the extras (not
				// from this domain — they're fine), and any kind we couldn't list (a
				// missing OAuth scope → a skip carrying gh's refresh hint).
				type extraKey struct{ kind, title string }
				ghSet := map[string]bool{}
				var extras []extraKey
				complete := true
				for _, set := range ghKeysFn(ctx, enroll.ExecRunner) {
					if set.Err != nil {
						complete = false
						checks = append(checks, check{desc: fmt.Sprintf("GitHub %s keys listed", set.Kind), skip: true, reason: set.Err.Error()})
						continue
					}
					for _, k := range set.Keys {
						mat, merr := sshLineMaterial(k.Key)
						if merr != nil {
							continue
						}
						ghSet[mat] = true
						if !domainSet[mat] {
							extras = append(extras, extraKey{k.Kind, k.Title})
						}
					}
				}

				// The DOMAIN is the source of truth: every published key MUST be on
				// GitHub. A published key missing from GitHub is the failure (a gap).
				// Only conclusive when the GitHub list is COMPLETE: if a kind was
				// skipped, a "gap" might just live in the unlisted kind, so soften it.
				gaps := false
				for _, d := range domain {
					desc := fmt.Sprintf("domain key %s is registered on GitHub", d.label)
					switch {
					case ghSet[d.material]:
						checks = append(checks, check{desc: desc, ok: true})
					case !complete:
						checks = append(checks, check{desc: desc, skip: true, reason: "GitHub key list incomplete (a scope is missing) — can't confirm"})
					default:
						checks = append(checks, check{desc: desc, diag: map[string]any{"reason": "gap — published on the domain but NOT on GitHub"}})
						gaps = true
					}
				}

				// Extra keys on GitHub (not from this domain) are fine — the domain
				// is the source of truth — so they're never failures. Off by default;
				// --show-orphans lists them as informational skips.
				if showOrphans {
					for _, e := range extras {
						checks = append(checks, check{
							desc:   fmt.Sprintf("GitHub %s key %q is not from %s", e.kind, e.title, args[0]),
							skip:   true,
							reason: "extra key on GitHub — fine; the domain is the source of truth",
						})
					}
				}

				ts := rep.TestStream(len(checks))
				for _, ck := range checks {
					switch {
					case ck.skip:
						ts.Skip(ck.desc, ck.reason)
					case ck.ok:
						ts.Ok(ck.desc)
					default:
						ts.NotOk(ck.desc, ck.diag)
					}
				}
				ts.Finish()
				if gaps {
					return errors.New("a domain-published key is not registered on GitHub")
				}
				return nil
			}
			return presentCrapOp(cmd.OutOrStdout(), crap.ReporterOptions{Source: "papi"}, "papi gh-check "+args[0], produce)
		},
	}
	cmd.Flags().BoolVar(&showOrphans, "show-orphans", false, "also list keys on GitHub that aren't published on the domain (extra keys — informational, never a failure)")
	return cmd
}

// githubScopes are the gh OAuth scopes papi's GitHub integration needs: listing
// and adding SSH authentication keys (admin:public_key) and SSH signing keys
// (admin:ssh_signing_key). `papi gh-auth` requests them; `papi enroll` registration
// and `papi gh-check` consume them.
var githubScopes = []string{"admin:public_key", "admin:ssh_signing_key"}

// ghAuthArgs builds the `gh auth refresh` argv that grants githubScopes on host.
func ghAuthArgs(host string) []string {
	args := []string{"auth", "refresh", "-h", host}
	for _, s := range githubScopes {
		args = append(args, "-s", s)
	}
	return args
}

func newGHAuthCmd() *cobra.Command {
	var hostname string
	cmd := &cobra.Command{
		Use:   "gh-auth",
		Short: "Grant gh the GitHub scopes papi needs (admin:public_key + admin:ssh_signing_key)",
		Long: "Launch `gh auth refresh` to add the OAuth scopes papi's GitHub integration uses — " +
			"admin:public_key (SSH authentication keys: `papi enroll` registration and `papi " +
			"gh-check`) and admin:ssh_signing_key (SSH signing keys) — to your existing gh login. " +
			"Interactive: gh runs its browser/device flow on your terminal. Run it once if gh " +
			"reports a missing scope; needs an existing `gh auth login`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return enroll.ExecInteractive(cmd.Context(), "gh", ghAuthArgs(hostname)...)
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "github.com", "GitHub hostname (gh -h)")
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

// newSSHSyncCmd builds `papi ssh-sync <domain>`: fetch a domain's published
// slot-9A keys and (re)write them into a LOCAL dedicated managed file, in full,
// each run. Unlike ssh-copy-id (which appends to a remote authorized_keys and
// never prunes), ssh-sync OWNS its target file — it is rewritten to exactly the
// domain's current key set, so a rotated or revoked card disappears on the next
// run. It powers the papi-ssh-sync home-manager/NixOS service (which runs it on a
// timer) but works standalone. One domain per invocation keeps the file→domain
// mapping (and the service's one-unit-per-instance model) unambiguous.
func newSSHSyncCmd() *cobra.Command {
	var authorizedKeysPath, guid string
	cmd := &cobra.Command{
		Use:   "ssh-sync <domain>",
		Short: "Sync a PAPI domain's slot-9A keys into a local managed authorized_keys file",
		Long: "Fetch ALL of <domain>'s published slot-9A SSH keys (GET /papi/ssh-authorized-keys, " +
			"via the §8.1 discovery-following client) and (re)write them into a LOCAL managed file " +
			"IN FULL — unlike `ssh-copy-id`, which appends to a remote authorized_keys and never " +
			"prunes. The file is rewritten to exactly the domain's current key set on every run, so " +
			"a rotated or revoked card is removed on the next sync; an unchanged upstream leaves the " +
			"file byte-identical (reported as `unchanged`). The default target is " +
			"$XDG_CONFIG_HOME/papi/ssh-sync/<domain>.keys (the host, lowercased, every byte outside " +
			"[a-z0-9.-] — notably the port colon — mapped to _); override with --authorized-keys. The " +
			"parent dir is created 0700 and the file 0600, written atomically (temp + rename) so a " +
			"concurrent sshd read never sees a half-written file. With --guid <HEX>, sync only that " +
			"one card's key. Point sshd's AuthorizedKeysFile at the managed file to honor the keys " +
			"(the papi-ssh-sync NixOS module wires this automatically).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			path := authorizedKeysPath
			if path == "" {
				p, err := defaultSyncPath(domain)
				if err != nil {
					return err
				}
				path = p
			}
			c, err := papi.NewClient(domain)
			if err != nil {
				return err
			}
			body, _, err := c.SSHAuthorizedKeys(cmd.Context())
			if err != nil {
				return err
			}
			keys, err := extractAuthorizedKeysAllowEmpty(body, guid)
			if err != nil {
				return err
			}
			changed, err := writeManagedFile(path, renderManagedFile(keys, buildManagedHeader(domain, guid)))
			if err != nil {
				return err
			}
			state := "unchanged"
			if changed {
				state = "updated"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "synced %d key(s) to %s (%s)\n", len(keys), path, state)
			return nil
		},
	}
	cmd.Flags().StringVar(&authorizedKeysPath, "authorized-keys", "",
		"managed file to (re)write in full (default: $XDG_CONFIG_HOME/papi/ssh-sync/<domain>.keys)")
	cmd.Flags().StringVar(&guid, "guid", "",
		"sync only the slot-9A key whose guid=<HEX> annotation matches (case-insensitive)")
	return cmd
}

// defaultSyncPath is the managed-file path ssh-sync writes when --authorized-keys
// is unset: $XDG_CONFIG_HOME/papi/ssh-sync/<host-slug>.keys. It mirrors the
// home-manager module's default so the CLI and the timer service agree on one
// file.
func defaultSyncPath(domain string) (string, error) {
	slug, err := papiHostSlug(domain)
	if err != nil {
		return "", err
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(cfg, "papi", "ssh-sync", slug+".keys"), nil
}

// papiHostSlug reduces a domain/URL to a filesystem-safe slug of its host[:port]:
// the host (scheme/path stripped via papi.NormalizeBaseHost), lowercased, with
// every byte outside [a-z0-9.-] — notably the port ':' — replaced by '_'. The Nix
// module's hostSlug MUST produce the identical slug, or the CLI default path and
// the service default path diverge for the same domain.
func papiHostSlug(domain string) (string, error) {
	host, err := papi.NormalizeBaseHost(domain)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String(), nil
}

// buildManagedHeader renders the managed-file comment banner. It is deliberately
// TIMESTAMP-FREE: ssh-sync compares the rendered bytes against the file on disk to
// report updated/unchanged, so a varying header would make every run look like a
// change and defeat the idempotency signal.
func buildManagedHeader(domain, guid string) string {
	host, err := papi.NormalizeBaseHost(domain)
	if err != nil {
		host = domain // never fatal for a comment; the fetch already validated the domain
	}
	filter := "none"
	if guid != "" {
		filter = guid
	}
	var b strings.Builder
	b.WriteString("# MANAGED BY papi ssh-sync — DO NOT EDIT.\n")
	b.WriteString("# Rewritten in full on each run; upstream-removed keys are pruned.\n")
	fmt.Fprintf(&b, "# source: GET /papi/ssh-authorized-keys from %s\n", host)
	fmt.Fprintf(&b, "# guid-filter: %s\n", filter)
	return b.String()
}

// renderManagedFile renders the full managed authorized_keys file: the header
// banner, then each validated key line verbatim, one per line, with a trailing
// newline. The output is the COMPLETE file (a full rewrite), so upstream-removed
// keys are pruned simply by not appearing; an empty key set yields header-only.
func renderManagedFile(keys []string, header string) []byte {
	var b bytes.Buffer
	b.WriteString(header)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// writeManagedFile writes content to path idempotently and atomically, reporting
// whether the file changed. If the file already equals content it is a no-op
// (changed=false). Otherwise the parent dir is created 0700 and content is written
// to a temp file (0600) then renamed over path, so a concurrent sshd read never
// observes a partial file.
func writeManagedFile(path string, content []byte) (changed bool, err error) {
	if existing, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(existing, content) {
		return false, nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".papi-ssh-sync-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename has consumed it; cleans up on any error path
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	return true, nil
}

// extractAuthorizedKeys parses a /papi/ssh-authorized-keys body into installable
// authorized_keys lines, kept verbatim (annotations and all). It skips blanks and
// comment lines and — crucially — anything that does not parse as a well-formed
// SSH public key, so a hostile domain cannot smuggle arbitrary text into the
// remote install script (the lines are fed to a shell heredoc). With guid set,
// only the line whose guid=<HEX> annotation matches (case-insensitively) is kept.
func extractAuthorizedKeys(body []byte, guid string) ([]string, error) {
	var keys []string
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
			continue // not a real key (stray text / malformed) — never install it
		}
		if guid != "" {
			m := guidAnnotation.FindStringSubmatch(line)
			if m == nil || !strings.EqualFold(m[1], guid) {
				continue
			}
		}
		keys = append(keys, line)
	}
	if len(keys) == 0 {
		if guid != "" {
			return nil, fmt.Errorf("no ssh-authorized-keys line with guid=%s", guid)
		}
		return nil, errNoInstallableKeys
	}
	return keys, nil
}

// errNoInstallableKeys is the (no --guid) empty-result sentinel from
// extractAuthorizedKeys. ssh-copy-id treats it as fatal (nothing to install);
// ssh-sync treats it as "prune to empty" via extractAuthorizedKeysAllowEmpty.
var errNoInstallableKeys = errors.New("no installable slot-9A keys in /papi/ssh-authorized-keys")

// extractAuthorizedKeysAllowEmpty is extractAuthorizedKeys for the sync path: a
// domain that publishes NO keys yields an empty slice and no error, so ssh-sync
// rewrites its managed file to empty (pruning everything) rather than failing. A
// --guid that matches nothing is still an error — that's a real misconfiguration,
// not an empty upstream — because extractAuthorizedKeys returns a distinct,
// non-sentinel error for it.
func extractAuthorizedKeysAllowEmpty(body []byte, guid string) ([]string, error) {
	keys, err := extractAuthorizedKeys(body, guid)
	if errors.Is(err, errNoInstallableKeys) {
		return nil, nil
	}
	return keys, err
}

// buildSSHInstallScript renders a POSIX-sh script that installs keys into the
// remote ~/.ssh/authorized_keys idempotently: it hardens ~/.ssh (0700) and the
// file (0600), then appends only keys whose "type base64" material is not already
// present, and prints "added=N present=M". The keys ride a quoted heredoc so
// their contents are never shell-expanded; the whole script is fed to a remote
// `sh` on stdin (the heredoc body is read from that same stream).
func buildSSHInstallScript(keys []string) string {
	var b strings.Builder
	b.WriteString(`set -eu
umask 077
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 700 "$HOME/.ssh"
chmod 600 "$HOME/.ssh/authorized_keys"
added=0
present=0
while IFS= read -r line; do
	[ -n "$line" ] || continue
	km=$(printf '%s\n' "$line" | awk '{print $1" "$2}')
	if grep -qF -- "$km" "$HOME/.ssh/authorized_keys"; then
		present=$((present + 1))
	else
		printf '%s\n' "$line" >>"$HOME/.ssh/authorized_keys"
		added=$((added + 1))
	fi
done <<'PAPI_KEYS_EOF'
`)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('\n')
	}
	b.WriteString(`PAPI_KEYS_EOF
printf 'added=%d present=%d\n' "$added" "$present"
`)
	return b.String()
}

// sshRunner runs `ssh <args>` with stdin and returns stdout — the single exec
// seam, swapped in tests so the command's fetch→extract→install wiring runs
// without a real host. Production execs ssh, inheriting the operator's SSH
// config/agent (the same affordance ssh-copy-id(1) relies on).
var sshRunner = func(ctx context.Context, args []string, stdin string) (string, error) {
	c := exec.CommandContext(ctx, "ssh", args...)
	c.Stdin = strings.NewReader(stdin)
	var out, errBuf bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errBuf
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, sshFailureDetail(out.String(), errBuf.String()))
	}
	return out.String(), nil
}

// cmdFailureDetail picks the most useful diagnostic from a failed ssh/sftp run:
// the captured stderr, else stdout, else emptyHint (a non-zero exit with no
// output at all needs the caller's context to be intelligible).
func cmdFailureDetail(stdout, stderr, emptyHint string) string {
	if s := strings.TrimSpace(stderr); s != "" {
		return s
	}
	if s := strings.TrimSpace(stdout); s != "" {
		return s
	}
	return emptyHint
}

// sshFailureDetail is cmdFailureDetail with the no-shell hint: a non-zero exit
// with NO output usually means the destination ran no shell for the install
// script — a forced or restricted command (e.g. an rsync-only target) — which the
// `sh` install path cannot drive (try --sftp).
func sshFailureDetail(stdout, stderr string) string {
	return cmdFailureDetail(stdout, stderr,
		"no output from the destination — it likely runs no shell (forced/restricted command); retry with --sftp")
}

// sshLevelError reports whether err is ssh's OWN failure (exit 255: connection,
// auth, or name resolution) rather than the remote command's non-zero exit. ssh
// reserves 255 for itself and otherwise passes the remote exit code through, so a
// non-255 exit means the host answered but the shell path failed — the only case
// where retrying over SFTP can help (a 255 would fail identically). SSH cannot
// enumerate remote subsystems, so attempting is the only test.
func sshLevelError(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 255
}

var copyIDCount = regexp.MustCompile(`added=(\d+) present=(\d+)`)

// installKeysOverSSH ships keys to target's authorized_keys via sshRunner and
// returns how many were added vs already present.
func installKeysOverSSH(ctx context.Context, target string, keys []string, port int, identity string) (added, present int, err error) {
	args := make([]string, 0, 6)
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if identity != "" {
		args = append(args, "-i", identity)
	}
	args = append(args, target, "sh")
	out, err := sshRunner(ctx, args, buildSSHInstallScript(keys))
	if err != nil {
		return 0, 0, fmt.Errorf("ssh %s: %w", target, err)
	}
	m := copyIDCount.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, fmt.Errorf("unexpected remote output: %q", strings.TrimSpace(out))
	}
	added, _ = strconv.Atoi(m[1])
	present, _ = strconv.Atoi(m[2])
	return added, present, nil
}

// mergeAuthorizedKeys appends newKeys to an existing authorized_keys body,
// skipping any whose key material (type+base64, comments/options ignored) is
// already present, and reports how many were added vs already present. It is the
// shell-free counterpart of buildSSHInstallScript's remote dedup: the merge runs
// locally (the SFTP path), so no remote shell is needed.
func mergeAuthorizedKeys(existing []byte, newKeys []string) (merged []byte, added, present int) {
	have := map[string]bool{}
	for _, line := range strings.Split(string(existing), "\n") {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
			have[string(ssh.MarshalAuthorizedKey(pub))] = true
		}
	}
	var b bytes.Buffer
	b.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		b.WriteByte('\n')
	}
	for _, k := range newKeys {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			continue // already validated upstream; be defensive
		}
		material := string(ssh.MarshalAuthorizedKey(pub))
		if have[material] {
			present++
			continue
		}
		have[material] = true // dedup within newKeys too
		b.WriteString(k)
		b.WriteByte('\n')
		added++
	}
	return b.Bytes(), added, present
}

// sftpRunner runs `sftp <args>` with a batch script on stdin and returns stdout —
// the SFTP exec seam (swapped in tests). Like sshRunner it execs the openssh
// client, so it resolves the same ~/.ssh/config and agent.
var sftpRunner = func(ctx context.Context, args []string, batch string) (string, error) {
	c := exec.CommandContext(ctx, "sftp", args...)
	c.Stdin = strings.NewReader(batch)
	var out, errBuf bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errBuf
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, cmdFailureDetail(out.String(), errBuf.String(),
			"no output from sftp — the destination may not offer the sftp subsystem"))
	}
	return out.String(), nil
}

// sftpArgs builds the `sftp -b - [...] <dest>` argv (batch on stdin). Note sftp's
// port flag is -P (capital), unlike ssh's -p.
func sftpArgs(dest string, port int, identity string) []string {
	args := []string{"-b", "-"}
	if port != 0 {
		args = append(args, "-P", strconv.Itoa(port))
	}
	if identity != "" {
		args = append(args, "-i", identity)
	}
	return append(args, dest)
}

// installKeysOverSFTP installs keys into dest's ~/.ssh/authorized_keys without a
// remote shell: it fetches the current file over SFTP, merges + dedups locally,
// and uploads the result (creating ~/.ssh 0700 / the file 0600). This drives
// shell-less but SFTP-capable hosts (forced-shell/nologin), which the `sh` path
// cannot. Two short sftp batches bracket the local merge.
func installKeysOverSFTP(ctx context.Context, dest string, keys []string, port int, identity string) (added, present int, err error) {
	tmp, err := os.MkdirTemp("", "papi-ssh-copy-id-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(tmp)
	existingPath := filepath.Join(tmp, "existing")
	mergedPath := filepath.Join(tmp, "merged")

	// Fetch: ensure ~/.ssh, then pull the current authorized_keys. The leading `-`
	// makes sftp ignore a missing dir/file (first run) without aborting the batch.
	fetch := "-mkdir .ssh\n-chmod 700 .ssh\n-get .ssh/authorized_keys " + existingPath + "\n"
	if _, err := sftpRunner(ctx, sftpArgs(dest, port, identity), fetch); err != nil {
		return 0, 0, fmt.Errorf("sftp %s (fetch): %w", dest, err)
	}
	existing, _ := os.ReadFile(existingPath) // absent on first run → treated as empty

	merged, added, present := mergeAuthorizedKeys(existing, keys)
	if added == 0 {
		return 0, present, nil // nothing new — skip the upload entirely
	}
	if err := os.WriteFile(mergedPath, merged, 0o600); err != nil {
		return 0, 0, err
	}

	// `-chmod` is best-effort: managed/shared hosts (and chrooted sftp) often deny
	// client setstat, but overwriting an existing authorized_keys preserves its
	// perms and a freshly-created one is 0600 under a sane umask — so a denied
	// chmod must not fail the install once the put has landed.
	push := "put " + mergedPath + " .ssh/authorized_keys\n-chmod 600 .ssh/authorized_keys\n"
	if _, err := sftpRunner(ctx, sftpArgs(dest, port, identity), push); err != nil {
		return 0, 0, fmt.Errorf("sftp %s (push): %w", dest, err)
	}
	return added, present, nil
}

// isTerminal reports whether w is an interactive terminal — the signal for
// rendering the live crap viewport vs. emitting raw ndjson-crap. Mirrors crap's
// presentcli: NO_COLOR forces the plain path, detection is a stdlib stat (no
// isatty dependency), and non-*os.File writers (e.g. test buffers) are not TTYs.
func isTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

// presentCrapOp runs produce against a crap.Reporter and presents the resulting
// ndjson-crap stream (crap RFC-0001): a live viewport when out is a TTY, else the
// raw ndjson-crap on out (pipe to `crap-present`, or capture). This is the shared
// entry point for papi's operation commands. produce's returned error is the
// operation's verdict (the process exit code); the records it emits are the
// presentation.
func presentCrapOp(out io.Writer, opts crap.ReporterOptions, title string, produce func(*crap.Reporter) error) error {
	if !isTerminal(out) {
		rep := crap.NewReporter(out, opts)
		err := produce(rep)
		if err == nil {
			err = rep.Err()
		}
		return err
	}
	// TTY: feed the producer's records through a pipe into the live viewport,
	// which renders to out (the terminal). Keystrokes are never read from the data
	// pipe (the viewport gives its program an empty input reader).
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		rep := crap.NewReporter(pw, opts)
		err := produce(rep)
		if err == nil {
			err = rep.Err()
		}
		_ = pw.Close() // EOF → the viewport quits
		done <- err
	}()
	verr := viewport.Present(pr, viewport.Options{Title: title, Out: out, IsTTY: true})
	if perr := <-done; perr != nil {
		return perr
	}
	return verr
}

// installKeys performs the install (ssh with sftp fallback, or forced sftp),
// wrapping each transport attempt in a crap execution phase under op, and returns
// the aggregate added/present counts. The fallback policy matches the non-crap
// path: a non-ssh-level shell failure retries over SFTP; a 255 (connection/auth)
// does not.
func installKeys(ctx context.Context, op *crap.Operation, dest string, keys []string, port int, identity string, useSFTP bool) (added, present int, err error) {
	if useSFTP {
		return installSFTPPhase(ctx, op, dest, keys, port, identity)
	}
	added, present, err = installKeysOverSSH(ctx, dest, keys, port, identity)
	switch {
	case err == nil:
		ph := op.Phase("install via ssh")
		ph.Command("ssh " + dest + " sh")
		ph.Done()
		return added, present, nil
	case sshLevelError(err):
		// Connection/auth (exit 255) is a real failure — SFTP would fail
		// identically — so it's a failed phase (red ✗).
		ph := op.Phase("install via ssh")
		ph.Command("ssh " + dest + " sh")
		ph.Fail(err)
		return 0, 0, err
	default:
		// A shell-less host is an EXPECTED miss, not a failure: the SFTP fallback
		// is the supported path. Record the ssh attempt as a skip (orange ↷, not a
		// red ✗ that would tally the operation as failed) and fall back.
		op.Skip("install via ssh", "no usable shell on "+dest+" — falling back to SFTP")
		return installSFTPPhase(ctx, op, dest, keys, port, identity)
	}
}

func installSFTPPhase(ctx context.Context, op *crap.Operation, dest string, keys []string, port int, identity string) (int, int, error) {
	ph := op.Phase("install via sftp")
	ph.Command("sftp " + dest)
	added, present, err := installKeysOverSFTP(ctx, dest, keys, port, identity)
	if err != nil {
		ph.Fail(err)
		return 0, 0, err
	}
	ph.Done()
	return added, present, nil
}

func newSSHCopyIDCmd() *cobra.Command {
	var domain, guid, identity string
	var port int
	var useSFTP bool
	cmd := &cobra.Command{
		Use:   "ssh-copy-id <destination>",
		Short: "Install a PAPI domain's enrolled slot-9A keys into an SSH destination's authorized_keys",
		Long: "Fetch ALL of --domain's published slot-9A SSH keys (GET /papi/ssh-authorized-keys, " +
			"via the §8.1 discovery-following client) and install them into <destination>'s " +
			"~/.ssh/authorized_keys — like ssh-copy-id(1), but sourcing the keys from PAPI " +
			"instead of a local file. <destination> is anything ssh accepts: a hostname, an IP, " +
			"a user@host, or — most usefully — a Host alias from your ~/.ssh/config, since the " +
			"install shells to `ssh <destination>` and ssh resolves the config (HostName, User, " +
			"Port, IdentityFile, ProxyJump, …). The append is idempotent (deduped by key material; " +
			"~/.ssh and the file are created 0700/0600 if missing), so re-running keeps a host in " +
			"sync as cards are enrolled or rotated. With --guid <HEX>, install only that one " +
			"card's key. --port / --identity override the resolved config. The default install " +
			"runs a small `sh` script remotely; if the destination has no usable shell (a " +
			"forced/restricted command, e.g. sftp-only/nologin hosts), papi automatically " +
			"retries over the SFTP subsystem — fetching, merging, and re-uploading " +
			"authorized_keys with no remote shell. Pass --sftp to force the SFTP path directly " +
			"(skipping the shell attempt) for a host you already know is shell-less.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(domain)
			if err != nil {
				return err
			}
			dest := args[0]
			ctx := cmd.Context()

			// produce drives the operation AND emits its ndjson-crap presentation:
			// a fetch phase, the install attempt(s) as execution phases (ssh →
			// sftp fallback), and the per-key tally on the operation. The returned
			// error is the verdict (exit code); the SFTP fallback shows up as the
			// failed ssh phase followed by the sftp phase.
			produce := func(rep *crap.Reporter) error {
				op := rep.Operation("ssh-copy-id "+dest, crap.OpOptions{})
				defer op.Finish()

				fp := op.Phase("fetch /papi/ssh-authorized-keys")
				body, _, ferr := c.SSHAuthorizedKeys(ctx)
				if ferr != nil {
					fp.Fail(ferr)
					op.Fail("fetch keys", ferr)
					return ferr
				}
				keys, kerr := extractAuthorizedKeys(body, guid)
				if kerr != nil {
					fp.Fail(kerr)
					op.Fail("fetch keys", kerr)
					return kerr
				}
				fp.Done()

				added, present, ierr := installKeys(ctx, op, dest, keys, port, identity, useSFTP)
				if ierr != nil {
					op.Fail("install", ierr)
					return ierr
				}
				for i := 0; i < added; i++ {
					op.Item("authorized key", 0)
				}
				for i := 0; i < present; i++ {
					op.Skip("authorized key", "already present")
				}
				return nil
			}
			return presentCrapOp(cmd.OutOrStdout(), crap.ReporterOptions{Source: "papi"}, "papi ssh-copy-id "+dest, produce)
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "PAPI domain to source enrolled slot-9A keys from (required)")
	cmd.Flags().StringVar(&guid, "guid", "", "install only the slot-9A key whose guid=<HEX> annotation matches (case-insensitive)")
	cmd.Flags().IntVar(&port, "port", 0, "ssh port (default: ssh's own default)")
	cmd.Flags().StringVar(&identity, "identity", "", "ssh identity file (passed as ssh/sftp -i)")
	cmd.Flags().BoolVar(&useSFTP, "sftp", false, "force the SFTP install path, skipping the shell attempt (papi otherwise tries a shell and falls back to SFTP automatically)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

// verifiedRecipientsFn is the receipt-batch trust gate (FDR-0002), behind a seam
// so the command's file-reading / dedup / --strict wiring is testable without
// real receipt crypto.
var verifiedRecipientsFn = inspect.VerifiedRecipients

func newVerifiedRecipientsCmd() *cobra.Command {
	var domain string
	var strict bool
	cmd := &cobra.Command{
		Use:   "verified-recipients <receipt-file>...",
		Short: "Emit the slot-9D recipients of enrollment receipts that verify against a domain",
		Long: "Verify each papi-enroll-receipt-v1 against --domain (the same self_proof + " +
			"attestation checks as verify-receipt) and print the slot-9D recipient id " +
			"(recipient.id) of every receipt that passes, one per line — the verified " +
			"encryption-recipient set, in the piggy-ids --recipients-only / .pivy-ids form. " +
			"This is the trust gate of the FDR-0002 composition: a card's recipient is " +
			"emitted only when a trusted card has attested its enrollment, so the set can " +
			"drive a PIV-gated encrypt. Failing receipts are reported on stderr and excluded; " +
			"with --strict, ANY failure makes the command emit nothing and exit non-zero.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(domain)
			if err != nil {
				return err
			}
			receipts := make([][]byte, 0, len(args))
			for _, path := range args {
				raw, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("read %s: %w", path, err)
				}
				receipts = append(receipts, raw)
			}
			results := verifiedRecipientsFn(cmd.Context(), c, receipts)

			errOut := cmd.ErrOrStderr()
			seen := map[string]bool{}
			var recipients []string
			var failures int
			for i, r := range results {
				if !r.Verified {
					fmt.Fprintf(errOut, "%s: excluded — %s\n", args[i], r.Reason)
					failures++
					continue
				}
				if !seen[r.RecipientID] {
					seen[r.RecipientID] = true
					recipients = append(recipients, r.RecipientID)
				}
			}
			if strict && failures > 0 {
				return fmt.Errorf("%d receipt(s) failed verification (--strict)", failures)
			}
			if len(recipients) == 0 {
				return fmt.Errorf("no receipts verified — empty recipient set")
			}
			out := cmd.OutOrStdout()
			for _, id := range recipients {
				if _, err := fmt.Fprintln(out, id); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "PAPI domain to verify the receipts against (required)")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero and emit nothing if ANY receipt fails verification")
	_ = cmd.MarkFlagRequired("domain")
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

// authedBody runs the §5 handshake as recipient (recovering the challenge nonce via
// decryptCmd, the card boundary) and returns the scoped response body for GET path
// presented with the minted PiggySession. It is the shared authed-fetch behind the
// projected-endpoint subcommands (person, repos, profiles, …), so each can list the
// full authenticated projection — including §5-gated data — instead of the anonymous
// one. A single call = one handshake = one card decrypt; there is no session reuse
// across invocations, so a consumer should fetch a whole endpoint in one shot.
func authedBody(ctx context.Context, c *papi.Client, recipient, decryptCmd, path string) ([]byte, error) {
	sess, err := inspect.Handshake(ctx, c, inspect.Options{Recipient: recipient, DecryptCmd: decryptCmd})
	if err != nil {
		return nil, err
	}
	resp, err := c.FetchAuthed(ctx, path, sess.ID)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("GET %s (authed): HTTP %d", path, resp.Status)
	}
	return resp.Body, nil
}

// authedPerson runs the §5 handshake as recipient and fetches the scoped /papi so
// the ACL-gated person.contact projects in, returning the authenticated person.
func authedPerson(ctx context.Context, c *papi.Client, recipient, decryptCmd string) (*papi.Person, error) {
	body, err := authedBody(ctx, c, recipient, decryptCmd, "/papi")
	if err != nil {
		return nil, err
	}
	var env struct {
		Data struct {
			Person *papi.Person `json:"person"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
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

// repoView is the projected subset of a repository the `repos` command prints.
type repoView struct {
	Name          string `json:"name,omitempty"`
	URL           string `json:"url,omitempty"`
	Owner         string `json:"owner,omitempty"`
	Forge         string `json:"forge,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Visibility    string `json:"visibility,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

// cloneForge is the slice of a /papi/forges entry needed to synthesize clone urls:
// the forge's clone channel (its published ssh_clone base, or a host derived from
// base_url) and its repos. Other forge fields are ignored here.
type cloneForge struct {
	BaseURL  string `json:"base_url"`
	SSHClone string `json:"ssh_clone"`
	Repos    []struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	} `json:"repos"`
}

// cloneURL synthesizes a git clone url for owner/name on this forge. It prefers the
// forge's published ssh_clone base (kind-agnostic — it honors whatever channel the
// server advertised, e.g. a forgejo behind SSO), and otherwise derives an scp-style
// git@<host> url from base_url (github/gitlab/codeberg …). Returns "" when neither is
// available, so there is nothing to clone from.
func (f cloneForge) cloneURL(owner, name string) string {
	repo := owner + "/" + name
	if f.SSHClone != "" {
		return strings.TrimRight(f.SSHClone, "/") + "/" + repo + ".git"
	}
	if u, err := url.Parse(f.BaseURL); err == nil && u.Host != "" {
		return "git@" + u.Host + ":" + repo + ".git"
	}
	return ""
}

// cloneForges fetches /papi/forges (authenticated when recipient is set) and decodes
// the entries needed for clone-url synthesis. Sourced from /papi/forges because the
// clone channel (ssh_clone) lives at the forge level, not on the flattened
// /papi/repos entry (whose url is the published — often SSO-gated — web url).
func cloneForges(ctx context.Context, c *papi.Client, recipient, decryptCmd string) ([]cloneForge, error) {
	var raw []byte
	if recipient == "" {
		v, _, err := c.Forges(ctx)
		if err != nil {
			return nil, err
		}
		if raw, err = json.Marshal(v); err != nil {
			return nil, err
		}
	} else {
		body, err := authedBody(ctx, c, recipient, decryptCmd, "/papi/forges")
		if err != nil {
			return nil, err
		}
		if raw, _, err = papi.DecodeEnvelope(body); err != nil {
			return nil, err
		}
	}
	var forges []cloneForge
	if err := json.Unmarshal(raw, &forges); err != nil {
		return nil, fmt.Errorf("parse forges for clone urls: %w", err)
	}
	return forges, nil
}

func newReposCmd() *cobra.Command {
	var owner string
	var urlOnly bool
	var recipient, decryptCmd string
	cmd := &cobra.Command{
		Use:   "repos <domain>",
		Short: "List a domain's PAPI repositories (GET /papi/repos)",
		Long: "Fetch <domain>'s repositories and print them. By default emits the flattened, " +
			"provenance-annotated GET /papi/repos list as JSON; --owner filters to a single " +
			"owner. --url instead prints one directly-clonable git url per line: papi joins each " +
			"repo to its forge's clone channel (the forge's published ssh_clone base, else an " +
			"scp-style git@<host> from base_url), so a consumer can `git clone` each line as-is — " +
			"including §5-gated forges whose /papi/repos url is only the SSO-gated web url. " +
			"Anonymously only public forges project; pass --recipient (and --decrypt-cmd) to run " +
			"the §5 handshake and get the full scoped set (e.g. a private forgejo over SSH). " +
			"(--url covers forge-hosted repos; organization-hosted repos, if any, appear only in " +
			"the JSON view.)",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			// --url emits directly-clonable urls, synthesized from the forges' clone
			// channels (the flattened /papi/repos carries only the web url, so the
			// ssh_clone base is joined in from /papi/forges).
			if urlOnly {
				forges, err := cloneForges(cmd.Context(), c, recipient, decryptCmd)
				if err != nil {
					return err
				}
				for _, f := range forges {
					for _, r := range f.Repos {
						if owner != "" && r.Owner != owner {
							continue
						}
						if u := f.cloneURL(r.Owner, r.Name); u != "" {
							if _, err := fmt.Fprintln(out, u); err != nil {
								return err
							}
						}
					}
				}
				return nil
			}

			// JSON: the flattened, provenance-annotated /papi/repos view.
			var repos []papi.Repo
			if recipient == "" {
				repos, _, err = c.Repos(cmd.Context())
			} else {
				var body []byte
				if body, err = authedBody(cmd.Context(), c, recipient, decryptCmd, "/papi/repos"); err == nil {
					repos, err = papi.DecodeRepos(body)
				}
			}
			if err != nil {
				return err
			}
			views := make([]repoView, 0, len(repos))
			for _, r := range repos {
				if owner != "" && r.Owner != owner {
					continue
				}
				views = append(views, repoView{
					Name: r.Name, URL: r.URL, Owner: r.Owner, Forge: r.Forge,
					Kind: r.Kind, Visibility: r.Visibility, DefaultBranch: r.DefaultBranch,
				})
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(views)
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "only list repositories with this owner")
	cmd.Flags().BoolVar(&urlOnly, "url", false, "print one directly-clonable git url per line (synthesized from each forge's clone channel) instead of JSON")
	cmd.Flags().StringVar(&recipient, "recipient", "",
		"piggy recipient id to authenticate as; runs the §5 handshake so §5-gated forges (private/forgejo) are listed")
	cmd.Flags().StringVar(&decryptCmd, "decrypt-cmd", "",
		"shell command that reads the challenge ebox (base64) on stdin and writes the nonce on stdout (the card boundary)")
	return cmd
}

func newForgesCmd() *cobra.Command {
	var recipient, decryptCmd string
	cmd := &cobra.Command{
		Use:   "forges <domain>",
		Short: "List a domain's PAPI forges (GET /papi/forges)",
		Long: "Fetch <domain>'s GET /papi/forges — the forge identities (kind, base_url, " +
			"repos[], and any server-specific fields such as ssh_clone) — and print the projected " +
			"array as JSON, verbatim: unrecognized members are preserved (RFC-0001 §1.1), so a " +
			"clone consumer can read a forge's clone channel and join it with its repos[]. " +
			"Anonymously only public forges project; pass --recipient (and --decrypt-cmd) to run " +
			"the §5 handshake and get the full scoped set — e.g. a private forgejo with its " +
			"ssh_clone base.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			var forges any
			if recipient == "" {
				forges, _, err = c.Forges(cmd.Context())
			} else {
				var body []byte
				if body, err = authedBody(cmd.Context(), c, recipient, decryptCmd, "/papi/forges"); err == nil {
					var data json.RawMessage
					if data, _, err = papi.DecodeEnvelope(body); err == nil {
						err = json.Unmarshal(data, &forges)
					}
				}
			}
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(forges)
		},
	}
	cmd.Flags().StringVar(&recipient, "recipient", "",
		"piggy recipient id to authenticate as; runs the §5 handshake so §5-gated forges (private/forgejo) appear")
	cmd.Flags().StringVar(&decryptCmd, "decrypt-cmd", "",
		"shell command that reads the challenge ebox (base64) on stdin and writes the nonce on stdout (the card boundary)")
	return cmd
}

func newProfilesCmd() *cobra.Command {
	var id string
	var flakerefOnly bool
	cmd := &cobra.Command{
		Use:   "profiles <domain>",
		Short: "List a domain's PAPI host profiles (GET /papi/profiles)",
		Long: "Fetch <domain>'s GET /papi/profiles — the host profiles (flakerefs) a " +
			"staged installer activates — and print them as JSON. --id selects a single " +
			"profile (erroring if none matches); --flakeref prints one flakeref per line. " +
			"Host profiles are commonly §5-gated, so an unauthenticated fetch shows only " +
			"the anonymous-visible set.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			profiles, _, err := c.Profiles(cmd.Context())
			if err != nil {
				return err
			}
			if id != "" {
				filtered := make([]papi.Profile, 0, 1)
				for _, p := range profiles {
					if p.ID == id {
						filtered = append(filtered, p)
					}
				}
				if len(filtered) == 0 {
					return fmt.Errorf("no profile with id %q", id)
				}
				profiles = filtered
			}
			out := cmd.OutOrStdout()
			if flakerefOnly {
				for _, p := range profiles {
					if p.Flakeref != "" {
						if _, err := fmt.Fprintln(out, p.Flakeref); err != nil {
							return err
						}
					}
				}
				return nil
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(profiles)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "select only the profile with this id")
	cmd.Flags().BoolVar(&flakerefOnly, "flakeref", false, "print one flakeref per line instead of JSON")
	return cmd
}

func newQueryCmd() *cobra.Command {
	var raw bool
	cmd := &cobra.Command{
		Use:   "query <domain> <jq-expr>",
		Short: "Run a jq expression over a domain's PAPI document (GET /papi)",
		Long: "Fetch <domain>'s GET /papi document and evaluate the jq expression against " +
			"it — an embedded gojq, no external jq binary — printing each result as JSON. " +
			"--raw/-r prints string results unquoted (like jq -r). Lets consumers pluck " +
			"arbitrary fields (forges[], organizations[], repos[], person, …) without " +
			"bespoke curl+jq.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			query, err := gojq.Parse(args[1])
			if err != nil {
				return fmt.Errorf("parse jq query: %w", err)
			}
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			input, _, err := c.RawDocument(cmd.Context())
			if err != nil {
				return err
			}
			return runQuery(cmd.OutOrStdout(), query, input, raw)
		},
	}
	cmd.Flags().BoolVarP(&raw, "raw", "r", false, "print string results unquoted (like jq -r)")
	return cmd
}

// runQuery evaluates query over input, writing each result to out: a string
// result is printed unquoted under raw, otherwise every result is indented JSON.
// A query runtime error (e.g. from `error`/`halt`) is returned.
func runQuery(out io.Writer, query *gojq.Query, input any, raw bool) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	iter := query.Run(input)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return err
		}
		if s, ok := v.(string); ok && raw {
			if _, err := fmt.Fprintln(out, s); err != nil {
				return err
			}
			continue
		}
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	return nil
}

// labeledSigner wraps an enroll.Signer to announce, on out, which card + role
// each slot-9A signature is for just before the (PIN-prompting) sign — papi's
// tty-side mitigation for the otherwise-ambiguous PIN prompt. The askpass/zenity
// prompt naming the card is a piggy-side fix (it owns the prompt).
type labeledSigner struct {
	inner enroll.Signer
	out   io.Writer
	roles map[string]string // guid → human role label
}

func (l labeledSigner) SignSlot9A(ctx context.Context, guid string, msg []byte) ([]byte, error) {
	role := l.roles[guid]
	if role == "" {
		role = "card " + guid
	}
	fmt.Fprintf(l.out, "→ signing with %s — enter its PIN if prompted\n", role)
	return l.inner.SignSlot9A(ctx, guid, msg)
}

// enrollGUIDFile is the default receipt filename for a new card's GUID.
func enrollGUIDFile(guid string) string {
	g := strings.ToLower(strings.TrimSpace(guid))
	if len(g) > 8 {
		g = g[:8]
	}
	return "enroll-receipt-" + g + ".json"
}

func newEnrollCmd() *cobra.Command {
	var newGUID, newSerial, trustedGUID, pin, out, cnPrefix string
	var allowReprovision, noGHRegister bool
	cmd := &cobra.Command{
		Use:   "enroll <domain>",
		Short: "Provision + enroll a new YubiKey, emitting a signed receipt (FDR-0001)",
		Long: "Provision a new YubiKey and emit a signed papi-enroll-receipt-v1 for " +
			"<domain>'s deploy side to publish, attested by an already-bootstrapped trusted " +
			"card. By default it shows an interactive picker over the attached cards (blank " +
			"cards are selectable; the provisioned trusted card is shown but not enrollable), " +
			"runs `piggy card init` on the chosen blank card, then reads it back and enrolls " +
			"it. Pass --new-guid to enroll an ALREADY-provisioned card (skip the picker + " +
			"provisioning), or --new-serial to pick the blank card non-interactively. With " +
			"--allow-reprovision the picker also offers provisioned cards: choosing one RESETS " +
			"it (destroys its keys) and re-provisions from scratch, behind a loud extra confirm. " +
			"--cn-prefix names the new card's slot certs (else piggy derives piv-auth@<guid8>); " +
			"interactive runs prompt for it. The " +
			"trusted attester is the sole provisioned card, or --trusted-guid. papi drives the " +
			"papi-agnostic piggy primitives (piggy list / age-plugin-piggy to read back, " +
			"piggy sign-bytes to sign): the new card self-signs its 9D↔9A binding and the " +
			"trusted card attests; the receipt is written then verified against <domain>. On " +
			"success it also registers the new card's slot-9A key on your GitHub account as both " +
			"an authentication and a signing key (via gh), unless --no-gh-register. All " +
			"cards must be present (PCSC); provisioning prompts for the PIN on your terminal.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			ctx := cmd.Context()
			run := enroll.ExecRunner

			// Enumerate cards only when we must provision or auto-resolve a GUID.
			var cards []enroll.CardState
			var err error
			if newGUID == "" || trustedGUID == "" {
				if cards, err = enroll.ListCards(ctx, run); err != nil {
					return err
				}
			}
			if newGUID, err = enroll.ResolveNewCard(ctx, enroll.ExecInteractive, run, cards, newGUID, newSerial, domain, allowReprovision, cnPrefix); err != nil {
				return err
			}
			if trustedGUID, err = enroll.ResolveTrustedGUID(cards, trustedGUID); err != nil {
				return err
			}

			newCard, err := enroll.ReadCard(ctx, run, newGUID)
			if err != nil {
				return fmt.Errorf("read new card: %w", err)
			}
			trustedCard, err := enroll.ReadCard(ctx, run, trustedGUID)
			if err != nil {
				return fmt.Errorf("read trusted card: %w", err)
			}

			// Wrap the signer so each PIN-prompting sign is announced with the
			// card + role it's for — the operator otherwise can't tell which card's
			// PIN a prompt wants (the freshly-provisioned new card still has the
			// default PIN, the trusted card has the operator's).
			signer := labeledSigner{
				inner: enroll.PiggySignBytesSigner{PIN: pin},
				out:   cmd.ErrOrStderr(),
				roles: map[string]string{
					newGUID:     fmt.Sprintf("the NEW card %s [%s] (self_proof)", newGUID, newCard.CN),
					trustedGUID: fmt.Sprintf("the TRUSTED card %s [%s] (attestation)", trustedGUID, trustedCard.CN),
				},
			}
			receipt, err := enroll.BuildReceipt(ctx, signer, newCard, domain, trustedGUID, trustedCard.SSHID, time.Now().Unix())
			if err != nil {
				return err
			}

			if out == "" {
				out = enrollGUIDFile(newGUID)
			}
			if err := os.WriteFile(out, receipt, 0o644); err != nil {
				return fmt.Errorf("write receipt: %w", err)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "wrote %s\n", out)

			// The trusted card is already published on <domain>, so the receipt
			// must verify end-to-end now — a fail means the attester isn't trusted
			// there or the signing went wrong.
			c, err := papi.NewClient(domain)
			if err != nil {
				return err
			}
			res, err := inspect.VerifyReceipt(ctx, c, receipt)
			if err != nil {
				return err
			}
			for _, ck := range res.Checks {
				status := "verified"
				if !ck.OK {
					status = "FAILED"
				}
				fmt.Fprintf(w, "%s: %s — %s\n", ck.Name, status, ck.Detail)
			}
			if !res.OK {
				return fmt.Errorf("receipt did not verify against %s", domain)
			}

			// Register the new card's slot-9A key on GitHub (auth + signing) so it
			// can git-over-SSH and sign commits. Best-effort: the receipt is the
			// durable artifact, so a gh failure (not installed / not authed) warns
			// rather than failing the enroll. --no-gh-register skips it (e.g. when
			// enrolling a card for someone else's account).
			if !noGHRegister {
				title := newCard.CN
				if title == "" {
					g := strings.ToLower(newGUID)
					if len(g) > 8 {
						g = g[:8]
					}
					title = "yubikey-" + g
				}
				if err := enroll.RegisterGitHubKey(ctx, run, newCard.SSHLine, title); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: GitHub key registration failed (%v); register manually with `gh ssh-key add`\n", err)
				} else {
					fmt.Fprintf(w, "registered slot-9A key on GitHub (auth + signing) as %q\n", title)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&newGUID, "new-guid", "", "enroll this ALREADY-provisioned card by GUID (skip the picker + provisioning)")
	cmd.Flags().StringVar(&newSerial, "new-serial", "", "provision the blank card with this serial (skip the picker)")
	cmd.Flags().BoolVar(&allowReprovision, "allow-reprovision", false, "permit selecting an ALREADY-provisioned card and resetting it (destroys its keys) before re-provisioning — a loud extra confirm")
	cmd.Flags().BoolVar(&noGHRegister, "no-gh-register", false, "do NOT register the new card's slot-9A key on GitHub (auth + signing); skip when enrolling a card for someone else's account")
	cmd.Flags().StringVar(&cnPrefix, "cn-prefix", "", "name for the new card's slot certs (cn=…, surfaces in piggy list / ssh-authorized-keys); default: piggy's piv-auth@<guid8>. Interactive runs prompt for it")
	cmd.Flags().StringVar(&trustedGUID, "trusted-guid", "", "GUID of the TRUSTED attester card (default: the sole provisioned card)")
	cmd.Flags().StringVar(&pin, "pin", "", "PIV PIN for slot-9A signing (passed to piggy sign-bytes -P; may be required by the card's PIN policy)")
	cmd.Flags().StringVar(&out, "out", "", "receipt output path (default: enroll-receipt-<new-guid8>.json)")
	return cmd
}

func newVerifyReceiptCmd() *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "verify-receipt <receipt-file>",
		Short: "Verify a papi-enroll-receipt-v1 against a domain's published keys (FDR-0001)",
		Long: "Verify a card-enrollment receipt (papi-enroll-receipt-v1) emitted by " +
			"`papi enroll`: its self_proof binds the new card's slot-9D recipient to its " +
			"slot-9A key (a §9.3 papi-proof-sig-v1 over the claim), and its attestation is " +
			"signed by a slot-9A key ALREADY published on --domain's /papi/piggy-ids (a " +
			"papi-enroll-att-v1 over the receipt's canonical bytes) — an already-trusted " +
			"card vouching for the new one. Presents the checks via the crap-TUI (a live " +
			"viewport on a terminal; ndjson-crap when piped — `… | crap-present`) and exits " +
			"non-zero if any check fails; this is the verifier a deploy gate runs before " +
			"publishing a new key.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if domain == "" {
				return fmt.Errorf("--domain is required (the PAPI domain whose published slot-9A keys attest the receipt)")
			}
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			c, err := papi.NewClient(domain)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			produce := func(rep *crap.Reporter) error {
				res, verr := inspect.VerifyReceipt(ctx, c, raw)
				if verr != nil {
					// A hard error (unreadable JSON / wrong schema) before any
					// check — surface it as a single failed test point.
					ts := rep.TestStream(1)
					ts.NotOk("verify-receipt", map[string]any{"error": verr.Error()})
					ts.Finish()
					return verr
				}
				ts := rep.TestStream(len(res.Checks))
				for _, ck := range res.Checks {
					if ck.OK {
						ts.Ok(ck.Name + " — " + ck.Detail)
					} else {
						ts.NotOk(ck.Name, map[string]any{"detail": ck.Detail})
					}
				}
				ts.Finish()
				if !res.OK {
					return errors.New("receipt verification failed")
				}
				return nil
			}
			return presentCrapOp(cmd.OutOrStdout(), crap.ReporterOptions{Source: "papi"},
				"papi verify-receipt "+filepath.Base(args[0]), produce)
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "",
		"the PAPI domain whose published slot-9A keys must attest the receipt (required)")
	return cmd
}

// newSignChallengeCmd is the client half of the RFC-0001 §5.2 sign-challenge
// scheme: it answers a server-issued challenge by signing the domain-separated
// nonce with the caller's slot-9A key (papi#31). The signing primitive is the same
// piggy direct-PCSC byte-signer `papi enroll` uses; this exposes it as a
// challenge-answerer rather than net-new crypto.
// signChallengeSigner builds the slot-9A signer for the sign-challenge commands,
// choosing between the forwarded SSH agent and direct-PCSC `piggy sign-bytes`. mode
// is "auto" (agent when $SSH_AUTH_SOCK is set, else PCSC), "agent", or "pcsc". It
// returns the signer and the guid to sign with: in PCSC mode an empty guid is
// resolved to the sole provisioned card via `piggy list`; in agent mode the guid is
// passed through (the agent selects the slot-9A key, disambiguating by guid only
// when several cards are present) and PCSC is never touched — the path for hosts
// that reach the card over a forwarded agent rather than a local pcscd.
func signChallengeSigner(ctx context.Context, mode, guid, pin, agentSocket string) (signchallenge.Signer, string, error) {
	useAgent := false
	switch mode {
	case "agent":
		useAgent = true
	case "pcsc":
		useAgent = false
	case "", "auto":
		useAgent = agentSocket != "" || os.Getenv("SSH_AUTH_SOCK") != ""
	default:
		return nil, "", fmt.Errorf("--signer must be auto, agent, or pcsc (got %q)", mode)
	}
	if useAgent {
		// agentSocket empty → AgentSignBytesSigner falls back to $SSH_AUTH_SOCK. The
		// socket is dialed lazily at sign time, so this never touches the card at
		// startup — the oracle daemon runs whether or not a card is present.
		return enroll.AgentSignBytesSigner{SocketPath: agentSocket}, guid, nil
	}
	if guid == "" {
		cards, err := enroll.ListCards(ctx, enroll.ExecRunner)
		if err != nil {
			return nil, "", err
		}
		if guid, err = enroll.ResolveTrustedGUID(cards, ""); err != nil {
			return nil, "", err
		}
	}
	return enroll.PiggySignBytesSigner{PIN: pin}, guid, nil
}

func newSignChallengeCmd() *cobra.Command {
	var domain, guid, pin, signerMode string
	cmd := &cobra.Command{
		Use:   "sign-challenge --domain <domain>",
		Short: "Sign a §5.2 auth challenge with slot-9A, emitting the /papi/auth/response body",
		Long: "Read a PAPI sign-challenge — the POST /papi/auth/challenge response JSON " +
			"{challenge_id, nonce, expires_at} — on stdin, build the §5.2 domain-separated " +
			"preimage papi-auth-v1\\n<domain>\\n<nonce>, sign SHA-256(preimage) with the " +
			"caller's PIV slot-9A key (ECDSA P-256, via `piggy sign-bytes --slot 9a` — the " +
			"card must be physically present; no agent), and print the POST " +
			"/papi/auth/response body {challenge_id, signature} on stdout, where signature " +
			"is a papi-auth-sig-v1@ecdsa_p256_sig markl id (raw 64-byte r‖s). --domain is " +
			"the PAPI identity domain the signature binds to; it is never echoed by the " +
			"challenge (cross-site relay defense), so it must be supplied here. With no " +
			"--guid the sole provisioned card is used; --pin passes the slot-9A PIN to " +
			"piggy. The server verifies the signature against the registered slot-9A key " +
			"and mints a session — this command performs no network I/O itself.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if domain == "" {
				return fmt.Errorf("--domain is required (the PAPI identity domain the §5.2 signature binds to)")
			}
			ctx := cmd.Context()
			raw, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read challenge JSON from stdin: %w", err)
			}
			ch, err := signchallenge.ParseChallenge(raw)
			if err != nil {
				return err
			}
			signer, signGUID, err := signChallengeSigner(ctx, signerMode, guid, pin, "")
			if err != nil {
				return err
			}
			resp, err := signchallenge.Sign(ctx, signer, signGUID, domain, ch)
			if err != nil {
				return err
			}
			body, err := json.Marshal(resp)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "",
		"PAPI identity domain the §5.2 signature binds to (required; e.g. staging.linenisgreat.com)")
	cmd.Flags().StringVar(&guid, "guid", "",
		"GUID of the slot-9A card to sign with (default: the sole provisioned card)")
	cmd.Flags().StringVar(&pin, "pin", "",
		"PIV PIN for slot-9A signing (passed to piggy sign-bytes -P; may be required by the card's PIN policy)")
	cmd.Flags().StringVar(&signerMode, "signer", "auto",
		"slot-9A signer: auto ($SSH_AUTH_SOCK agent if set, else piggy sign-bytes), agent, or pcsc")
	return cmd
}

// newSignChallengeServeCmd runs the §5.2 sign-challenge logic as a loopback HTTP
// "signing oracle" so a browser SPA — which holds no card access of its own — can
// obtain a slot-9A signature (papi#36, the gating spike for circus FDR-0013). It is
// the same producing side as `sign-challenge` (signchallenge.Sign +
// enroll.PiggySignBytesSigner), wrapped in an HTTP transport instead of stdin/stdout:
// the browser POSTs the challenge JSON to /sign and gets the {challenge_id,
// signature} response body back. The browser still runs the network handshake
// itself; this serves only the one card-bound step a page cannot do (no PCSC in a
// browser). It is the first production HTTP server in the papi binary, deliberately
// minimal and loopback-only.
func newSignChallengeServeCmd() *cobra.Command {
	var addr, domain, origin, target, guid, pin, signerMode, agentSocket, configPath, logFormat string
	var allowCallbacks []string
	cmd := &cobra.Command{
		Use:   "sign-challenge-serve [--domain <d> --origin <o>] [--allow-callback <url>]",
		Short: "Run a §5.2 card oracle: /sign + /login for a browser SPA, and/or /authorize for FDR-0014 forward-auth",
		Long: "Serve the §5.2 sign-challenge producing side over HTTP so a browser SPA can obtain " +
			"a slot-9A signature it cannot produce itself (no PCSC in a page). Two routes:\n\n" +
			"  /sign  — POST a /papi/auth/challenge response {challenge_id, nonce, expires_at}; " +
			"get back the /papi/auth/response body {challenge_id, signature}. The caller runs the " +
			"network handshake; this signs only (the backend/plugin seam).\n" +
			"  /login — (enabled by --target) POST {auth_key_id}; the oracle runs discovery → " +
			"challenge → sign → response against --target server-side and returns the minted " +
			"session, so a browser with no backend never calls the PAPI server cross-origin.\n\n" +
			"Signing uses the --signer chooser: auto picks the forwarded SSH agent ($SSH_AUTH_SOCK) " +
			"when set, else `piggy sign-bytes --slot 9a` (local PCSC); agent/pcsc force one. " +
			"--domain is the PAPI identity domain the signature binds to (fixed here, never read " +
			"from the request — relay defense). --origin pins CORS. Bind --addr beyond loopback " +
			"(e.g. 0.0.0.0) only on a trusted network: /login is then a card-gated session-minting " +
			"endpoint, gated only by the card's PIN/touch policy. --config loads a TOML file " +
			"(flags override); --log-format sets text|json request logging on stderr.\n\n" +
			"Authorize-only mode: pass only --allow-callback (no --domain/--origin) to serve just " +
			"/authorize — the forward-auth card-login the FDR-0014 verifier drives. /sign and /login " +
			"are not mounted. This is the mode homeManagerModules.papi-oracle runs. Use --agent-socket " +
			"to point the agent signer at a fixed socket (e.g. the ssh-agent-mux socket) so a user " +
			"service need not inherit $SSH_AUTH_SOCK.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var fc signchallenge.FileConfig
			if configPath != "" {
				var err error
				if fc, err = signchallenge.LoadFileConfig(configPath); err != nil {
					return err
				}
			}
			// Precedence: an explicitly-set flag wins, else the config file, else the
			// flag default (which the flag var already holds when unset).
			addr = signchallenge.Resolve(cmd.Flags().Changed("addr"), addr, fc.Addr)
			domain = signchallenge.Resolve(cmd.Flags().Changed("domain"), domain, fc.Domain)
			origin = signchallenge.Resolve(cmd.Flags().Changed("origin"), origin, fc.Origin)
			target = signchallenge.Resolve(cmd.Flags().Changed("target"), target, fc.Target)
			guid = signchallenge.Resolve(cmd.Flags().Changed("guid"), guid, fc.GUID)
			signerMode = signchallenge.Resolve(cmd.Flags().Changed("signer"), signerMode, fc.Signer)
			logFormat = signchallenge.Resolve(cmd.Flags().Changed("log-format"), logFormat, fc.LogFormat)

			if domain == "" && len(allowCallbacks) == 0 {
				return fmt.Errorf("nothing to serve: set --domain (for /sign, plus /login with --target) or --allow-callback (for /authorize)")
			}
			if domain != "" && origin == "" {
				return fmt.Errorf("--origin is required with --domain (the SPA origin CORS is pinned to; e.g. http://localhost:3000)")
			}
			if target != "" && domain == "" {
				return fmt.Errorf("--target requires --domain (the /login broker binds the §5.2 signature to it)")
			}
			logger, err := newServeLogger(logFormat)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			signer, signGUID, err := signChallengeSigner(ctx, signerMode, guid, pin, agentSocket)
			if err != nil {
				return err
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", addr, err)
			}
			routes := "/sign"
			if target != "" {
				routes = "/sign, /login"
			}
			if len(allowCallbacks) > 0 {
				routes += ", /authorize"
			}
			if domain == "" {
				fmt.Fprintf(cmd.OutOrStdout(),
					"papi sign-challenge-serve: authorize-only oracle on http://%s (%s)\n", ln.Addr(), routes)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(),
					"papi sign-challenge-serve: card oracle for %q on http://%s (%s; CORS origin %s; target %q)\n",
					domain, ln.Addr(), routes, origin, target)
			}
			srv := &http.Server{
				Handler: signchallenge.Handler(signchallenge.ServeConfig{
					Signer: signer, GUID: signGUID, Domain: domain, Origin: origin, Target: target, Logger: logger,
					AllowCallbacks: allowCallbacks,
				}),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			return serveHTTP(ctx, srv, ln)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0",
		"loopback address to listen on (default 127.0.0.1:0 → an ephemeral port, printed at startup)")
	cmd.Flags().StringVar(&domain, "domain", "",
		"PAPI identity domain the §5.2 signature binds to (required; e.g. staging.linenisgreat.com)")
	cmd.Flags().StringVar(&origin, "origin", "",
		"SPA origin CORS is pinned to (required; e.g. http://localhost:3000)")
	cmd.Flags().StringVar(&target, "target", "",
		"PAPI base URL the /login broker calls server-side (e.g. https://api.linenisgreat.com); empty serves only /sign")
	cmd.Flags().StringVar(&guid, "guid", "",
		"GUID of the slot-9A card to sign with (default: the sole provisioned card)")
	cmd.Flags().StringVar(&pin, "pin", "",
		"PIV PIN for slot-9A signing (passed to piggy sign-bytes -P; else piggy prompts via askpass)")
	cmd.Flags().StringVar(&signerMode, "signer", "auto",
		"slot-9A signer: auto ($SSH_AUTH_SOCK agent if set, else piggy sign-bytes), agent, or pcsc")
	cmd.Flags().StringVar(&agentSocket, "agent-socket", "",
		"SSH agent socket for the agent signer (default $SSH_AUTH_SOCK); dialed lazily at sign time, so the daemon starts without a card — e.g. ~/.local/state/ssh/mux-agent.sock")
	cmd.Flags().StringVar(&configPath, "config", "",
		"optional TOML config file (addr/domain/origin/target/guid/signer/log_format); explicit flags override it")
	cmd.Flags().StringVar(&logFormat, "log-format", "text",
		"log output format: text or json")
	cmd.Flags().StringSliceVar(&allowCallbacks, "allow-callback", nil,
		"exact verifier callback URL the /authorize card-sign may sign for (repeatable; enables /authorize)")
	return cmd
}

// newServeLogger builds the oracle's slog.Logger from the --log-format value (logs
// to stderr so request logs don't pollute the stdout startup line).
func newServeLogger(format string) (*slog.Logger, error) {
	var h slog.Handler
	switch format {
	case "", "text":
		h = slog.NewTextHandler(os.Stderr, nil)
	case "json":
		h = slog.NewJSONHandler(os.Stderr, nil)
	default:
		return nil, fmt.Errorf("--log-format must be text or json (got %q)", format)
	}
	return slog.New(h), nil
}

// serveHTTP runs srv on ln until ctx is cancelled (SIGINT), then drains in-flight
// requests with a bounded deadline. Shared by the oracle and verifier commands.
func serveHTTP(ctx context.Context, srv *http.Server, ln net.Listener) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// newAuthVerifierCmd runs the FDR-0014 PAPI-session forward-auth verifier: the nginx
// `auth_request` target (/auth/verify) plus the card-login flow (/auth/login →
// /auth/callback) that mints a signed __papi_session cookie. The login is card-direct
// (RFC-0001 §5.2): the oracle card-signs the verifier's nonce, and the verifier
// ECDSA-verifies that signature against the registered slot-9A keys it loads from
// --authorized-keys-file (the papi-ssh-sync fragment). No software signing key exists
// anywhere — only the YubiKey signs, and ANY registered card may authenticate.
func newAuthVerifierCmd() *cobra.Command {
	var addr, cookieKeyFile, authorizedKeysFile, oracleLogin, externalURL, cookieDomain, logFormat string
	var allowPrincipals, allowGroups []string
	var cookieSecure, enableVerifySignature bool
	cmd := &cobra.Command{
		Use:   "auth-verifier --cookie-key-file <f> --authorized-keys-file <f> --oracle-login <url> --external-url <url>",
		Short: "Run the FDR-0014 PAPI-session forward-auth verifier (nginx auth_request)",
		Long: "Serve the forward-auth verifier behind nginx `auth_request` (circus FDR-0014). " +
			"/auth/verify validates the signed __papi_session cookie + the principal/groups " +
			"allowlist → 200 with Remote-User/Remote-Groups (nginx maps Remote-User → " +
			"X-WEBAUTH-USER for Forgejo) or 401. /auth/login → /auth/callback run a card-direct " +
			"login (RFC-0001 §5.2): the oracle card-signs the verifier nonce and the verifier " +
			"ECDSA-verifies it against the registered slot-9A keys in --authorized-keys-file (the " +
			"papi-ssh-sync fragment), then mints the cookie ONCE (validate-at-mint; no per-request " +
			"PAPI call). No software signing key exists — only the card signs, and any registered " +
			"card may authenticate. With --enable-verify-signature it ALSO (or, with no forward-auth " +
			"flags, ONLY) serves POST /auth/verify-signature: the FDR-0013 app-native verify oracle " +
			"— a card §5.2 signature plus the domain and nonce it was signed over in, the verified " +
			"principal out, as stateless JSON — for consumers that mint their own session instead of " +
			"taking the verifier cookie.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Two modes. Forward-auth (the default) serves /auth/verify|login|callback
			// and needs the cookie/oracle/external config. Verify-signature-only
			// (--enable-verify-signature with NO forward-auth flags) serves just
			// /auth/verify-signature and needs only the registry. Setting the flag
			// alongside any forward-auth flag runs both (combined).
			forwardAuth := !enableVerifySignature ||
				cookieKeyFile != "" || oracleLogin != "" || externalURL != ""
			if authorizedKeysFile == "" {
				return fmt.Errorf("--authorized-keys-file is required")
			}
			registry, err := authproxy.LoadRegistry(authorizedKeysFile)
			if err != nil {
				return err
			}
			logger, err := newServeLogger(logFormat)
			if err != nil {
				return err
			}
			cfg := authproxy.VerifierConfig{
				Registry:              registry,
				EnableVerifySignature: enableVerifySignature,
				AllowPrincipals:       authproxy.Set(allowPrincipals),
				AllowGroups:           authproxy.Set(allowGroups),
				Logger:                logger,
			}
			routes := make([]string, 0, 4)
			if forwardAuth {
				for _, req := range []struct{ name, val string }{
					{"cookie-key-file", cookieKeyFile}, {"oracle-login", oracleLogin},
					{"external-url", externalURL},
				} {
					if req.val == "" {
						return fmt.Errorf("--%s is required (forward-auth mode)", req.name)
					}
				}
				cookieKey, err := authproxy.LoadCookieKey(cookieKeyFile)
				if err != nil {
					return err
				}
				cfg.CookieKey = cookieKey
				cfg.OracleLogin = oracleLogin
				cfg.ExternalURL = externalURL
				cfg.CookieSecure = cookieSecure
				cfg.CookieDomain = cookieDomain
				routes = append(routes, "/auth/verify", "/auth/login", "/auth/callback")
			}
			if enableVerifySignature {
				routes = append(routes, "/auth/verify-signature")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", addr, err)
			}
			mode := "forward-auth"
			if !forwardAuth {
				mode = "verify-signature-only"
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"papi auth-verifier [%s]: http://%s (%s; %d registered cards)\n",
				mode, ln.Addr(), strings.Join(routes, ", "), registry.Len())
			srv := &http.Server{
				Handler:           authproxy.VerifierHandler(cfg),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			return serveHTTP(ctx, srv, ln)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0",
		"address to listen on (ephemeral port if :0)")
	cmd.Flags().StringVar(&cookieKeyFile, "cookie-key-file", "",
		"file with the verifier-only HMAC cookie key (>= 32 bytes; required)")
	cmd.Flags().StringVar(&authorizedKeysFile, "authorized-keys-file", "",
		"registered cards: a papi-ssh-sync fragment or a /papi/ssh-authorized-keys body — its ecdsa-sha2-nistp256 (slot-9A auth) lines (required)")
	cmd.Flags().StringVar(&oracleLogin, "oracle-login", "",
		"the oracle's /authorize URL the login flow redirects to (required)")
	cmd.Flags().StringVar(&externalURL, "external-url", "",
		"the verifier's external base URL, scheme://host (required; the §5.2 signature domain)")
	cmd.Flags().StringSliceVar(&allowPrincipals, "allow-principal", nil,
		"allowed principal (repeatable; empty allowlist = any registered card)")
	cmd.Flags().StringSliceVar(&allowGroups, "allow-group", nil,
		"allowed group (repeatable)")
	cmd.Flags().BoolVar(&cookieSecure, "cookie-secure", true,
		"set Secure on the session cookie (requires HTTPS; set false only for plain-HTTP tailnet)")
	cmd.Flags().StringVar(&cookieDomain, "cookie-domain", "",
		"session cookie Domain (default: host-only)")
	cmd.Flags().BoolVar(&enableVerifySignature, "enable-verify-signature", false,
		"also serve POST /auth/verify-signature (FDR-0013 app-native verify oracle: a card §5.2 signature + domain + nonce → the verified principal, stateless JSON). With no forward-auth flags (--cookie-key-file/--oracle-login/--external-url), runs verify-signature-only: registry + --addr only")
	cmd.Flags().StringVar(&logFormat, "log-format", "text",
		"log output format: text or json")
	return cmd
}
