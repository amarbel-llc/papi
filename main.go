// Command papi is the Personal API (PAPI) conformance tool. `validate` discovers,
// introspects, and checks a domain's PAPI against RFC-0001 (emitting an
// ndjson-crap stream; pipe to `crap-present`), running the §5 challenge/response
// handshake when given a --recipient. The `piggy-ids`, `ssh-keys`, and `person`
// subcommands surface a domain's published identity material for downstream
// consumption (e.g. identity bootstrap).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/crap/go-crap/v2/viewport"
	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/enroll"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
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
	root.AddCommand(newVerifiedRecipientsCmd())
	root.AddCommand(newPersonCmd())
	root.AddCommand(newReposCmd())
	root.AddCommand(newQueryCmd())
	root.AddCommand(newEnrollCmd())
	root.AddCommand(newVerifyReceiptCmd())
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

func newValidateCmd() *cobra.Command {
	var opts inspect.Options
	cmd := &cobra.Command{
		Use:   "validate <domain>",
		Short: "Validate a domain's PAPI against RFC-0001, emitting ndjson-crap",
		Long: "Fetch <domain>'s PAPI, report what it publishes, and check it against the " +
			"RFC-0001 conformance contract — discovery, the {data,meta} envelope and " +
			"meta.visibility, acl-strip, projection, the text endpoints, the auth error " +
			"codes, identity-ownership proofs (§9), the document signatures (§10), and the " +
			"nix cache entry schema (§11) — as an ndjson-crap stream (pipe to " +
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
		return nil, fmt.Errorf("no installable slot-9A keys in /papi/ssh-authorized-keys")
	}
	return keys, nil
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

func newReposCmd() *cobra.Command {
	var owner string
	var urlOnly bool
	cmd := &cobra.Command{
		Use:   "repos <domain>",
		Short: "List a domain's PAPI repositories (GET /papi/repos)",
		Long: "Fetch <domain>'s GET /papi/repos — the flattened, provenance-annotated " +
			"repository list — and print it. By default emits the repos as JSON; --url " +
			"prints one repository url per line (a curl+jq replacement for consumers that " +
			"clone them); --owner filters to a single owner.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := papi.NewClient(args[0])
			if err != nil {
				return err
			}
			repos, _, err := c.Repos(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			views := make([]repoView, 0, len(repos))
			for _, r := range repos {
				if owner != "" && r.Owner != owner {
					continue
				}
				if urlOnly {
					if r.URL != "" {
						if _, err := fmt.Fprintln(out, r.URL); err != nil {
							return err
						}
					}
					continue
				}
				views = append(views, repoView{
					Name: r.Name, URL: r.URL, Owner: r.Owner, Forge: r.Forge,
					Kind: r.Kind, Visibility: r.Visibility, DefaultBranch: r.DefaultBranch,
				})
			}
			if urlOnly {
				return nil
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(views)
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "only list repositories with this owner")
	cmd.Flags().BoolVar(&urlOnly, "url", false, "print one repository url per line instead of JSON")
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
	var allowReprovision bool
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
			"trusted card attests; the receipt is written then verified against <domain>. All " +
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
			return nil
		},
	}
	cmd.Flags().StringVar(&newGUID, "new-guid", "", "enroll this ALREADY-provisioned card by GUID (skip the picker + provisioning)")
	cmd.Flags().StringVar(&newSerial, "new-serial", "", "provision the blank card with this serial (skip the picker)")
	cmd.Flags().BoolVar(&allowReprovision, "allow-reprovision", false, "permit selecting an ALREADY-provisioned card and resetting it (destroys its keys) before re-provisioning — a loud extra confirm")
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
