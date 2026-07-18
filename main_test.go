package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amarbel-llc/crap/go-crap/v2/ndjsoncrap"
	"github.com/amarbel-llc/hyphence/go/hyphence"
	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/enroll"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
	"github.com/amarbel-llc/papi/internal/alfa/signchallenge"
	"golang.org/x/crypto/ssh"
)

// genSSHKey returns a fresh ed25519 key in canonical "type base64" form.
func genSSHKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// crapRecords decodes a raw ndjson-crap buffer into its records (the form an
// operation command writes when stdout is not a TTY).
func crapRecords(t *testing.T, s string) []ndjsoncrap.Record {
	t.Helper()
	rd := ndjsoncrap.NewReader(strings.NewReader(s))
	var recs []ndjsoncrap.Record
	for {
		rec, err := rd.Next()
		if err == io.EOF {
			return recs
		}
		if err != nil {
			t.Fatalf("decode ndjson-crap: %v\n%s", err, s)
		}
		recs = append(recs, rec)
	}
}

// crapOpEnd returns the single operation_end record (the operation's verdict).
func crapOpEnd(t *testing.T, recs []ndjsoncrap.Record) ndjsoncrap.OperationEnd {
	t.Helper()
	for _, rec := range recs {
		if oe, ok := rec.(ndjsoncrap.OperationEnd); ok {
			return oe
		}
	}
	t.Fatal("no operation_end record in the crap stream")
	return ndjsoncrap.OperationEnd{}
}

// crapHasFailedNode reports whether any execution phase ended with a non-zero
// exit (e.g. the failed ssh phase before an SFTP fallback).
func crapHasFailedNode(recs []ndjsoncrap.Record) bool {
	for _, rec := range recs {
		if ne, ok := rec.(ndjsoncrap.NodeEnd); ok && ne.ExitCode != nil && *ne.ExitCode != 0 {
			return true
		}
	}
	return false
}

// crapHasFailedTest reports whether the stream carries a failing result-family
// test point (the form verify-receipt emits).
func crapHasFailedTest(recs []ndjsoncrap.Record) bool {
	for _, rec := range recs {
		if tt, ok := rec.(ndjsoncrap.Test); ok && !tt.OK {
			return true
		}
	}
	return false
}

// crapHasSkippedTest reports whether the stream carries a skipped test point.
func crapHasSkippedTest(recs []ndjsoncrap.Record) bool {
	for _, rec := range recs {
		if tt, ok := rec.(ndjsoncrap.Test); ok && tt.Directive != nil && tt.Directive.Kind == "skip" {
			return true
		}
	}
	return false
}

func TestVerifyReceiptCmdCrap(t *testing.T) {
	// A wrong-schema receipt fails before any network fetch, so a stub server is
	// enough to build the client; the crap stream carries a failed test point and
	// the command exits non-zero.
	srv := httptest.NewServer(http.NewServeMux())
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte(`{"schema":"bogus-v9"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newVerifyReceiptCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{path, "--domain", srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatal("a wrong-schema receipt should error")
	}
	if !crapHasFailedTest(crapRecords(t, out.String())) {
		t.Errorf("expected a failed test point in the crap stream:\n%s", out.String())
	}
}

// twoKeyBody is a two-line /papi/ssh-authorized-keys fixture: two slot-9A keys,
// each annotated with guid=<HEX> and cn=<name> (RFC-0001 §4.2). The guids differ
// in case from the flag values the tests pass, to exercise case-insensitivity.
const twoKeyBody = "ssh-ed25519 AAAAaaa laptop guid=DEADBEEF cn=laptop\n" +
	"ssh-ed25519 AAAAbbb phone guid=cafef00d cn=phone\n"

func sshKeysServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, twoKeyBody)
	})
	return httptest.NewServer(mux)
}

// runCmd builds the ssh-keys/person command, points it at args, and captures its
// stdout. cobra writes to the command's OutOrStdout, which SetOut redirects.
func runSSHKeys(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSSHKeysCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestSSHKeysGUIDMatch(t *testing.T) {
	srv := sshKeysServer(t)
	defer srv.Close()

	// Lowercase flag against the uppercase DEADBEEF line — case-insensitive match.
	out, err := runSSHKeys(t, srv.URL, "--guid", "deadbeef")
	if err != nil {
		t.Fatalf("ssh-keys --guid deadbeef: %v", err)
	}
	if !strings.Contains(out, "guid=DEADBEEF") || strings.Contains(out, "cafef00d") {
		t.Errorf("want only the DEADBEEF line, got:\n%s", out)
	}
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n != 0 {
		t.Errorf("want a single line, got %d newlines:\n%s", n, out)
	}
}

func TestSSHKeysGUIDNoMatch(t *testing.T) {
	srv := sshKeysServer(t)
	defer srv.Close()

	out, err := runSSHKeys(t, srv.URL, "--guid", "00000000")
	if err == nil {
		t.Fatalf("ssh-keys --guid 00000000: want error on no match, got output:\n%s", out)
	}
	if !strings.Contains(err.Error(), "00000000") {
		t.Errorf("error should name the missing guid, got: %v", err)
	}
}

func TestSSHKeysVerbatim(t *testing.T) {
	srv := sshKeysServer(t)
	defer srv.Close()

	out, err := runSSHKeys(t, srv.URL)
	if err != nil {
		t.Fatalf("ssh-keys (verbatim): %v", err)
	}
	if out != twoKeyBody {
		t.Errorf("verbatim body mismatch:\ngot:  %q\nwant: %q", out, twoKeyBody)
	}
}

// authorizedKeyLine builds a real, parseable OpenSSH authorized_keys line with a
// guid=<HEX> annotation — extractAuthorizedKeys validates with ParseAuthorizedKey,
// so the twoKeyBody placeholder material won't do here.
func authorizedKeyLine(t *testing.T, guid string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s piggy slot=9A guid=%s cn=test",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), guid)
}

func TestExtractAuthorizedKeys(t *testing.T) {
	k1 := authorizedKeyLine(t, "DEADBEEF")
	k2 := authorizedKeyLine(t, "cafef00d")
	body := "# a comment line\n" + k1 + "\n\n" + k2 + "\nnot a valid key line\n"

	all, err := extractAuthorizedKeys([]byte(body), "")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(all) != 2 || all[0] != k1 || all[1] != k2 {
		t.Fatalf("want [k1 k2] (comment/blank/garbage dropped), got %v", all)
	}

	// guid filter is case-insensitive and selects exactly one.
	one, err := extractAuthorizedKeys([]byte(body), "deadbeef")
	if err != nil {
		t.Fatalf("extract --guid: %v", err)
	}
	if len(one) != 1 || one[0] != k1 {
		t.Fatalf("guid filter want [k1], got %v", one)
	}

	if _, err := extractAuthorizedKeys([]byte(body), "00000000"); err == nil {
		t.Error("a non-matching guid should error")
	}
	if _, err := extractAuthorizedKeys([]byte("# only a comment\njunk text\n"), ""); err == nil {
		t.Error("a body with no valid keys should error")
	}
}

func TestBuildSSHInstallScript(t *testing.T) {
	k1 := authorizedKeyLine(t, "DEADBEEF")
	script := buildSSHInstallScript([]string{k1})
	for _, want := range []string{
		`mkdir -p "$HOME/.ssh"`,
		`chmod 700 "$HOME/.ssh"`,
		`chmod 600 "$HOME/.ssh/authorized_keys"`,
		"<<'PAPI_KEYS_EOF'", // quoted heredoc — no expansion of key contents
		k1,
		`printf 'added=%d present=%d\n'`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q\n--- script ---\n%s", want, script)
		}
	}
}

func TestSSHFailureDetail(t *testing.T) {
	if got := sshFailureDetail("ignored", "permission denied"); got != "permission denied" {
		t.Errorf("stderr should win, got %q", got)
	}
	if got := sshFailureDetail("remote stdout msg", ""); got != "remote stdout msg" {
		t.Errorf("stdout is the fallback, got %q", got)
	}
	// A silent non-zero exit (the rsync-kp case) gets the no-shell hint.
	if got := sshFailureDetail("  ", ""); !strings.Contains(got, "forced/restricted command") {
		t.Errorf("empty streams should hint at a shell-less destination, got %q", got)
	}
}

func TestMergeAuthorizedKeys(t *testing.T) {
	k1 := authorizedKeyLine(t, "DEADBEEF")
	k2 := authorizedKeyLine(t, "CAFEF00D")
	// existing already carries k1's key material under a different comment.
	f := strings.Fields(k1)
	existing := []byte(f[0] + " " + f[1] + " some-other-comment\n")

	merged, added, present := mergeAuthorizedKeys(existing, []string{k1, k2, k2})
	if added != 1 || present != 2 {
		t.Fatalf("added=%d present=%d, want added=1 (k2 once) present=2 (k1 + dup k2)", added, present)
	}
	if !strings.Contains(string(merged), strings.Fields(k2)[1]) {
		t.Errorf("merged should contain k2's key material")
	}
	if !strings.Contains(string(merged), "some-other-comment") {
		t.Errorf("merged should preserve the pre-existing line")
	}
}

// sftpLocalArg pulls the local path token a batch line passes after prefix (e.g.
// the get target or the put source).
func sftpLocalArg(batch, prefix string) string {
	i := strings.Index(batch, prefix)
	if i < 0 {
		return ""
	}
	rest := batch[i+len(prefix):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func TestInstallKeysOverSFTP(t *testing.T) {
	k1 := authorizedKeyLine(t, "DEADBEEF")
	k2 := authorizedKeyLine(t, "CAFEF00D")

	var uploaded string
	var pushChmod bool
	orig := sftpRunner
	sftpRunner = func(_ context.Context, _ []string, batch string) (string, error) {
		switch {
		case strings.Contains(batch, "-get"): // fetch: pretend the host already has k1
			if err := os.WriteFile(sftpLocalArg(batch, "-get .ssh/authorized_keys "), []byte(k1+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		case strings.Contains(batch, "put "): // push: capture what we upload
			b, err := os.ReadFile(sftpLocalArg(batch, "put "))
			if err != nil {
				t.Fatal(err)
			}
			uploaded = string(b)
			pushChmod = strings.Contains(batch, "-chmod 600") // best-effort: must not fail the install
		}
		return "", nil
	}
	defer func() { sftpRunner = orig }()

	added, present, err := installKeysOverSFTP(context.Background(), "sftp-host", []string{k1, k2}, 0, "")
	if err != nil {
		t.Fatalf("installKeysOverSFTP: %v", err)
	}
	if added != 1 || present != 1 {
		t.Fatalf("added=%d present=%d, want added=1 (k2) present=1 (k1 already there)", added, present)
	}
	if !pushChmod {
		t.Error("push batch should chmod 600 authorized_keys")
	}
	if !strings.Contains(uploaded, strings.Fields(k1)[1]) || !strings.Contains(uploaded, strings.Fields(k2)[1]) {
		t.Errorf("uploaded authorized_keys must carry both the existing and the new key:\n%s", uploaded)
	}
}

func TestSSHLevelError(t *testing.T) {
	exitErr := func(code int) error {
		return exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	}
	if !sshLevelError(exitErr(255)) {
		t.Error("exit 255 is an ssh-level (connection/auth) error")
	}
	if sshLevelError(exitErr(1)) {
		t.Error("exit 1 is a remote-command failure, not ssh-level — should be eligible for SFTP fallback")
	}
	if sshLevelError(errors.New("not an exit error")) {
		t.Error("a non-exit error is not ssh-level")
	}
}

// sshCopyIDRun executes a fresh ssh-copy-id command (silencing cobra usage, as
// the root would in production) and returns stdout, stderr, and the error.
func sshCopyIDRun(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newSSHCopyIDCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background()) // run BEFORE reading the buffers
	return out.String(), errOut.String(), err
}

func TestSSHCopyIDFallsBackToSFTP(t *testing.T) {
	srv := sshCopyIDServer(t)
	defer srv.Close()

	origSSH, origSFTP := sshRunner, sftpRunner
	// Shell path fails non-255 (host answered, no usable shell) → fall back.
	sshRunner = func(context.Context, []string, string) (string, error) {
		return "", exec.Command("sh", "-c", "exit 1").Run()
	}
	var sftpCalled bool
	sftpRunner = func(context.Context, []string, string) (string, error) {
		sftpCalled = true
		return "", nil // empty fetch (no existing file) + accepted push
	}
	defer func() { sshRunner, sftpRunner = origSSH, origSFTP }()

	out, _, err := sshCopyIDRun(t, "host", "--domain", srv.URL)
	if err != nil {
		t.Fatalf("should fall back to SFTP and succeed: %v", err)
	}
	if !sftpCalled {
		t.Error("expected automatic SFTP fallback after the shell path failed")
	}
	// A shell-less host that falls back to SFTP is a SUCCESS: the ssh attempt is a
	// skip (orange), NOT a failed node, so the operation ends OK with both keys
	// installed.
	recs := crapRecords(t, out)
	oe := crapOpEnd(t, recs)
	if !oe.OK || oe.Done != 2 {
		t.Errorf("operation_end = %+v, want OK done=2 (both keys via SFTP)", oe)
	}
	if oe.Skipped < 1 {
		t.Errorf("operation_end = %+v, want the ssh attempt counted as a skip", oe)
	}
	if crapHasFailedNode(recs) {
		t.Error("a fallback ssh attempt must be a skip, not a failed NodeEnd")
	}
}

func TestSSHCopyIDNoFallbackOnSSHLevelError(t *testing.T) {
	srv := sshCopyIDServer(t)
	defer srv.Close()

	origSSH, origSFTP := sshRunner, sftpRunner
	sshRunner = func(context.Context, []string, string) (string, error) {
		return "", exec.Command("sh", "-c", "exit 255").Run() // connection/auth failure
	}
	var sftpCalled bool
	sftpRunner = func(context.Context, []string, string) (string, error) {
		sftpCalled = true
		return "", nil
	}
	defer func() { sshRunner, sftpRunner = origSSH, origSFTP }()

	out, _, err := sshCopyIDRun(t, "host", "--domain", srv.URL)
	if err == nil {
		t.Fatal("an ssh-level (255) failure should surface, not fall back")
	}
	if sftpCalled {
		t.Error("must NOT fall back to SFTP on an ssh-level (255) failure — it would fail identically")
	}
	if oe := crapOpEnd(t, crapRecords(t, out)); oe.OK {
		t.Error("operation_end should be OK=false when the install fails")
	}
}

// sshCopyIDServer serves a two-key /papi/ssh-authorized-keys body of REAL keys
// (extractAuthorizedKeys parse-validates, unlike the ssh-keys path).
func sshCopyIDServer(t *testing.T) *httptest.Server {
	t.Helper()
	body := authorizedKeyLine(t, "DEADBEEF") + "\n" + authorizedKeyLine(t, "cafef00d") + "\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, body)
	})
	return httptest.NewServer(mux)
}

func TestSSHCopyIDInstallsKeys(t *testing.T) {
	srv := sshCopyIDServer(t)
	defer srv.Close()

	var gotArgs []string
	var gotScript string
	orig := sshRunner
	sshRunner = func(_ context.Context, args []string, stdin string) (string, error) {
		gotArgs, gotScript = args, stdin
		return "added=2 present=0\n", nil
	}
	defer func() { sshRunner = orig }()

	out, _, err := sshCopyIDRun(t, "deploy@host.example", "--domain", srv.URL, "--port", "2222")
	if err != nil {
		t.Fatalf("ssh-copy-id: %v", err)
	}

	if oe := crapOpEnd(t, crapRecords(t, out)); !oe.OK || oe.Done != 2 || oe.Skipped != 0 {
		t.Errorf("operation_end = %+v, want OK done=2 skipped=0", oe)
	}
	if got := strings.Join(gotArgs, " "); got != "-p 2222 deploy@host.example sh" {
		t.Errorf("ssh args = %q, want %q", got, "-p 2222 deploy@host.example sh")
	}
	if !strings.Contains(gotScript, "PAPI_KEYS_EOF") || !strings.Contains(gotScript, "guid=DEADBEEF") {
		t.Errorf("install script not piped to ssh:\n%s", gotScript)
	}
}

func TestRenderManagedFile(t *testing.T) {
	hdr := "# header line\n"
	k1 := authorizedKeyLine(t, "DEADBEEF")
	k2 := authorizedKeyLine(t, "CAFEF00D")
	if got, want := string(renderManagedFile([]string{k1, k2}, hdr)), hdr+k1+"\n"+k2+"\n"; got != want {
		t.Errorf("render mismatch:\ngot:  %q\nwant: %q", got, want)
	}
	// empty key set → header only (a domain that publishes nothing prunes to empty)
	if got := string(renderManagedFile(nil, hdr)); got != hdr {
		t.Errorf("empty render = %q, want header only %q", got, hdr)
	}
}

func TestPapiHostSlug(t *testing.T) {
	// The bare form and every URL form of the same domain must produce the SAME
	// slug, or the CLI default path diverges from the module default.
	cases := map[string]string{
		"example.com":              "example.com",
		"https://example.com":      "example.com",
		"https://example.com/foo":  "example.com",
		"Example.COM":              "example.com",
		"https://example.com:8443": "example.com_8443",
	}
	for in, want := range cases {
		got, err := papiHostSlug(in)
		if err != nil {
			t.Fatalf("papiHostSlug(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("papiHostSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteManagedFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "papi.keys") // sub must be created 0700
	c1 := []byte("# h\nkeyA\n")

	changed, err := writeManagedFile(path, c1)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v, want changed=true", changed, err)
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
	}
	if di, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}

	// identical content → no-op
	if changed, err := writeManagedFile(path, c1); err != nil || changed {
		t.Errorf("rewrite identical: changed=%v err=%v, want changed=false", changed, err)
	}

	// changed content → rewrite, old content pruned
	c2 := []byte("# h\nkeyB\n")
	if changed, err := writeManagedFile(path, c2); err != nil || !changed {
		t.Errorf("rewrite changed: changed=%v err=%v, want changed=true", changed, err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(c2) || strings.Contains(string(got), "keyA") {
		t.Errorf("after rewrite = %q, want %q (keyA pruned)", got, c2)
	}

	// no temp files left behind on any path
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".papi-ssh-sync-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// mutableKeysServer serves *body as /papi/ssh-authorized-keys, letting a test
// change the published key set between runs to exercise prune-on-rewrite.
func mutableKeysServer(t *testing.T, body *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, *body)
	})
	return httptest.NewServer(mux)
}

// syncRun executes a fresh ssh-sync command and returns stdout + error.
func syncRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSSHSyncCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestSSHSyncCmd(t *testing.T) {
	k1 := authorizedKeyLine(t, "DEADBEEF")
	k2 := authorizedKeyLine(t, "CAFEF00D")
	body := k1 + "\n" + k2 + "\n"
	srv := mutableKeysServer(t, &body)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "papi.keys")

	// first sync: both keys land under the managed header, reported updated.
	out, err := syncRun(t, srv.URL, "--authorized-keys", path)
	if err != nil {
		t.Fatalf("ssh-sync: %v", err)
	}
	if !strings.Contains(out, "synced 2 key(s)") || !strings.Contains(out, "(updated)") {
		t.Errorf("report = %q, want `synced 2 key(s) … (updated)`", out)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "MANAGED BY papi ssh-sync") {
		t.Errorf("missing managed header:\n%s", got)
	}
	if !strings.Contains(string(got), strings.Fields(k1)[1]) || !strings.Contains(string(got), strings.Fields(k2)[1]) {
		t.Errorf("file should carry both keys:\n%s", got)
	}

	// re-sync with unchanged upstream: byte-identical, reported unchanged.
	if out, err := syncRun(t, srv.URL, "--authorized-keys", path); err != nil || !strings.Contains(out, "(unchanged)") {
		t.Errorf("re-sync = %q err=%v, want (unchanged)", out, err)
	}

	// upstream drops k1 (card rotation): the full rewrite prunes it.
	body = k2 + "\n"
	out, err = syncRun(t, srv.URL, "--authorized-keys", path)
	if err != nil {
		t.Fatalf("ssh-sync after rotation: %v", err)
	}
	if !strings.Contains(out, "(updated)") {
		t.Errorf("rotation should report updated, got %q", out)
	}
	got, _ = os.ReadFile(path)
	if strings.Contains(string(got), strings.Fields(k1)[1]) {
		t.Errorf("k1 should be pruned after upstream removal:\n%s", got)
	}
	if !strings.Contains(string(got), strings.Fields(k2)[1]) {
		t.Errorf("k2 should remain:\n%s", got)
	}

	// --guid selects exactly one key.
	body = k1 + "\n" + k2 + "\n"
	if _, err := syncRun(t, srv.URL, "--authorized-keys", path, "--guid", "deadbeef"); err != nil {
		t.Fatalf("ssh-sync --guid: %v", err)
	}
	got, _ = os.ReadFile(path)
	if !strings.Contains(string(got), strings.Fields(k1)[1]) || strings.Contains(string(got), strings.Fields(k2)[1]) {
		t.Errorf("--guid deadbeef should keep only k1:\n%s", got)
	}
}

func TestSSHSyncEmptyUpstream(t *testing.T) {
	body := "# no keys published yet\n"
	srv := mutableKeysServer(t, &body)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "papi.keys")

	out, err := syncRun(t, srv.URL, "--authorized-keys", path)
	if err != nil {
		t.Fatalf("ssh-sync empty upstream should not error: %v", err)
	}
	if !strings.Contains(out, "synced 0 key(s)") {
		t.Errorf("report = %q, want `synced 0 key(s)`", out)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "MANAGED BY papi ssh-sync") {
		t.Errorf("empty sync should still write the managed header:\n%s", got)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(got)), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Errorf("empty sync wrote a non-comment line: %q", line)
		}
	}
}

// TestVerifiedRecipientsCmd exercises the command's file-reading, dedup, stderr
// reporting, and --strict wiring through the verifiedRecipientsFn seam (the real
// receipt crypto is covered by inspect.TestVerifiedRecipients).
func TestVerifiedRecipientsCmd(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 3)
	for i := range paths {
		p := filepath.Join(dir, fmt.Sprintf("r%d.json", i))
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[i] = p
	}

	orig := verifiedRecipientsFn
	// r0 + r1 verify to the SAME recipient (dedup); r2 fails.
	verifiedRecipientsFn = func(_ context.Context, _ *papi.Client, receipts [][]byte) []inspect.RecipientResult {
		return []inspect.RecipientResult{
			{RecipientID: "piggy-recipient-v1@dup", Verified: true},
			{RecipientID: "piggy-recipient-v1@dup", Verified: true},
			{Reason: "attestation: not published"},
		}
	}
	defer func() { verifiedRecipientsFn = orig }()

	run := func(extra ...string) (string, string, error) {
		cmd := newVerifiedRecipientsCmd()
		cmd.SilenceUsage = true // root sets this in production; the test runs the child standalone
		cmd.SilenceErrors = true
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append([]string{"--domain", "example.com"}, append(append([]string{}, paths...), extra...)...))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), errOut.String(), err
	}

	out, errOut, err := run()
	if err != nil {
		t.Fatalf("verified-recipients: %v", err)
	}
	if strings.TrimSpace(out) != "piggy-recipient-v1@dup" {
		t.Errorf("stdout should be the deduped recipient once, got %q", out)
	}
	if !strings.Contains(errOut, "excluded — attestation: not published") {
		t.Errorf("stderr should report the excluded receipt, got %q", errOut)
	}

	out, _, err = run("--strict")
	if err == nil {
		t.Error("--strict should error when a receipt fails")
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("--strict should emit nothing, got %q", out)
	}
}

func TestBootstrapCmd(t *testing.T) {
	const shim = "#!/bin/sh\nset -eu\n# eng bin/provision.sh (self-contained): clone eng, then stage host\ngit clone https://github.com/amarbel-llc/eng \"$HOME/eng\"\nexec \"$HOME/eng/bin/provision.sh\"\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, shim)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := newBootstrapCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if out.String() != shim {
		t.Errorf("bootstrap shim not printed verbatim:\ngot:  %q\nwant: %q", out.String(), shim)
	}
}

// ghDomainServer serves the given key lines (each a "type base64") as a domain's
// /papi/ssh-authorized-keys, annotated with distinct slot-9A guids.
func ghDomainServer(t *testing.T, keys ...string) *httptest.Server {
	t.Helper()
	var b strings.Builder
	for i, k := range keys {
		fmt.Fprintf(&b, "%s piggy slot=9A guid=%08X\n", k, 0xA0000000+i)
	}
	body := b.String()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, body)
	})
	return httptest.NewServer(mux)
}

func runGHCheck(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newGHCheckCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestGHCheckGap: a domain-published key MISSING from GitHub is the failure (the
// domain is the source of truth).
func TestGHCheckGap(t *testing.T) {
	k1 := genSSHKey(t) // on the domain AND GitHub
	k3 := genSSHKey(t) // on the domain, NOT GitHub → gap
	srv := ghDomainServer(t, k1, k3)
	defer srv.Close()

	orig := ghKeysFn
	ghKeysFn = func(context.Context, enroll.Runner) []enroll.GitHubKeySet {
		return []enroll.GitHubKeySet{
			{Kind: "authentication", Keys: []enroll.GitHubKey{{Title: "card", Kind: "authentication", Key: k1}}},
			{Kind: "signing"},
		}
	}
	defer func() { ghKeysFn = orig }()

	out, err := runGHCheck(t, srv.URL)
	if err == nil {
		t.Fatal("a domain key missing from GitHub (gap) should make gh-check exit non-zero")
	}
	if !crapHasFailedTest(crapRecords(t, out)) {
		t.Errorf("expected the gap as a failed test:\n%s", out)
	}
}

// TestGHCheckExtraKeys: an extra key on GitHub (not from the domain) is fine —
// never a failure, hidden by default, listed as a skip with --show-orphans.
func TestGHCheckExtraKeys(t *testing.T) {
	k1 := genSSHKey(t) // on the domain AND GitHub
	k2 := genSSHKey(t) // extra on GitHub only
	srv := ghDomainServer(t, k1)
	defer srv.Close()

	orig := ghKeysFn
	ghKeysFn = func(context.Context, enroll.Runner) []enroll.GitHubKeySet {
		return []enroll.GitHubKeySet{
			{Kind: "authentication", Keys: []enroll.GitHubKey{
				{Title: "card", Kind: "authentication", Key: k1},
				{Title: "extra", Kind: "authentication", Key: k2},
			}},
			{Kind: "signing"},
		}
	}
	defer func() { ghKeysFn = orig }()

	// default: extra keys don't fail and aren't shown
	out, err := runGHCheck(t, srv.URL)
	if err != nil {
		t.Fatalf("an extra GitHub key must not fail gh-check: %v", err)
	}
	recs := crapRecords(t, out)
	if crapHasFailedTest(recs) {
		t.Errorf("an extra GitHub key must not be a failure:\n%s", out)
	}
	if crapHasSkippedTest(recs) {
		t.Errorf("extra keys must be hidden without --show-orphans:\n%s", out)
	}

	// --show-orphans: the extra key is listed as an informational skip, still exit 0
	out, err = runGHCheck(t, srv.URL, "--show-orphans")
	if err != nil {
		t.Fatalf("--show-orphans must not fail on extras: %v", err)
	}
	if !crapHasSkippedTest(crapRecords(t, out)) {
		t.Errorf("--show-orphans should list the extra key as a skip:\n%s", out)
	}
}

func TestGHCheckCmdMissingScope(t *testing.T) {
	k1 := genSSHKey(t) // on the domain and on GitHub (auth)

	mux := http.NewServeMux()
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, k1+" piggy slot=9A guid=AAAA\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	orig := ghKeysFn
	// The signing kind can't be listed (missing scope) — captured as a per-kind
	// error, which must SKIP rather than fail the whole check.
	ghKeysFn = func(context.Context, enroll.Runner) []enroll.GitHubKeySet {
		return []enroll.GitHubKeySet{
			{Kind: "authentication", Keys: []enroll.GitHubKey{{Title: "card", Kind: "authentication", Key: k1}}},
			{Kind: "signing", Err: errors.New("gh api user/ssh_signing_keys: needs admin:ssh_signing_key")},
		}
	}
	defer func() { ghKeysFn = orig }()

	cmd := newGHCheckCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("a missing scope should skip, not fail the command: %v", err)
	}
	recs := crapRecords(t, out.String())
	if crapHasFailedTest(recs) {
		t.Errorf("missing scope must not produce a failed test:\n%s", out.String())
	}
	if !crapHasSkippedTest(recs) {
		t.Errorf("missing scope should produce a skipped test:\n%s", out.String())
	}
}

func TestGHAuthArgs(t *testing.T) {
	got := strings.Join(ghAuthArgs("github.com"), " ")
	want := "auth refresh -h github.com -s admin:public_key -s admin:ssh_signing_key"
	if got != want {
		t.Errorf("ghAuthArgs = %q, want %q", got, want)
	}
}

// personDocServer serves a /papi whose person block carries display_name and a
// nested contact.email — the scoped projection's shape (RFC-0001 §6). The
// anonymous `person` path decodes the same struct, so this exercises the new
// Person.DisplayName + Person.Contact.Email fields end to end through the command.
func personDocServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"tester",`+
			`"display_name":"Test Er","contact":{"email":"test@example.com"}}},`+
			`"meta":{"type":"papi","version":"papi/v0","visibility":"scoped"}}`)
	})
	return httptest.NewServer(mux)
}

func TestPersonDecode(t *testing.T) {
	srv := personDocServer(t)
	defer srv.Close()

	cmd := newPersonCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("person: %v", err)
	}

	var v personView
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("person output is not JSON: %v\n%s", err, out.String())
	}
	if v.Handle != "tester" {
		t.Errorf("handle = %q, want tester", v.Handle)
	}
	if v.DisplayName != "Test Er" {
		t.Errorf("display_name = %q, want %q", v.DisplayName, "Test Er")
	}
	if v.Email != "test@example.com" {
		t.Errorf("email = %q, want test@example.com", v.Email)
	}
}

// TestPersonDisplayNameFallback confirms `name` fills display_name when
// display_name is absent, and a stripped contact (anonymous projection) yields no
// email — the bootstrap consumer treats a missing email as non-fatal.
func TestPersonDisplayNameFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"anon","name":"Legacy Name"}},`+
			`"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := newPersonCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("person: %v", err)
	}

	var v personView
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("person output is not JSON: %v\n%s", err, out.String())
	}
	if v.DisplayName != "Legacy Name" {
		t.Errorf("display_name fallback = %q, want %q", v.DisplayName, "Legacy Name")
	}
	if v.Email != "" {
		t.Errorf("anonymous projection should reveal no email, got %q", v.Email)
	}
}

// reposServer serves a /papi/repos flattened list spanning two owners/forges, plus
// the matching /papi/forges (which --url synthesizes clone urls from).
func reposServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[`+
			`{"name":"papi","url":"https://github.com/amarbel-llc/papi","owner":"amarbel-llc","forge":"github","kind":"github","visibility":"public","default_branch":"master"},`+
			`{"name":"eng","url":"https://github.com/amarbel-llc/eng","owner":"amarbel-llc","forge":"github","kind":"github","visibility":"public","default_branch":"master"},`+
			`{"name":"dotfiles","url":"https://codeberg.org/someone/dotfiles","owner":"someone","forge":"codeberg","kind":"codeberg","visibility":"public","default_branch":"main"}`+
			`],"meta":{"type":"repos","visibility":"public","count":3}}`)
	})
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Real /papi/forges shape (amarbel-llc/papi#47): the owner is the forge's
		// single `identity`, and repos[] carry NO per-repo owner.
		io.WriteString(w, `{"data":[`+
			`{"kind":"github","base_url":"https://github.com","identity":"amarbel-llc","repos":[{"name":"papi"},{"name":"eng"}]},`+
			`{"kind":"codeberg","base_url":"https://codeberg.org","identity":"someone","repos":[{"name":"dotfiles"}]}`+
			`],"meta":{"type":"forges","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

func runRepos(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newReposCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestReposJSON(t *testing.T) {
	srv := reposServer(t)
	defer srv.Close()
	out, err := runRepos(t, srv.URL)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	var views []repoView
	if err := json.Unmarshal([]byte(out), &views); err != nil {
		t.Fatalf("repos output not JSON: %v\n%s", err, out)
	}
	if len(views) != 3 {
		t.Fatalf("want 3 repos, got %d", len(views))
	}
	if views[0].Name != "papi" || views[0].Owner != "amarbel-llc" || views[0].URL == "" {
		t.Errorf("repo[0] = %+v", views[0])
	}
}

func TestReposURLOwnerFilter(t *testing.T) {
	srv := reposServer(t)
	defer srv.Close()
	out, err := runRepos(t, srv.URL, "--owner", "amarbel-llc", "--url")
	if err != nil {
		t.Fatalf("repos --owner --url: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 urls, got %d: %q", len(lines), out)
	}
	// --url synthesizes an scp-style clone url from the github forge's base_url.
	for _, l := range lines {
		if !strings.HasPrefix(l, "git@github.com:amarbel-llc/") || !strings.HasSuffix(l, ".git") {
			t.Errorf("want a git@github.com:amarbel-llc/<name>.git clone url, got %q", l)
		}
	}
	if strings.Contains(out, "codeberg") || strings.Contains(out, "someone") {
		t.Errorf("--owner filter leaked another owner:\n%s", out)
	}
}

// registerHandshake wires the §5 challenge/response onto mux: the challenge mints
// base64(nonce) (a `base64 -d` decrypt-cmd recovers it), the response validates it
// once and mints session "sess1". Projected endpoints then gate their scoped set on
// the `Authorization: PiggySession sess1` header. Mirrors internal/alfa/inspect's
// mock-box fixture.
func registerHandshake(mux *http.ServeMux, nonce string) {
	consumed := false
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"challenge_id":"ch1","ebox_b64":%q,"expires_at":9999999999},"meta":{"type":"papi-auth-challenge"}}`,
			base64.StdEncoding.EncodeToString([]byte(nonce)))
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if consumed || m["challenge_id"] != "ch1" || m["nonce"] != nonce {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		consumed = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"session":"sess1","principal":"tester","expires_at":9999999999},"meta":{"type":"papi-auth-session"}}`)
	})
}

// reposAuthedServer gates a §5-only forgejo forge behind the handshake: anonymous
// /papi/forges returns just the public github forge, the authed session also returns
// the forgejo one (carrying ssh_clone). --url synthesizes clone urls from these.
func reposAuthedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerHandshake(mux, "repos-nonce")
	pub := `{"id":"github-primary","kind":"github","base_url":"https://github.com","identity":"amarbel-llc","repos":[]}`
	gated := `{"id":"forgejo-gated","kind":"forgejo","base_url":"https://forge.linenisgreat.com","ssh_clone":"ssh://git@krone:2222","identity":"amarbel-llc","repos":[]}`
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+pub+`,`+gated+`],"meta":{"type":"forges","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pub+`],"meta":{"type":"forges","visibility":"public"}}`)
	})
	pubRepo := `{"name":"papi","url":"https://github.com/amarbel-llc/papi","owner":"amarbel-llc","forge":"github-primary","kind":"github","visibility":"public","default_branch":"master"}`
	gatedRepo := `{"name":"secret","url":"https://forge.linenisgreat.com/amarbel-llc/secret","owner":"amarbel-llc","forge":"forgejo-gated","kind":"forgejo","visibility":"scoped","default_branch":"main"}`
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+pubRepo+`,`+gatedRepo+`],"meta":{"type":"repos","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pubRepo+`],"meta":{"type":"repos","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

// TestReposAnonVsAuthed: anonymous --url omits the §5-gated forgejo repo; the authed
// handshake (--recipient/--decrypt-cmd) emits its SSH clone url, synthesized by joining
// the repo to the forge's ssh_clone base — the whole point of the (b) shape.
func TestReposAnonVsAuthed(t *testing.T) {
	srv := reposAuthedServer(t)
	defer srv.Close()

	anon, err := runRepos(t, srv.URL, "--url")
	if err != nil {
		t.Fatalf("anon repos: %v", err)
	}
	if strings.Contains(anon, "krone") || strings.Contains(anon, "linenisgreat") {
		t.Errorf("anonymous --url leaked a §5-gated forge:\n%s", anon)
	}
	if !strings.Contains(anon, "git@github.com:amarbel-llc/papi.git") {
		t.Errorf("anon --url should synthesize the public github clone url:\n%s", anon)
	}

	authed, err := runRepos(t, srv.URL, "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d", "--url")
	if err != nil {
		t.Fatalf("authed repos: %v", err)
	}
	if !strings.Contains(authed, "ssh://git@krone:2222/amarbel-llc/secret.git") {
		t.Errorf("authed --url missing the forgejo SSH clone url (ssh_clone join):\n%s", authed)
	}
	if n := len(strings.Split(strings.TrimSpace(authed), "\n")); n != 2 {
		t.Fatalf("authed --url want 2 clone urls, got %d:\n%s", n, authed)
	}
}

// signerFake signs as a slot-9A card would (SHA-256 over the bare preimage, ECDSA
// P-256, raw r‖s), standing in for a real PIV device via the signChallengeSignerFn seam.
type signerFake struct{ priv *ecdsa.PrivateKey }

func (f signerFake) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, f.priv, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	return rs, nil
}

// reposSignServer advertises the RECOMMENDED §5.2 sign-challenge scheme and gates a
// §5-only forgejo forge behind it: the challenge mints a nonce for a known
// auth_key_id, the response ECDSA-verifies the slot-9A signature over the §5.2
// preimage (bound to the request host), and authed /papi/forges adds the gated forge.
func reposSignServer(t *testing.T, signerPub *ecdsa.PublicKey, authKeyID string) *httptest.Server {
	t.Helper()
	consumed := false
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"version":"papi/v0","auth":{"scheme":"piggy-sign-challenge"}}`)
	})
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["auth_key_id"] != authKeyID {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"challenge_id":"ch1","nonce":"repos-sign-nonce","expires_at":9999999999},"meta":{"type":"papi-auth-challenge"}}`)
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if consumed || m["challenge_id"] != "ch1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := signchallenge.Verify(signerPub, r.Host, "repos-sign-nonce", m["signature"]); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		consumed = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"session":"sess1","principal":"tester","expires_at":9999999999},"meta":{"type":"papi-auth-session"}}`)
	})
	githubForge := `{"id":"github-primary","kind":"github","base_url":"https://github.com","identity":"friedenberg","repos":[]}`
	gatedForge := `{"id":"forgejo-gated","kind":"forgejo","base_url":"https://forge.example.com","ssh_clone":"ssh://git@forge.example.com:2222","identity":"friedenberg","repos":[]}`
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+githubForge+`,`+gatedForge+`],"meta":{"type":"forges","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+githubForge+`],"meta":{"type":"forges","visibility":"public"}}`)
	})
	// The flattened /papi/repos is the authoritative list --url enumerates: the github
	// repo (whose forge publishes repos:[]) and, when authed, the gated forgejo repo.
	// Each carries the `forge` id --url joins to the clone channel.
	pubRepo := `{"name":"papi","url":"https://github.com/friedenberg/papi","owner":"friedenberg","forge":"github-primary","kind":"github","visibility":"public","default_branch":"master"}`
	gatedRepo := `{"name":"secret","url":"https://forge.example.com/friedenberg/secret","owner":"friedenberg","forge":"forgejo-gated","kind":"forgejo","visibility":"scoped","default_branch":"main"}`
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+pubRepo+`,`+gatedRepo+`],"meta":{"type":"repos","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pubRepo+`],"meta":{"type":"repos","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

// TestReposSignChallengeURL is the CLI-level regression for amarbel-llc/papi#46:
// against a sign-challenge server, `repos --auth-key-id ... --url` runs the §5.2
// handshake (signing the nonce, not POSTing a slot-9D recipient) and enumerates the
// full scoped set. The slot-9A signer is injected via the signChallengeSignerFn seam.
func TestReposSignChallengeURL(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const authKeyID = "piggy-auth-v1@ecdsa_p256_pub-me"
	srv := reposSignServer(t, &priv.PublicKey, authKeyID)
	defer srv.Close()

	orig := signChallengeSignerFn
	signChallengeSignerFn = func(_ context.Context, _, guid, _, _ string) (signchallenge.Signer, string, error) {
		return signerFake{priv}, guid, nil
	}
	defer func() { signChallengeSignerFn = orig }()

	anon, err := runRepos(t, srv.URL, "--url")
	if err != nil {
		t.Fatalf("anon repos: %v", err)
	}
	if strings.Contains(anon, "secret") {
		t.Errorf("anonymous --url leaked a §5-gated forge:\n%s", anon)
	}
	if !strings.Contains(anon, "git@github.com:friedenberg/papi.git") {
		t.Errorf("anon --url should synthesize the public github clone url with the forge identity as owner:\n%s", anon)
	}

	authed, err := runRepos(t, srv.URL, "--auth-key-id", authKeyID, "--url")
	if err != nil {
		t.Fatalf("authed repos (sign-challenge): %v", err)
	}
	if !strings.Contains(authed, "ssh://git@forge.example.com:2222/friedenberg/secret.git") {
		t.Errorf("sign-challenge authed --url missing the gated forgejo clone url:\n%s", authed)
	}
	if n := len(strings.Split(strings.TrimSpace(authed), "\n")); n != 2 {
		t.Fatalf("sign-challenge authed --url want 2 clone urls, got %d:\n%s", n, authed)
	}
}

// flattenedReposServer mirrors the live linenisgreat shape that regressed papi#50:
// /papi/forges publishes a github forge with an EMPTY repos[] (a read-through anchor)
// while the flattened /papi/repos — the authoritative list — still carries the github
// repos. --url must emit them by joining each flattened entry to its forge by id.
func flattenedReposServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[`+
			`{"id":"github-primary","kind":"github","base_url":"https://github.com","identity":"friedenberg","repos":[]},`+
			`{"id":"forgejo-krone","kind":"forgejo","base_url":"https://forge.linenisgreat.com","ssh_clone":"ssh://git@forge.linenisgreat.com:2222","identity":"amarbel-llc","repos":[]}`+
			`],"meta":{"type":"forges","visibility":"public"}}`)
	})
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[`+
			`{"name":"xdg","url":"https://github.com/friedenberg/xdg","owner":"friedenberg","forge":"github-primary","kind":"github","visibility":"public","default_branch":"master"},`+
			`{"name":"stats-me","url":"https://forge.linenisgreat.com/amarbel-llc/stats-me","owner":"amarbel-llc","forge":"forgejo-krone","kind":"forgejo","visibility":"public","default_branch":"master"}`+
			`],"meta":{"type":"repos","visibility":"public","count":2}}`)
	})
	return httptest.NewServer(mux)
}

// TestReposURLFromFlattenedRepos is the papi#50 regression: --url must source repos
// from the authoritative flattened /papi/repos and join clone channels by `forge` id,
// so a github forge that publishes repos:[] (the live linenisgreat read-through shape)
// still yields clone urls — the bug was --url iterating the empty forge.repos[].
func TestReposURLFromFlattenedRepos(t *testing.T) {
	srv := flattenedReposServer(t)
	defer srv.Close()
	out, err := runRepos(t, srv.URL, "--url")
	if err != nil {
		t.Fatalf("repos --url: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 clone urls, got %d:\n%s", len(lines), out)
	}
	// The github repo comes from the flattened list even though its forge's repos[] is
	// empty — derived scp-style from base_url.
	if !strings.Contains(out, "git@github.com:friedenberg/xdg.git") {
		t.Errorf("missing the github clone url (the dropped forge.repos=[] regression):\n%s", out)
	}
	// The forgejo repo uses the forge's ssh_clone override (scheme + :2222), not a
	// host-derived url.
	if !strings.Contains(out, "ssh://git@forge.linenisgreat.com:2222/amarbel-llc/stats-me.git") {
		t.Errorf("missing the forgejo ssh_clone url:\n%s", out)
	}
}

// TestReposURLWarnsAndStrict is the papi#50 safety net: a published repo with no
// derivable clone url is reported on stderr and omitted (exit 0), and --strict turns
// that omission into a nonzero exit.
func TestReposURLWarnsAndStrict(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A forge with neither ssh_clone nor a parseable base_url host.
		io.WriteString(w, `{"data":[{"id":"weird","kind":"bare","base_url":"","identity":"x","repos":[]}],"meta":{"type":"forges","visibility":"public"}}`)
	})
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A repo whose forge has no channel AND whose own url has no host → undrivable.
		io.WriteString(w, `{"data":[{"name":"orphan","url":"","owner":"x","forge":"weird","kind":"bare","visibility":"public"}],"meta":{"type":"repos","visibility":"public","count":1}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Default: omitted with a stderr warning, exit 0.
	cmd := newReposCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{srv.URL, "--url"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("--url should not error by default: %v", err)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("want no clone urls, got:\n%s", out.String())
	}
	if !strings.Contains(errBuf.String(), "orphan") || !strings.Contains(errBuf.String(), "omitted") {
		t.Errorf("want a stderr omission warning naming the repo, got:\n%s", errBuf.String())
	}

	// --strict: the same omission is a nonzero exit.
	strictCmd := newReposCmd()
	strictCmd.SilenceUsage, strictCmd.SilenceErrors = true, true
	strictCmd.SetOut(new(bytes.Buffer))
	strictCmd.SetErr(new(bytes.Buffer))
	strictCmd.SetArgs([]string{srv.URL, "--url", "--strict"})
	if err := strictCmd.ExecuteContext(context.Background()); err == nil {
		t.Error("--strict should exit nonzero when a published repo is omitted")
	}
}

// forgesAuthedServer gates a §5-only forgejo forge (carrying the non-standard
// ssh_clone field) behind the handshake.
func forgesAuthedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerHandshake(mux, "forges-nonce")
	pub := `{"id":"github-amarbel-llc","kind":"github","base_url":"https://github.com","repos":[{"name":"papi","owner":"amarbel-llc"}]}`
	gated := `{"id":"forgejo-krone-amarbel-llc","kind":"forgejo","base_url":"https://forge.linenisgreat.com","ssh_clone":"ssh://git@krone:2222","repos":[{"name":"secret","owner":"amarbel-llc","default_branch":"main"}]}`
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+pub+`,`+gated+`],"meta":{"type":"forges","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pub+`],"meta":{"type":"forges","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

// TestSignChallengeFromResponse pins the offline-signer papercut fix: by default
// `papi sign-challenge` is a strict bare-payload primitive, and --from-response lets
// a user pipe the live server's full §4.2-enveloped /papi/auth/challenge response
// straight in (challenge read from .data). No leniency — the input shape is chosen
// explicitly per invocation, not sniffed.
func TestSignChallengeFromResponse(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := signChallengeSignerFn
	signChallengeSignerFn = func(_ context.Context, _, guid, _, _ string) (signchallenge.Signer, string, error) {
		return signerFake{priv}, guid, nil
	}
	defer func() { signChallengeSignerFn = orig }()

	const enveloped = `{"data":{"challenge_id":"ch1","nonce":"0011223344556677","expires_at":9999999999},"meta":{"type":"papi-auth-challenge"}}`

	// --from-response unwraps the {data,meta} envelope and signs the inner challenge.
	cmd := newSignChallengeCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetIn(strings.NewReader(enveloped))
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--domain", "staging.linenisgreat.com", "--from-response"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("sign-challenge --from-response: %v", err)
	}
	var resp signchallenge.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; out=%s", err, out.String())
	}
	if resp.ChallengeID != "ch1" {
		t.Errorf("challenge_id = %q, want ch1 (read from .data)", resp.ChallengeID)
	}
	if !strings.HasPrefix(resp.Signature, "papi-auth-sig-v1@") {
		t.Errorf("signature = %q, want a papi-auth-sig-v1 markl id", resp.Signature)
	}

	// Without --from-response the enveloped body is rejected — the default is the
	// strict bare primitive (ParseChallenge finds no top-level challenge_id).
	bare := newSignChallengeCmd()
	bare.SilenceUsage, bare.SilenceErrors = true, true
	bare.SetIn(strings.NewReader(enveloped))
	bare.SetOut(new(bytes.Buffer))
	bare.SetArgs([]string{"--domain", "staging.linenisgreat.com"})
	if err := bare.ExecuteContext(context.Background()); err == nil {
		t.Error("sign-challenge without --from-response should reject an enveloped body (strict bare primitive)")
	}
}

// forgeCheckServer serves a forge that declares a private canary plus an anonymous
// /papi/repos that either hides the canary (leak=false) or leaks it (leak=true).
func forgeCheckServer(t *testing.T, leak bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"id":"forgejo-krone","kind":"forgejo","base_url":"https://forge.example.com","identity":"amarbel-llc","canary":"amarbel-llc/papi-private-canary"}],"meta":{"type":"forges","visibility":"public"}}`)
	})
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pub := `{"name":"stats-me","url":"https://forge.example.com/amarbel-llc/stats-me","owner":"amarbel-llc","forge":"forgejo-krone","kind":"forgejo","visibility":"public"}`
		if leak {
			canary := `{"name":"papi-private-canary","url":"https://forge.example.com/amarbel-llc/papi-private-canary","owner":"amarbel-llc","forge":"forgejo-krone","kind":"forgejo","visibility":"public"}`
			io.WriteString(w, `{"data":[`+pub+`,`+canary+`],"meta":{"type":"repos","visibility":"public","count":2}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pub+`],"meta":{"type":"repos","visibility":"public","count":1}}`)
	})
	return httptest.NewServer(mux)
}

func runForgeCheck(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newForgeCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestForgeCheckCanaryAbsent: the card-free floor passes (exit 0) when the declared
// canary is absent from the anonymous /papi/repos.
func TestForgeCheckCanaryAbsent(t *testing.T) {
	srv := forgeCheckServer(t, false)
	defer srv.Close()
	out, err := runForgeCheck(t, "check", srv.URL)
	if err != nil {
		t.Fatalf("forge check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "absent from anonymous") {
		t.Errorf("want a canary-absent ok point:\n%s", out)
	}
}

// TestForgeCheckCanaryLeaked: a canary present in the anonymous listing is a MUST
// failure (nonzero exit) — the private-repo leak the shared gate exists to catch.
func TestForgeCheckCanaryLeaked(t *testing.T) {
	srv := forgeCheckServer(t, true)
	defer srv.Close()
	out, err := runForgeCheck(t, "check", srv.URL)
	if err == nil {
		t.Fatalf("forge check should fail on a leaked canary:\n%s", out)
	}
	if !strings.Contains(out, "LEAKED") {
		t.Errorf("want a canary-leak MUST failure:\n%s", out)
	}
}

// TestForgeCheckAuthedReconcile: with a handshake, the authed tier reconciles the full
// declared set — a declared-public repo anonymously visible AND a declared-private repo
// anonymously hidden both pass.
func TestForgeCheckAuthedReconcile(t *testing.T) {
	mux := http.NewServeMux()
	registerHandshake(mux, "forge-nonce")
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"id":"forgejo-krone","kind":"forgejo","base_url":"https://forge.example.com","identity":"amarbel-llc"}],"meta":{"type":"forges","visibility":"public"}}`)
	})
	pub := `{"name":"stats-me","url":"https://forge.example.com/amarbel-llc/stats-me","owner":"amarbel-llc","forge":"forgejo-krone","kind":"forgejo","visibility":"public"}`
	priv := `{"name":"secret","url":"https://forge.example.com/amarbel-llc/secret","owner":"amarbel-llc","forge":"forgejo-krone","kind":"forgejo","visibility":"private"}`
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+pub+`,`+priv+`],"meta":{"type":"repos","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pub+`],"meta":{"type":"repos","visibility":"public"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	out, err := runForgeCheck(t, "check", srv.URL, "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d")
	if err != nil {
		t.Fatalf("authed forge check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "declared-public repo") {
		t.Errorf("want the declared-public reconciliation verdict:\n%s", out)
	}
	if !strings.Contains(out, "declared-private") {
		t.Errorf("want the declared-private reconciliation verdict:\n%s", out)
	}
}

func runForges(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newForgesCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestForgesAnonVsAuthedPassThrough: anonymous forges omit the §5-gated forge; the
// authed set includes it AND passes the server's non-standard ssh_clone field through
// verbatim (RFC-0001 §1.1 — clients preserve members they don't recognize), which is
// what a clone consumer joins with repos[] to build SSH clone urls.
func TestForgesAnonVsAuthedPassThrough(t *testing.T) {
	srv := forgesAuthedServer(t)
	defer srv.Close()

	anon, err := runForges(t, srv.URL)
	if err != nil {
		t.Fatalf("anon forges: %v", err)
	}
	if strings.Contains(anon, "ssh_clone") || strings.Contains(anon, "forgejo") {
		t.Errorf("anonymous forges leaked the §5-gated forgejo forge:\n%s", anon)
	}

	authed, err := runForges(t, srv.URL, "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d")
	if err != nil {
		t.Fatalf("authed forges: %v", err)
	}
	if !strings.Contains(authed, `"ssh_clone"`) || !strings.Contains(authed, "ssh://git@krone:2222") {
		t.Errorf("authed forges dropped the server's ssh_clone field (must pass through):\n%s", authed)
	}
	if !strings.Contains(authed, "forgejo") {
		t.Errorf("authed forges missing the §5-gated forgejo forge:\n%s", authed)
	}
}

// authedTextServer serves a text/plain projected endpoint gated by the §5 handshake:
// anonymous returns pub, the authed session returns pub + a §5-gated extra line.
func authedTextServer(t *testing.T, path, pub, extra string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerHandshake(mux, "text-nonce")
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, pub+"\n"+extra+"\n")
			return
		}
		io.WriteString(w, pub+"\n")
	})
	return httptest.NewServer(mux)
}

// TestPiggyIDsAuthed / TestSSHKeysAuthed: the text endpoints gate their scoped set
// behind --recipient, exactly like the JSON ones.
func TestPiggyIDsAuthed(t *testing.T) {
	srv := authedTextServer(t, "/papi/piggy-ids", "piggy-recipient-v1@pub", "piggy-recipient-v1@gated")
	defer srv.Close()
	run := func(args ...string) string {
		cmd := newPiggyIDsCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatalf("piggy-ids %v: %v", args, err)
		}
		return out.String()
	}
	if anon := run(srv.URL); strings.Contains(anon, "gated") {
		t.Errorf("anonymous piggy-ids leaked a §5-gated id:\n%s", anon)
	}
	if authed := run(srv.URL, "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d"); !strings.Contains(authed, "gated") {
		t.Errorf("authed piggy-ids missing the §5-gated id:\n%s", authed)
	}
}

func TestSSHKeysAuthed(t *testing.T) {
	// guids must be hex (the --guid matcher is [0-9A-Fa-f]+); cn labels carry the
	// pub/gated distinction for the leak check.
	srv := authedTextServer(t, "/papi/ssh-authorized-keys",
		"ecdsa-sha2-nistp256 AAAApub guid=BEEF cn=pub",
		"ecdsa-sha2-nistp256 BBBBgated guid=DEAD cn=gated")
	defer srv.Close()
	run := func(args ...string) string {
		cmd := newSSHKeysCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatalf("ssh-keys %v: %v", args, err)
		}
		return out.String()
	}
	if anon := run(srv.URL); strings.Contains(anon, "cn=gated") {
		t.Errorf("anonymous ssh-keys leaked a §5-gated key:\n%s", anon)
	}
	// --guid resolves against the authed set: the gated card is found only with auth.
	if authed := run(srv.URL, "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d", "--guid", "DEAD"); !strings.Contains(authed, "guid=DEAD") {
		t.Errorf("authed ssh-keys --guid DEAD should resolve the §5-gated key:\n%s", authed)
	}
}

// profilesAuthedServer gates a §5-only host profile behind the handshake.
func profilesAuthedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerHandshake(mux, "profiles-nonce")
	pub := `{"id":"public-host","flakeref":"github:x/y#pub"}`
	gated := `{"id":"private-host","flakeref":"github:x/y#priv"}`
	mux.HandleFunc("/papi/profiles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":[`+pub+`,`+gated+`],"meta":{"type":"profiles","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":[`+pub+`],"meta":{"type":"profiles","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

func TestProfilesAuthed(t *testing.T) {
	srv := profilesAuthedServer(t)
	defer srv.Close()
	run := func(args ...string) string {
		cmd := newProfilesCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatalf("profiles %v: %v", args, err)
		}
		return out.String()
	}
	if anon := run(srv.URL, "--flakeref"); strings.Contains(anon, "priv") {
		t.Errorf("anonymous profiles leaked a §5-gated host profile:\n%s", anon)
	}
	authed := run(srv.URL, "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d", "--flakeref")
	if !strings.Contains(authed, "github:x/y#priv") {
		t.Errorf("authed profiles missing the §5-gated host profile:\n%s", authed)
	}
}

// queryAuthedServer gates person.contact behind the handshake (the §2 acl gate),
// so a jq over the scoped /papi projection reaches it.
func queryAuthedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerHandshake(mux, "query-nonce")
	mux.HandleFunc("/papi", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":{"person":{"handle":"t","contact":{"email":"me@example.com"}}},"meta":{"visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":{"person":{"handle":"t"}},"meta":{"visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

func TestQueryAuthed(t *testing.T) {
	srv := queryAuthedServer(t)
	defer srv.Close()
	run := func(args ...string) string {
		cmd := newQueryCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatalf("query %v: %v", args, err)
		}
		return strings.TrimSpace(out.String())
	}
	expr := `.person.contact.email // "none"`
	if anon := run(srv.URL, expr, "-r"); anon != "none" {
		t.Errorf("anonymous query saw acl-gated contact.email = %q, want none", anon)
	}
	if authed := run(srv.URL, expr, "-r", "--recipient", "piggy-x", "--decrypt-cmd", "base64 -d"); authed != "me@example.com" {
		t.Errorf("authed query contact.email = %q, want me@example.com", authed)
	}
}

// profilesServer serves a /papi/profiles list: a NixOS host (system + standalone
// home, carrying home_flakeref) and a non-NixOS home profile (no home_flakeref).
func profilesServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/profiles", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[`+
			`{"id":"framework-laptop","flakeref":"github:amarbel-llc/eng#nixosConfigurations.framework-laptop","home_flakeref":"github:amarbel-llc/eng#homeConfigurations.framework-laptop","kind":"nixos-configuration","platform":"nixos","description":"Framework 13 laptop"},`+
			`{"id":"dev","flakeref":"github:amarbel-llc/eng#homeConfigurations.dev","kind":"home-configuration","platform":"linux","description":"non-NixOS dev home"}`+
			`],"meta":{"type":"profiles","visibility":"public","count":2}}`)
	})
	return httptest.NewServer(mux)
}

func runProfiles(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newProfilesCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestProfilesJSON(t *testing.T) {
	srv := profilesServer(t)
	defer srv.Close()
	out, err := runProfiles(t, srv.URL)
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	var ps []papi.Profile
	if err := json.Unmarshal([]byte(out), &ps); err != nil {
		t.Fatalf("profiles output not JSON: %v\n%s", err, out)
	}
	if len(ps) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(ps))
	}
	if ps[0].ID != "framework-laptop" || ps[0].HomeFlakeref == "" || ps[0].Kind != "nixos-configuration" {
		t.Errorf("profile[0] = %+v", ps[0])
	}
	if ps[1].HomeFlakeref != "" {
		t.Errorf("non-nixos profile should carry no home_flakeref, got %q", ps[1].HomeFlakeref)
	}
}

func TestProfilesIDAndFlakeref(t *testing.T) {
	srv := profilesServer(t)
	defer srv.Close()

	// --id selects exactly one; --flakeref prints its activation target.
	out, err := runProfiles(t, srv.URL, "--id", "framework-laptop", "--flakeref")
	if err != nil {
		t.Fatalf("profiles --id --flakeref: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "nixosConfigurations.framework-laptop") {
		t.Errorf("want the framework-laptop flakeref, got %q", out)
	}

	// an unknown id errors.
	if _, err := runProfiles(t, srv.URL, "--id", "nope"); err == nil {
		t.Error("unknown --id should error")
	}
}

// queryDocServer serves a /papi document with nested forges[].repos[] for jq.
func queryDocServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"tester"},`+
			`"forges":[{"id":"gh","kind":"github","repos":[`+
			`{"url":"https://github.com/amarbel-llc/papi"},{"url":"https://github.com/amarbel-llc/eng"}]}]},`+
			`"meta":{"type":"papi","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

func runQueryCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newQueryCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestQueryRawScalar(t *testing.T) {
	srv := queryDocServer(t)
	defer srv.Close()
	out, err := runQueryCmd(t, srv.URL, ".person.handle", "-r")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if strings.TrimSpace(out) != "tester" {
		t.Errorf("query .person.handle -r = %q, want tester", out)
	}
}

func TestQueryListURLs(t *testing.T) {
	srv := queryDocServer(t)
	defer srv.Close()
	out, err := runQueryCmd(t, srv.URL, ".forges[].repos[].url", "-r")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[0] != "https://github.com/amarbel-llc/papi" {
		t.Errorf("query urls = %q", lines)
	}
}

func TestQueryBadExpr(t *testing.T) {
	// A parse error short-circuits before any network call.
	_, err := runQueryCmd(t, "example.invalid", "{")
	if err == nil {
		t.Fatal("malformed jq expr should error")
	}
}

// --- identity (FDR-0009) ---

// identityFixture is a representative identity.toml for the CLI tests.
const identityFixture = `[host]
privilege-escalation = "sudo"
empty = ""

[papi]
domain = "linenisgreat.com"
`

// writeIdentityFixture writes content to a temp identity.toml and returns its path.
func writeIdentityFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runIdentity builds the identity command, runs it against args, and returns its
// stdout and error (cobra dispatches to the get/domain subcommand named first).
func runIdentity(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newIdentityCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestIdentityGetScalar(t *testing.T) {
	path := writeIdentityFixture(t, identityFixture)
	out, err := runIdentity(t, "get", "host.privilege-escalation", "--file", path)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if strings.TrimSpace(out) != "sudo" {
		t.Errorf("got %q, want sudo", out)
	}
}

func TestIdentityGetAbsentKeyUsesDefault(t *testing.T) {
	path := writeIdentityFixture(t, identityFixture)
	out, err := runIdentity(t, "get", "host.does-not-exist", "--default", "auto", "--file", path)
	if err != nil {
		t.Fatalf("absent key with --default must exit 0: %v", err)
	}
	if strings.TrimSpace(out) != "auto" {
		t.Errorf("got %q, want auto", out)
	}
}

func TestIdentityGetAbsentKeyNoDefaultIsEmpty(t *testing.T) {
	path := writeIdentityFixture(t, identityFixture)
	out, err := runIdentity(t, "get", "host.does-not-exist", "--file", path)
	if err != nil {
		t.Fatalf("absent key without --default must exit 0: %v", err)
	}
	if out != "\n" {
		t.Errorf("got %q, want a single empty line", out)
	}
}

func TestIdentityGetAbsentFileUsesDefault(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	out, err := runIdentity(t, "get", "papi.domain", "--default", "fallback.example", "--file", missing)
	if err != nil {
		t.Fatalf("absent file with --default must exit 0: %v", err)
	}
	if strings.TrimSpace(out) != "fallback.example" {
		t.Errorf("got %q, want fallback.example", out)
	}
}

func TestIdentityGetNonScalarErrors(t *testing.T) {
	path := writeIdentityFixture(t, identityFixture)
	// "host" is a table; per the contract this is a caller bug → non-zero exit,
	// and the default must NOT rescue it.
	if _, err := runIdentity(t, "get", "host", "--default", "x", "--file", path); err == nil {
		t.Fatal("a path resolving to a table must error even with --default")
	}
}

func TestIdentityDomain(t *testing.T) {
	path := writeIdentityFixture(t, identityFixture)
	out, err := runIdentity(t, "domain", "--file", path)
	if err != nil {
		t.Fatalf("domain: %v", err)
	}
	if strings.TrimSpace(out) != "linenisgreat.com" {
		t.Errorf("got %q, want linenisgreat.com", out)
	}
}

func TestIdentityDomainAbsentIsEmpty(t *testing.T) {
	// A file with no [papi] domain: the default-less accessor prints empty, exit 0.
	path := writeIdentityFixture(t, "[host]\nprivilege-escalation = \"sudo\"\n")
	out, err := runIdentity(t, "domain", "--file", path)
	if err != nil {
		t.Fatalf("absent domain must exit 0: %v", err)
	}
	if out != "\n" {
		t.Errorf("got %q, want a single empty line", out)
	}
}

// signChallengeServeRun runs the serve command's arg validation. It only exercises
// the error paths, which return before the command binds a socket or blocks serving.
func signChallengeServeRun(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newSignChallengeServeCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.ExecuteContext(context.Background())
}

func TestSignChallengeServeValidation(t *testing.T) {
	// Neither --domain nor --allow-callback: nothing to serve.
	if err := signChallengeServeRun(t); err == nil || !strings.Contains(err.Error(), "nothing to serve") {
		t.Errorf("no mode = %v, want 'nothing to serve'", err)
	}
	// --domain without --origin.
	if err := signChallengeServeRun(t, "--domain", "d.example"); err == nil ||
		!strings.Contains(err.Error(), "--origin is required") {
		t.Errorf("domain without origin = %v, want '--origin is required'", err)
	}
	// --target needs --domain; --allow-callback supplies a mode so we reach that check.
	if err := signChallengeServeRun(t,
		"--allow-callback", "https://forge.example/auth/callback",
		"--target", "https://api.example"); err == nil ||
		!strings.Contains(err.Error(), "--target requires --domain") {
		t.Errorf("target without domain = %v, want '--target requires --domain'", err)
	}
}

// purposePigpenSelfSig mirrors the unexported constant of the same name in
// internal/alfa/inspect (pigpen.go) — papi's provisional, piggy-unratified
// self-signature purpose token (RFC-0001 §14.2). package main can't import
// it directly, and duplicating the literal here (rather than exporting it
// just for a test) keeps inspect's provisional-scheme warning contained to
// one package. Mirrors cmd/pigpen-resolver-papi-http/main_test.go's fixture
// of the same shape. If that constant is ever renamed, this test fixture's
// signature will simply stop verifying (fail loud, not silently pass).
const purposePigpenSelfSig = "papi-pigpen-self-sig-v1"

// renderPigpenLines canonicalizes and serializes lines into hyphence document
// bytes via FormatBodyEmitter — mirrors
// internal/alfa/inspect/pigpen_test.go's renderPigpenDoc, reimplemented here
// since that helper is unexported in a different package.
func renderPigpenLines(t *testing.T, lines []hyphence.MetadataLine) []byte {
	t.Helper()
	doc := &hyphence.Document{Metadata: append([]hyphence.MetadataLine(nil), lines...)}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newSignedPigpenFixture starts an httptest.Server that serves a genuinely
// self-signed /papi/pigpen document (RFC-0001 §14.2) plus the matching
// /papi/piggy-ids publication, and returns the server and the exact document
// bytes a successful `papi pigpen resolve` should print unmodified.
//
// This duplicates the signing recipe from
// internal/alfa/inspect/pigpen_test.go's buildPigpenDoc (strip-self bytes via
// a bare `! pigpen-v1` line, sign, re-embed the lock) because that package's
// crypto-critical core (verifyPigpenSelfSignature, pigpenStripSelfBytes) is
// unexported and this is a different package (main). The crypto verification
// logic itself is already exhaustively covered by
// internal/alfa/inspect/pigpen_test.go; this fixture exists only to prove
// newPigpenResolveCmd's RunE carries a real success end to end (stdout ==
// resolved bytes), not to re-prove the crypto.
func newSignedPigpenFixture(t *testing.T) (srv *httptest.Server, doc []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	keyID, err := markl.Build(markl.PurposePIVAuth, markl.FormatSSHEcdsaNistp256Pub, compressed)
	if err != nil {
		t.Fatal(err)
	}

	lines := []hyphence.MetadataLine{
		{Prefix: '-', Value: keyID},
		{Prefix: '!', Value: "pigpen-v1"},
	}
	stripped := renderPigpenLines(t, lines) // strip-self signing input (§14.2)

	digest := sha256.Sum256(stripped)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sigID, err := markl.Build(purposePigpenSelfSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	lines[1].Value = "pigpen-v1@" + sigID
	doc = renderPigpenLines(t, lines)

	mux := http.NewServeMux()
	mux.HandleFunc("/papi/pigpen", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/vnd.pigpen")
		_, _ = w.Write(doc)
	})
	mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("# piggy-ids\n" + keyID + "\n"))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, doc
}

// TestPigpenResolveCmdSuccess exercises newPigpenResolveCmd's RunE against a
// genuinely self-signed fixture: exit nil, stdout equal to the resolved
// document bytes exactly.
func TestPigpenResolveCmdSuccess(t *testing.T) {
	srv, doc := newSignedPigpenFixture(t)

	cmd := newPigpenResolveCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("pigpen resolve: %v", err)
	}
	if !bytes.Equal(out.Bytes(), doc) {
		t.Errorf("stdout must equal the resolved document bytes exactly:\ngot:  %q\nwant: %q", out.Bytes(), doc)
	}
}

// TestPigpenResolveCmdFailure exercises newPigpenResolveCmd's RunE against a
// server with no /papi/pigpen route (404): ResolvePigpen's error must
// propagate through RunE unwrapped (no extra prefixing — root's own "papi:
// "+err handles that at the top level), embedding the locator.
func TestPigpenResolveCmdFailure(t *testing.T) {
	srv := httptest.NewServer(http.NewServeMux()) // no routes -> 404 on everything
	defer srv.Close()

	cmd := newPigpenResolveCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{srv.URL})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("pigpen resolve against a domain with no /papi/pigpen should error")
	}
	if out.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got %q", out.String())
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention the underlying HTTP 404, got %v", err)
	}
	if !strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error should embed the locator %q (from ResolvePigpen's own error), got %v", srv.URL, err)
	}
}

// TestPigpenCmdTree confirms `papi pigpen` registers `resolve` as a child
// subcommand (the parent+child home future pigpen affordances will share).
func TestPigpenCmdTree(t *testing.T) {
	cmd := newPigpenCmd()
	found := false
	for _, c := range cmd.Commands() {
		if c.Name() == "resolve" {
			found = true
		}
	}
	if !found {
		t.Errorf("papi pigpen should register a resolve subcommand, got: %v", cmd.Commands())
	}
}
