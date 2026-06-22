package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
	"golang.org/x/crypto/ssh"
)

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

	out, errOut, err := sshCopyIDRun(t, "host", "--domain", srv.URL)
	if err != nil {
		t.Fatalf("should fall back to SFTP and succeed: %v", err)
	}
	if !sftpCalled {
		t.Error("expected automatic SFTP fallback after the shell path failed")
	}
	if !strings.Contains(errOut, "retrying over SFTP") {
		t.Errorf("expected a fallback notice on stderr, got %q", errOut)
	}
	if !strings.Contains(out, "2 key(s) added") {
		t.Errorf("SFTP fallback should install both keys, got %q", out)
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

	if _, _, err := sshCopyIDRun(t, "host", "--domain", srv.URL); err == nil {
		t.Fatal("an ssh-level (255) failure should surface, not fall back")
	}
	if sftpCalled {
		t.Error("must NOT fall back to SFTP on an ssh-level (255) failure — it would fail identically")
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

	cmd := newSSHCopyIDCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deploy@host.example", "--domain", srv.URL, "--port", "2222"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ssh-copy-id: %v", err)
	}

	if !strings.Contains(out.String(), "2 key(s) added, 0 already present") {
		t.Errorf("summary: %q", out.String())
	}
	if got := strings.Join(gotArgs, " "); got != "-p 2222 deploy@host.example sh" {
		t.Errorf("ssh args = %q, want %q", got, "-p 2222 deploy@host.example sh")
	}
	if !strings.Contains(gotScript, "PAPI_KEYS_EOF") || !strings.Contains(gotScript, "guid=DEADBEEF") {
		t.Errorf("install script not piped to ssh:\n%s", gotScript)
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

// reposServer serves a /papi/repos flattened list spanning two owners/forges.
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
	for _, l := range lines {
		if !strings.Contains(l, "amarbel-llc") {
			t.Errorf("unexpected url %q", l)
		}
	}
	if strings.Contains(out, "codeberg") {
		t.Errorf("--owner filter leaked another owner:\n%s", out)
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
