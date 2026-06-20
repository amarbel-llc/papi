package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
