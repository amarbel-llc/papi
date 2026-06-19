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
