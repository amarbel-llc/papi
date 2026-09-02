package forgetoken

import (
	"testing"
	"time"
)

func TestTokenNameRoundTrip(t *testing.T) {
	deadline := time.Unix(1789000000, 0).UTC()
	cases := []string{
		"papi/mild-maple",              // the spinclass <repo-dirname>/<branch> shape
		"spinclass/fork.name_with-mix", // `sc fork` allows "-", "." and "_" in a branch
		"bare",
		"weird session/with spaces & symbols!",
		"trailing-digits/foo-123",
	}
	for _, session := range cases {
		t.Run(session, func(t *testing.T) {
			name := TokenName(session, deadline)
			gotSession, gotDeadline, ok := ParseTokenName(name)
			if !ok {
				t.Fatalf("ParseTokenName(%q) rejected a name we minted", name)
			}
			if gotSession != session {
				t.Fatalf("session round-trip: got %q, want %q (name %q)", gotSession, session, name)
			}
			if !gotDeadline.Equal(deadline) {
				t.Fatalf("deadline round-trip: got %s, want %s", gotDeadline, deadline)
			}
		})
	}
}

// The lossy "flatten / to -" encoding bobo warned about collides repo "a-b" +
// branch "c" with repo "a" + branch "b-c", which would let one session's revoke
// kill another's token. The escape must keep them distinct.
func TestDistinctSessionsNeverShareATokenName(t *testing.T) {
	deadline := time.Unix(1789000000, 0).UTC()
	a := TokenName("a-b/c", deadline)
	b := TokenName("a/b-c", deadline)
	if a == b {
		t.Fatalf("distinct sessions produced the same token name %q", a)
	}
	for session, name := range map[string]string{"a-b/c": a, "a/b-c": b} {
		got, _, ok := ParseTokenName(name)
		if !ok || got != session {
			t.Fatalf("ParseTokenName(%q) = %q, %v; want %q", name, got, ok, session)
		}
	}
}

func TestTokenNameZeroDeadline(t *testing.T) {
	name := TokenName("papi/mild-maple", time.Time{})
	session, deadline, ok := ParseTokenName(name)
	if !ok {
		t.Fatalf("ParseTokenName(%q) rejected a deadline-free name", name)
	}
	if session != "papi/mild-maple" {
		t.Fatalf("session: got %q", session)
	}
	if !deadline.IsZero() {
		t.Fatalf("a deadline-free token must decode to the zero time, got %s", deadline)
	}
	if (Managed{Deadline: deadline}).Expired(time.Now().Add(1000 * time.Hour)) {
		t.Fatal("a deadline-free token must never be swept")
	}
}

// Anything papi did not mint must fail to parse, since ParseTokenName is the only
// thing standing between the sweeper and the operator's own tokens.
func TestParseTokenNameRejectsForeignNames(t *testing.T) {
	for _, name := range []string{
		"",
		"my-laptop",
		"forge/krone-api-token",
		"papi-no-deadline-suffix",
		"papi-session-notanumber",
		"papi-truncated_2-123",  // malformed escape
		"papi-bad_ZZ-123",       // non-hex escape
		"prefixed-papi-foo-123", // prefix must anchor at the start
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := ParseTokenName(name); ok {
				t.Fatalf("ParseTokenName(%q) accepted a name papi did not mint", name)
			}
		})
	}
}
