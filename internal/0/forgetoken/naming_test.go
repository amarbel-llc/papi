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

// Pins the rendered format. The name is the feature's only persistent state and the
// operator reads it in the forge UI, so a change here is a real interface change —
// and note that "-" itself is escaped, which is what keeps the trailing-deadline
// split unambiguous.
func TestTokenNameRendersExactly(t *testing.T) {
	got := TokenName("papi/mild-maple", time.Unix(1789041600, 0).UTC())
	want := "papi-forge-token-papi_2Fmild_2Dmaple-1789041600"
	if got != want {
		t.Fatalf("TokenName = %q, want %q", got, want)
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

// Regression for the 2026-09-02 mass revocation: a live sweep matched 5,146
// pre-existing "papi-key-sync-<epoch>-<n>" tokens minted by an unrelated job and
// revoked all of them. They passed the old parser because they shared its "papi-"
// prefix and their trailing number read as a long-past Unix deadline. Both defences
// added since must reject them — the specific prefix, and (the load-bearing one) the
// escape alphabet, which forbids the literal "-" every such session name contains.
func TestParseTokenNameRejectsTheKeySyncNames(t *testing.T) {
	for _, name := range []string{
		"papi-key-sync-1788345474-434515",
		"papi-key-sync-1783389423-1171590",
		// Even carrying today's prefix, the hyphens still disqualify it.
		NamePrefix + "key-sync-1788345474-434515",
	} {
		t.Run(name, func(t *testing.T) {
			if session, deadline, ok := ParseTokenName(name); ok {
				t.Fatalf("ParseTokenName(%q) accepted a foreign token as session %q (deadline %s) — "+
					"sweep would revoke it", name, session, deadline)
			}
		})
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
