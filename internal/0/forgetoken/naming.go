package forgetoken

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NamePrefix marks a token as minted by this command. Every name papi generates
// starts with it, and revoke and sweep consider nothing else.
//
// It is this long on purpose. A short marker like "papi-" is not evidence of
// anything: on 2026-09-02 a sweep run against the live forge matched 5,146
// pre-existing tokens named "papi-key-sync-<epoch>-<n>" — minted by an unrelated
// job — because they shared that prefix AND their trailing number parsed as a
// (long past) Unix deadline, and revoked every one of them. The prefix is now
// specific to this feature, and ParseTokenName additionally enforces the escape
// alphabet below, which is the check that actually rules such names out.
const NamePrefix = "papi-forge-token-"

// A minted token's forge-visible name is the ONLY place papi records per-session
// state. There is no papi-side database: `revoke --session X` finds its token by
// listing the account's tokens and decoding the names, and `sweep` reads the
// deadline the same way. That is what makes both operations work from a fresh
// process on any host, and what lets a crashed session's token still be found.
//
// The layout is
//
//	papi-<escaped-session>-<deadline-unix>
//
// with the deadline as decimal seconds (0 = no deadline, never swept). Parsing
// splits on the LAST '-', which is unambiguous because the deadline is all
// digits and the escaping below never emits a trailing '-'.

// escapeSession renders an arbitrary session identifier into the character set a
// forge token name safely accepts, INJECTIVELY — distinct sessions always produce
// distinct escapes, so `revoke --session` can never match a different session's
// token. (A lossy squash of '/' to '-' would, for example, collide repo "a" +
// branch "b-c" with repo "a-b" + branch "c".)
//
// Bytes in [A-Za-z0-9.] pass through; every other byte, INCLUDING the '_' escape
// marker itself and '-', becomes "_XX" with XX the uppercase hex of the byte.
// Escaping '-' is what keeps the trailing-deadline split unambiguous.
func escapeSession(session string) string {
	var b strings.Builder
	for i := 0; i < len(session); i++ {
		if c := session[i]; isEscapeLiteral(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "_%02X", c)
		}
	}
	return b.String()
}

// isEscapeLiteral reports whether a byte survives escapeSession unchanged. It is
// the single definition of the escape alphabet, so escaping and the parser's
// validation cannot drift apart.
func isEscapeLiteral(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.'
}

// unescapeSession inverts escapeSession, accepting ONLY what escapeSession can
// produce: literals from [A-Za-z0-9.] and "_XX" hex escapes. Anything else means
// papi did not mint this name, and ok=false keeps revoke and sweep away from it.
//
// Rejecting a literal "-" is the load-bearing part, and the check whose absence
// caused the 2026-09-02 mass revocation described on NamePrefix: escapeSession
// encodes "-" as _2D, so a genuinely papi-minted session NEVER contains one,
// while an unrelated token named "papi-key-sync-<epoch>-<n>" does. Enforcing the
// alphabet excludes every such name structurally, rather than hoping the prefix
// is distinctive enough.
func unescapeSession(escaped string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(escaped); i++ {
		if c := escaped[i]; c != '_' && !isEscapeLiteral(c) {
			return "", false
		}
		if escaped[i] != '_' {
			b.WriteByte(escaped[i])
			continue
		}
		if i+2 >= len(escaped) {
			return "", false
		}
		v, err := strconv.ParseUint(escaped[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
		i += 2
	}
	return b.String(), true
}

// TokenName renders the forge-visible name for a session's token. A zero deadline
// means "no deadline" — the token is still revocable by session, but `sweep` will
// never reap it.
func TokenName(session string, deadline time.Time) string {
	var unix int64
	if !deadline.IsZero() {
		unix = deadline.Unix()
	}
	return fmt.Sprintf("%s%s-%d", NamePrefix, escapeSession(session), unix)
}

// ParseTokenName decodes a name produced by TokenName back into the session it was
// minted for and its deadline (zero when the name encodes 0). ok is false for any
// name papi did not mint, which is what keeps `sweep` off the operator's own
// tokens.
func ParseTokenName(name string) (session string, deadline time.Time, ok bool) {
	rest, found := strings.CutPrefix(name, NamePrefix)
	if !found {
		return "", time.Time{}, false
	}
	cut := strings.LastIndex(rest, "-")
	if cut < 0 {
		return "", time.Time{}, false
	}
	unix, err := strconv.ParseInt(rest[cut+1:], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	session, ok = unescapeSession(rest[:cut])
	if !ok {
		return "", time.Time{}, false
	}
	if unix == 0 {
		return session, time.Time{}, true
	}
	return session, time.Unix(unix, 0).UTC(), true
}
