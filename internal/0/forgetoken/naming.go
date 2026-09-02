package forgetoken

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NamePrefix marks a token as papi-minted. Every name papi generates starts with
// it, and `sweep` will only ever delete tokens carrying it — the operator's own
// hand-made tokens are structurally out of reach of the sweeper.
const NamePrefix = "papi-"

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
		c := session[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "_%02X", c)
		}
	}
	return b.String()
}

// unescapeSession inverts escapeSession. It reports ok=false on a malformed
// escape so a hand-made token that merely happens to start with "papi-" is
// rejected rather than misread as a session's.
func unescapeSession(escaped string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(escaped); i++ {
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
