//go:build !wasip1 && !(js && wasm)

// The hyphence import below pulls in purse-first/libs/dewey transitively,
// which has no wasip1/js-wasm implementation of its OS-file-attribute
// syscall wrapper (setUserChanges in dewey's internal/delta/files package).
// internal/alfa/inspect is imported wholesale by both cmd/papi-verify-wasm
// (GOOS=wasip1) and cmd/papi-client-wasm (GOOS=js GOARCH=wasm), and Go
// compiles every file in an imported package for the target platform even
// when its exported symbols go uncalled — so this file (and its
// hyphence/dewey dependency) must stay out of both wasm builds until
// nothing outside inspect calls parsePigpenMetadataLines under those
// targets (see `just build-wasm` / `just build-wasm-client`).
package inspect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/amarbel-llc/hyphence/go/hyphence"
	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

// parsePigpenMetadataLines decodes the metadata section of a hyphence
// document (RFC 0001) into its ordered []MetadataLine, discarding any
// body bytes that follow the closing boundary. This is deliberately a
// thin wrapper around hyphence's own machinery — hyphence.Reader
// driving hyphence.MetadataBuilder (the same pairing hyphence's own
// `hyphence format` subcommand uses) — with no pigpen-specific
// interpretation of the lines. That interpretation (locating the
// `piggy-recipient-v1@...` and `! pigpen-v1` lines, verifying the
// provisional self-signature) is Task B3.
func parsePigpenMetadataLines(data []byte) ([]hyphence.MetadataLine, error) {
	doc := &hyphence.Document{}
	reader := hyphence.Reader{
		RequireMetadata: true,
		Metadata:        &hyphence.MetadataBuilder{Doc: doc},
		Blob:            &hyphence.CountingDiscardReaderFrom{},
	}

	if _, err := reader.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, err
	}

	return doc.Metadata, nil
}

// purposePigpenSelfSig is the markl purpose for the pigpen `!`-line
// self-signature lock (RFC-0001 §14.2). THIS IS A PROVISIONAL,
// PAPI-INVENTED PLACEHOLDER. piggy RFC 0008 (pigpen wire format), RFC 0009
// (production cutover), and RFC 0010 (resolver-dispatch protocol) have since
// landed and piggy#216 is closed — but none of the three defines, reserves,
// or even mentions a self-signature scheme for a payload-less pigpen
// document: RFC 0008 §2.2's three documented faces (recipient set, sealed,
// pointer) assign the `!`-line lock only to a sealed document's header MAC,
// and §5's markl-registration table has no purpose resembling this one. So
// this isn't "still draft, awaiting the real name" — it's "outside what
// piggy's pigpen RFCs address at all." Expect this constant to be renamed or
// restructured if piggy ever does standardize a self-signature face; do not
// treat it as stable wire format. See
// docs/features/0013-pigpen-resolver-papi-http.md (Limitations) and
// docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md ("Tuning
// levers").
const purposePigpenSelfSig = "papi-pigpen-self-sig-v1"

// extractPigpenTypeLock finds the `!`-prefixed type-line MetadataLine and
// splits its Value on the first `@` into the type identifier (`pigpen-v1`)
// and the lock that follows it — the self-signature markl-id, when present
// (RFC-0001 §14.2). ok is false when there is no type line at all, or the
// type line carries no lock (a bare `pigpen-v1`, permitted since the
// self-signature is SHOULD not MUST).
func extractPigpenTypeLock(lines []hyphence.MetadataLine) (lock string, ok bool) {
	for _, l := range lines {
		if l.Prefix != '!' {
			continue
		}
		i := strings.IndexByte(l.Value, '@')
		if i < 0 {
			return "", false
		}
		return l.Value[i+1:], true
	}
	return "", false
}

// findPigpenAuthKey returns the first `-`-prefixed
// piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub markl-id among lines — the slot-9A
// key the provisional self-signature is verified against, published
// in-document exactly as RFC-0001 §14.3's worked example shows (the same key
// /papi/piggy-ids advertises).
func findPigpenAuthKey(lines []hyphence.MetadataLine) (keyMarklID string, keyPoint []byte, ok bool) {
	for _, l := range lines {
		if l.Prefix != '-' {
			continue
		}
		id, err := markl.Parse(l.Value)
		if err != nil || id.Purpose != markl.PurposePIVAuth || id.Format != markl.FormatSSHEcdsaNistp256Pub {
			continue
		}
		return l.Value, id.Payload, true
	}
	return "", nil, false
}

// pigpenStripSelfBytes reconstructs the §14.2 strip-self signing input: lines
// with the `!` type-line's lock removed (as if it were empty, mirroring
// §10.2's JSON strip-and-canonicalize recipe), canonicalized and re-encoded
// via hyphence's own FormatBodyEmitter — the same canonicalization a signer
// applies before signing — so a verifier reconstructing these bytes from a
// parsed document lands on identical bytes regardless of the source line
// order.
func pigpenStripSelfBytes(lines []hyphence.MetadataLine) ([]byte, error) {
	stripped := make([]hyphence.MetadataLine, len(lines))
	copy(stripped, lines)
	for i, l := range stripped {
		if l.Prefix != '!' {
			continue
		}
		if idx := strings.IndexByte(l.Value, '@'); idx >= 0 {
			l.Value = l.Value[:idx]
		}
		stripped[i] = l
	}

	doc := &hyphence.Document{Metadata: stripped}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(strings.NewReader("")); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Sentinel errors returned by verifyPigpenSelfSignature, letting callers
// (pigpenSignaturePoints below, and later ResolvePigpen, papi#54 Task C2)
// branch on which trust-verdict class occurred via errors.Is/errors.As
// instead of parsing error strings. Each corresponds to one of §14.2's
// distinguishable outcomes short of a valid signature.
var (
	// errPigpenUnsigned: no lock on the `! pigpen-v1` type line at all. The
	// self-signature is SHOULD, not MUST (RFC-0001 §14.2), so on its own this
	// is never a failure.
	errPigpenUnsigned = errors.New("no self-signature lock on the `! pigpen-v1` line")

	// errPigpenLockMalformed: the lock is present but doesn't parse as the
	// expected papi-pigpen-self-sig-v1@ecdsa_p256_sig markl-id (papi's
	// provisional, piggy-unratified scheme) — unverifiable, not a failure.
	errPigpenLockMalformed = errors.New("lock is not a " + purposePigpenSelfSig + "@ecdsa_p256_sig markl-id")

	// errPigpenNoAuthKey: no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line in
	// the document to verify the lock against — unverifiable, not a failure.
	errPigpenNoAuthKey = errors.New("no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line to verify the lock against")

	// errPigpenKeyNotPublished: the signing key is present in-document but
	// isn't advertised on /papi/piggy-ids — unverifiable (falls back to
	// unsigned), not a failure.
	errPigpenKeyNotPublished = errors.New("signing key is not published (piggy-ids)")

	// errPigpenSigInvalid: the ECDSA verification itself returned false — a
	// MUST failure (signed-but-invalid).
	errPigpenSigInvalid = errors.New("signature invalid")
)

// errPigpenKeyMalformed wraps a p256FromCompressed decode failure: the
// published key point itself doesn't decode to a valid P-256 public key.
// Reporting-wise this belongs to the same "signed-but-invalid" MUST-failure
// class as errPigpenSigInvalid (a key was found and published, but
// verification still can't succeed), but it's kept as its own error type
// (rather than folding into errPigpenSigInvalid) so the caller can recover
// the underlying decode error via Unwrap for its diagnostic map, exactly as
// the pre-refactor inline code did.
type errPigpenKeyMalformed struct{ err error }

func (e *errPigpenKeyMalformed) Error() string {
	return "signing key point malformed: " + e.err.Error()
}

func (e *errPigpenKeyMalformed) Unwrap() error { return e.err }

// errPigpenStripBytes wraps a pigpenStripSelfBytes failure: reconstructing
// the canonicalized strip-self signing input from the parsed lines failed.
// This is an internal encoding failure, not a trust verdict about the
// document (it doesn't fit "unsigned", "unverifiable", or "invalid" — the
// document may well be validly signed, hyphence just couldn't re-encode it),
// so it gets its own error type rather than folding into
// errPigpenLockMalformed; the pre-refactor code likewise reported it under
// the bare label, distinct from the "unverifiable" and "unsigned" skips.
type errPigpenStripBytes struct{ err error }

func (e *errPigpenStripBytes) Error() string {
	return "reconstruct strip-self bytes: " + e.err.Error()
}

func (e *errPigpenStripBytes) Unwrap() error { return e.err }

// verifyPigpenSelfSignature performs the trust-critical core of §14.2
// self-signature verification (papi#54): parse the lock, locate and check
// publication of the signing key, and run the ECDSA verification — from
// "parse the lock" through "ecdsa verify". It makes no HTTP calls itself
// (the caller supplies already-parsed lines), so it's reusable by both
// `papi validate` (pigpenSignaturePoints) and a future resolver
// (ResolvePigpen, Task C2) without duplicating the crypto-critical logic.
//
// fetchAuthIDs is called at most once, and only once the lock has parsed and
// an auth-key line has been found — mirroring the pre-refactor inline code's
// call timing exactly. This matters: /papi/piggy-ids is a live network fetch
// (fetchPiggyAuthIDs), and the common case §14.2 explicitly expects — a
// present-but-unsigned document, or a document with no lock/auth-key line at
// all — must resolve without ever touching the network. Callers typically
// pass a closure wrapping fetchPiggyAuthIDs; tests can pass one returning a
// static slice with no server involved.
//
// On success it returns the signing key's markl-id and a nil error; on any
// of the distinguishable failure/skip outcomes it returns a sentinel or
// wrapped error from the errPigpen* family above (see each for what it
// means), along with the signing key's markl-id when one was found before
// the failure occurred.
func verifyPigpenSelfSignature(lines []hyphence.MetadataLine, fetchAuthIDs func() []string) (keyID string, err error) {
	lock, hasLock := extractPigpenTypeLock(lines)
	if !hasLock {
		return "", errPigpenUnsigned
	}

	sigID, err := markl.Parse(lock)
	if err != nil || sigID.Purpose != purposePigpenSelfSig || sigID.Format != markl.FormatEcdsaP256Sig {
		return "", errPigpenLockMalformed
	}

	keyID, keyPoint, hasKey := findPigpenAuthKey(lines)
	if !hasKey {
		return "", errPigpenNoAuthKey
	}

	if !keyPublishedMarkl(keyID, keyPoint, nil, fetchAuthIDs()) {
		return keyID, errPigpenKeyNotPublished
	}

	pub, perr := p256FromCompressed(keyPoint)
	if perr != nil {
		return keyID, &errPigpenKeyMalformed{err: perr}
	}

	input, serr := pigpenStripSelfBytes(lines)
	if serr != nil {
		return keyID, &errPigpenStripBytes{err: serr}
	}

	if !ecdsaVerifyRaw(pub, input, sigID.Payload) {
		return keyID, errPigpenSigInvalid
	}

	return keyID, nil
}

// pigpenSignaturePoints verifies the /papi/pigpen document's self-signature
// (RFC-0001 §14.2, papi#54) against papi's PROVISIONAL, piggy-unaddressed
// scheme (the "papi-pigpen-self-sig-v1" purpose is papi's own placeholder —
// see purposePigpenSelfSig's doc comment above and
// docs/features/0013-pigpen-resolver-papi-http.md). piggy RFC 0008/0009/0010
// have since landed (piggy#216 closed) but never defined a self-signature
// face for a payload-less pigpen document, so there is nothing yet for this
// scheme to "graduate" into; it WILL need rework only if/when a future piggy
// RFC standardizes one. Until then, do not treat this as a stable
// wire-format check.
//
// /papi/pigpen is entirely OPTIONAL (RFC-0001 §14.1): a 404, any other
// non-200 status, or a fetch error is always a skip, never a fail, so this
// check never trips `papi validate`'s exit code against a server that simply
// doesn't implement it. Likewise a present-but-unsigned document (the
// self-signature is SHOULD, not MUST) is a skip. Only a present, well-formed,
// published-key lock that fails cryptographic verification is a MUST
// failure — mirroring signaturePoints' signed-but-invalid handling.
//
// The fetch, status-check, and metadata parse stay here (I/O, not
// crypto-critical); everything from "parse the lock" through "ecdsa verify"
// is delegated to verifyPigpenSelfSignature, whose returned error is mapped
// back to the exact skip/mustFail/ok points this function has always
// produced.
func pigpenSignaturePoints(ctx context.Context, c *papi.Client) []point {
	const label = "pigpen: §14.2 self-signature (experimental, provisional scheme, papi#54)"

	resp, err := c.Fetch(ctx, "/papi/pigpen")
	if err != nil {
		return []point{skip(label, "GET /papi/pigpen failed: "+err.Error())}
	}
	if resp.Status == http.StatusNotFound {
		return []point{skip(label, "/papi/pigpen not implemented (OPTIONAL, RFC-0001 §14.1)")}
	}
	if resp.Status != http.StatusOK {
		return []point{skip(label, fmt.Sprintf("/papi/pigpen returned HTTP %d", resp.Status))}
	}

	lines, err := parsePigpenMetadataLines(resp.Body)
	if err != nil {
		return []point{skip(label, "parse hyphence metadata: "+err.Error())}
	}

	keyID, verr := verifyPigpenSelfSignature(lines, func() []string {
		return fetchPiggyAuthIDs(ctx, c)
	})

	var keyMalformed *errPigpenKeyMalformed
	var stripBytes *errPigpenStripBytes
	switch {
	case verr == nil:
		return []point{ok(label + ": signed-and-valid")}
	case errors.Is(verr, errPigpenUnsigned):
		return []point{skip("pigpen: unsigned (§14.2 SHOULD, experimental)",
			"no self-signature lock on the `! pigpen-v1` line")}
	case errors.Is(verr, errPigpenLockMalformed):
		return []point{skip(label+" unverifiable",
			"lock is not a "+purposePigpenSelfSig+"@ecdsa_p256_sig markl-id")}
	case errors.Is(verr, errPigpenNoAuthKey):
		return []point{skip(label+" unverifiable",
			"no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line to verify the lock against")}
	case errors.Is(verr, errPigpenKeyNotPublished):
		return []point{skip(label+" unverifiable -> unsigned",
			"signing key is not published (piggy-ids)")}
	case errors.As(verr, &keyMalformed):
		return []point{mustFail(label+": signed-but-invalid",
			map[string]any{"error": keyMalformed.err.Error(), "key": keyID})}
	case errors.As(verr, &stripBytes):
		return []point{skip(label, "reconstruct strip-self bytes: "+stripBytes.err.Error())}
	case errors.Is(verr, errPigpenSigInvalid):
		return []point{mustFail(label+": signed-but-invalid", map[string]any{"key": keyID})}
	default:
		// Unreachable given verifyPigpenSelfSignature's documented contract
		// (it only ever returns nil or one of the errPigpen* values above),
		// but fail closed rather than silently reporting success.
		return []point{mustFail(label+": signed-but-invalid",
			map[string]any{"error": verr.Error(), "key": keyID})}
	}
}

// ResolvePigpen fetches, verifies, and returns papi's self-signed pigpen
// document (RFC-0001 §14.2, papi#54 Task C2): GET /papi/pigpen, verify the
// self-signature against the live /papi/piggy-ids key list via
// verifyPigpenSelfSignature — the same crypto-critical core
// pigpenSignaturePoints uses — and on success return the original fetched
// bytes unmodified (verify-then-passthrough, not a re-encode). This is
// deliberate: pigpenStripSelfBytes/FormatBodyEmitter reconstructs a *signing
// input*, not a guaranteed byte-identical round-trip of whatever the origin
// served, and piggy is explicitly indifferent to whether the returned doc
// still carries the lock (RFC-0010 §6). Passthrough avoids a second,
// unnecessary dependency on hyphence's encoder being lossless, and preserves
// an audit trail: a later reader can see the doc *was* self-signed.
//
// Unlike pigpenSignaturePoints (a `papi validate` check, where
// /papi/pigpen is OPTIONAL per RFC-0001 §14.1 and a present-but-unsigned
// document is a graceful skip since the self-signature is SHOULD not MUST),
// ResolvePigpen is a resolver: it has no skip concept. Every failure —
// fetch error, non-200 status (including 404/not-implemented), a malformed
// hyphence document, or an unsigned document — is a hard error. Treating an
// unsigned document as a hard failure here is papi's own policy choice for
// this resolver, stricter than the RFC's SHOULD-not-MUST; it is documented
// as such, not exposed as a flag.
//
// Every returned error embeds c.BaseURL (the locator) so a bare, human-run
// invocation of the resolver binary is self-sufficient: piggy already adds
// kind="papi-http"/locator="..." context of its own when it wraps the
// resolver's stderr, so these messages don't repeat that, just distinguish
// *which* failure occurred (fetch failed, 404/not-implemented, unexpected
// status, malformed document, or one of verifyPigpenSelfSignature's
// distinguishable errPigpen* verdicts — unsigned, malformed lock, no
// auth-key line, key not published, signature invalid).
func ResolvePigpen(ctx context.Context, c *papi.Client) ([]byte, error) {
	resp, err := c.Fetch(ctx, "/papi/pigpen")
	if err != nil {
		return nil, fmt.Errorf("pigpen: resolve %s/papi/pigpen: fetch failed: %w", c.BaseURL, err)
	}
	if resp.Status == http.StatusNotFound {
		return nil, fmt.Errorf("pigpen: resolve %s/papi/pigpen: not implemented (HTTP 404)", c.BaseURL)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("pigpen: resolve %s/papi/pigpen: unexpected HTTP %d", c.BaseURL, resp.Status)
	}

	lines, err := parsePigpenMetadataLines(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pigpen: resolve %s/papi/pigpen: parse hyphence metadata: %w", c.BaseURL, err)
	}

	if _, verr := verifyPigpenSelfSignature(lines, func() []string {
		return fetchPiggyAuthIDs(ctx, c)
	}); verr != nil {
		return nil, fmt.Errorf("pigpen: resolve %s/papi/pigpen: %w", c.BaseURL, verr)
	}

	return resp.Body, nil
}
