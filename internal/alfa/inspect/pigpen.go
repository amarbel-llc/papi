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

	"code.linenisgreat.com/hyphence/go/hyphence"
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

// findPigpenSelfSig returns the first `-`-prefixed line whose value carries
// papi's pigpen self-signature purpose (RFC-0001 §14.2, papi#54) — an
// ordinary purpose@format-payload markl-id
// (papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>), placed as a bare `-`
// line's whole value, same shape as the recipient/auth-key lines already in
// the document. ok is false when no such line exists at all (the common,
// SHOULD-not-MUST unsigned case, which must resolve without ever parsing
// the value as a markl-id); ok is true and value is returned as-is — still
// unparsed — when a line with the purpose prefix exists but may or may not
// otherwise be well-formed, mirroring findPigpenAuthKey's found-vs-missing
// split.
//
// This scheme replaces an earlier one that embedded the signature as a lock
// on the pigpen `!`-line: piggy's RFC 0008 §2.6 reserves that lock slot
// exclusively for a sealed document's header MAC, so a payload-less
// self-signature never had a wire position there at all. Verified against
// piggy's real recipient-set parser, which already tolerates an
// unrecognized-purpose `-` line by design (hyphence content grammar §6.6:
// an identifier the type system can't resolve degrades to a plain tag, not
// a decode error) — see linenisgreat/hyphence#6 and piggy commit ff4eb12.
func findPigpenSelfSig(lines []hyphence.MetadataLine) (value string, ok bool) {
	prefix := markl.PurposePigpenSelfSig + "@"
	for _, l := range lines {
		if l.Prefix != '-' || !strings.HasPrefix(l.Value, prefix) {
			continue
		}
		return l.Value, true
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

// pigpenStripSelfBytes reconstructs the §14.2 strip-self signing input:
// lines with the self-signature `-` line omitted entirely (as if it were
// never added, mirroring §10.2's JSON strip-and-canonicalize recipe),
// canonicalized and re-encoded via hyphence's own FormatBodyEmitter — the
// same canonicalization a signer applies before signing — so a verifier
// reconstructing these bytes from a parsed document lands on identical
// bytes regardless of the source line order. Unlike the earlier `!`-line
// lock scheme (which always kept the type line, only clearing its lock
// suffix), the self-signature now has no "present but empty" state of its
// own on the wire — an unsigned document simply has no such line, so
// omitting it entirely from the signing input is the exact analogue.
func pigpenStripSelfBytes(lines []hyphence.MetadataLine) ([]byte, error) {
	prefix := markl.PurposePigpenSelfSig + "@"
	stripped := make([]hyphence.MetadataLine, 0, len(lines))
	for _, l := range lines {
		if l.Prefix == '-' && strings.HasPrefix(l.Value, prefix) {
			continue
		}
		stripped = append(stripped, l)
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
//
// errPigpenNoAuthKey is also returned directly by SignPigpen (papi#54 Task
// D1, below): it calls findPigpenAuthKey itself rather than going through
// verifyPigpenSelfSignature, but the underlying condition — and what a
// caller should do about it — is identical on both the sign and verify
// sides, so it's shared rather than duplicated. See its own comment for why
// its wording is direction-neutral.
var (
	// errPigpenUnsigned: no papi-pigpen-self-sig-v1 `-` line in the document
	// at all. The self-signature is SHOULD, not MUST (RFC-0001 §14.2), so on
	// its own this is never a failure.
	errPigpenUnsigned = errors.New("no " + markl.PurposePigpenSelfSig + " markl-id line in the document")

	// errPigpenLockMalformed: a line with the self-signature purpose prefix
	// exists but doesn't parse as a well-formed
	// papi-pigpen-self-sig-v1@ecdsa_p256_sig markl-id — unverifiable, not a
	// failure.
	errPigpenLockMalformed = errors.New("self-signature line is not a well-formed " + markl.PurposePigpenSelfSig + "@" + markl.FormatEcdsaP256Sig + " markl-id")

	// errPigpenNoAuthKey: no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line in
	// the document. On the verify side (verifyPigpenSelfSignature) this means
	// there's no key to check an existing signature against — unverifiable,
	// not a failure. On the sign side (SignPigpen) it means there'd be
	// nothing for a FUTURE verifier to check the about-to-be-produced
	// signature against, so SignPigpen refuses outright. The wording below
	// is deliberately direction-neutral (doesn't say "the signature",
	// singular/existing) so it reads correctly from both call sites.
	errPigpenNoAuthKey = errors.New("no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line for a self-signature to be verified against")

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
// self-signature verification (papi#54): parse the self-signature `-` line,
// locate and check publication of the signing key, and run the ECDSA
// verification — from "parse the self-signature" through "ecdsa verify". It
// makes no HTTP calls itself (the caller supplies already-parsed lines), so
// it's reusable by both `papi validate` (pigpenSignaturePoints) and a
// resolver (ResolvePigpen) without duplicating the crypto-critical logic.
//
// fetchAuthIDs is called at most once, and only once a self-signature line
// has been found and an auth-key line has been found — mirroring the
// pre-refactor inline code's call timing exactly. This matters:
// /papi/piggy-ids is a live network fetch (fetchPiggyAuthIDs), and the
// common case §14.2 explicitly expects — a present-but-unsigned document,
// or a document with no self-signature/auth-key line at all — must resolve
// without ever touching the network. Callers typically pass a closure
// wrapping fetchPiggyAuthIDs; tests can pass one returning a static slice
// with no server involved.
//
// On success it returns the signing key's markl-id and a nil error; on any
// of the distinguishable failure/skip outcomes it returns a sentinel or
// wrapped error from the errPigpen* family above (see each for what it
// means), along with the signing key's markl-id when one was found before
// the failure occurred.
func verifyPigpenSelfSignature(lines []hyphence.MetadataLine, fetchAuthIDs func() []string) (keyID string, err error) {
	value, hasSig := findPigpenSelfSig(lines)
	if !hasSig {
		return "", errPigpenUnsigned
	}

	sigID, err := markl.Parse(value)
	if err != nil || sigID.Purpose != markl.PurposePigpenSelfSig || sigID.Format != markl.FormatEcdsaP256Sig {
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
// (RFC-0001 §14.2, papi#54): a papi-pigpen-self-sig-v1@ecdsa_p256_sig
// markl-id on its own `-` line (see findPigpenSelfSig's doc comment for why
// it lives there rather than as a `!`-line lock). The purpose itself
// (papi-pigpen-self-sig-v1) remains papi's own invention — piggy has not
// standardized a dedicated self-signature concept — but the *shape* is
// verified against piggy's real recipient-set parser, which tolerates an
// unrecognized-purpose `-` line by design (linenisgreat/hyphence#6, piggy
// RFC 0008 §2.3/§10 as of commit ff4eb12), so this is no longer a guess
// about undocumented behavior.
//
// /papi/pigpen is entirely OPTIONAL (RFC-0001 §14.1): a 404, any other
// non-200 status, or a fetch error is always a skip, never a fail, so this
// check never trips `papi validate`'s exit code against a server that simply
// doesn't implement it. Likewise a present-but-unsigned document (the
// self-signature is SHOULD, not MUST) is a skip. Only a present, well-formed,
// published-key self-signature that fails cryptographic verification is a
// MUST failure — mirroring signaturePoints' signed-but-invalid handling.
//
// The fetch, status-check, and metadata parse stay here (I/O, not
// crypto-critical); everything from "parse the self-signature" through
// "ecdsa verify" is delegated to verifyPigpenSelfSignature, whose returned
// error is mapped back to the exact skip/mustFail/ok points this function
// has always produced.
func pigpenSignaturePoints(ctx context.Context, c *papi.Client) []point {
	const label = "pigpen: §14.2 self-signature (papi#54)"

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
		return []point{skip("pigpen: unsigned (§14.2 SHOULD)",
			"no "+markl.PurposePigpenSelfSig+" markl-id line in the document")}
	case errors.Is(verr, errPigpenLockMalformed):
		return []point{skip(label+" unverifiable",
			"self-signature line is not a well-formed "+markl.PurposePigpenSelfSig+"@"+markl.FormatEcdsaP256Sig+" markl-id")}
	case errors.Is(verr, errPigpenNoAuthKey):
		return []point{skip(label+" unverifiable",
			"no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line to verify the self-signature against")}
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
// still carries the self-signature line (RFC-0010 §6). Passthrough avoids a
// second, unnecessary dependency on hyphence's encoder being lossless, and
// preserves an audit trail: a later reader can see the doc *was*
// self-signed.
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
// distinguishable errPigpen* verdicts — unsigned, malformed self-signature,
// no auth-key line, key not published, signature invalid).
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

// --- Signing (producer side, papi#54 Task D1) ---

// errPigpenAlreadySigned: SignPigpen was asked to sign a document that
// already has a papi-pigpen-self-sig-v1 `-` line. Refusing (rather than
// silently overwriting) means a caller can't accidentally destroy an
// existing self-signature by re-running SignPigpen on already-signed input.
var errPigpenAlreadySigned = errors.New("pigpen document already has a self-signature line; refusing to overwrite")

// errPigpenNoTypeLine: SignPigpen was asked to sign a document with no `!`
// line at all — a malformed/truncated pigpen document, not just an unsigned
// one. findPigpenAuthKey's ok==true says nothing about whether a `!` line is
// present anywhere else in the document — a document can publish a
// well-formed auth-key `-` line while missing its `!` line entirely. The new
// self-signature `-` line is inserted immediately before the `!` line to
// keep canonical line order (RFC 0002 §"Canonical line order": `-` lines,
// then `@`, then `!`), so SignPigpen needs that line's position and refuses
// before ever invoking the signer if there isn't one (no point spending a
// card signature on input that can't be completed).
var errPigpenNoTypeLine = errors.New("no `! pigpen-v1` type line to insert the self-signature line before")

// PigpenSigner signs message bytes with the slot-9A key of the card
// identified by guid, returning the raw 64-byte r‖s ECDSA P-256 signature —
// structurally identical to signchallenge.Signer (same method, same
// contract: msg is the bare preimage, NOT a pre-hash, since the card hashes
// SHA-256 internally). Defined locally rather than imported from
// signchallenge: Go's structural typing means any value already satisfying
// signchallenge.Signer's method set (e.g. enroll.PiggySignBytesSigner,
// enroll.AgentSignBytesSigner) also satisfies this interface with zero
// adapter code, so there's no reason to import that package just for its
// interface declaration.
type PigpenSigner interface {
	SignSlot9A(ctx context.Context, guid string, msg []byte) (rs []byte, err error)
}

// SignPigpen produces a self-signed pigpen document (RFC-0001 §14.2,
// papi#54): the producer-side inverse of verifyPigpenSelfSignature. data is
// an unsigned (or not-yet-self-signed) hyphence pigpen document; on success
// SignPigpen returns the same document with a fresh
// papi-pigpen-self-sig-v1@ecdsa_p256_sig markl-id inserted as a new `-`
// line, immediately before the `! pigpen-v1` type line (see
// findPigpenSelfSig's doc comment for why the signature lives on its own
// line rather than as a `!`-line lock).
//
// SignPigpen refuses three malformed inputs rather than silently producing a
// document a verifier can't check or worse, clobbering an existing
// signature:
//
//   - A papi-pigpen-self-sig-v1 line already exists (findPigpenSelfSig
//     reports ok=true): errPigpenAlreadySigned. Signing over an existing
//     signature would either silently discard a legitimate prior signature
//     or leave the document with two competing signature lines; either way
//     the caller almost certainly didn't intend it.
//   - No piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line is present
//     (findPigpenAuthKey reports ok=false): errPigpenNoAuthKey, the same
//     sentinel verifyPigpenSelfSignature returns for the identical
//     condition on the verify side — there is nothing in the document for a
//     future verifier to check the signature against.
//   - No `!` line exists anywhere in the document at all: errPigpenNoTypeLine.
//     Checked before the signer is ever invoked, since there'd be nowhere to
//     insert the resulting signature line regardless of what the signer
//     returns.
//
// The signing input is pigpenStripSelfBytes(lines) — the same canonicalized,
// still-unsigned-at-this-point strip-self bytes verifyPigpenSelfSignature
// reconstructs on the verify side, so a valid signature from here is
// guaranteed to verify there. signer.SignSlot9A is called with that input
// directly, UN-hashed: piggy (and any PigpenSigner satisfying this
// interface) hashes SHA-256 internally, per PiggySignBytesSigner's own doc
// comment (internal/alfa/enroll/card.go).
//
// Any error returned by signer.SignSlot9A is propagated (wrapped, so
// errors.Is/errors.As against the underlying error still works).
func SignPigpen(ctx context.Context, signer PigpenSigner, guid string, data []byte) ([]byte, error) {
	lines, err := parsePigpenMetadataLines(data)
	if err != nil {
		return nil, fmt.Errorf("pigpen: sign: parse hyphence metadata: %w", err)
	}

	if _, hasSig := findPigpenSelfSig(lines); hasSig {
		return nil, errPigpenAlreadySigned
	}

	if _, _, hasKey := findPigpenAuthKey(lines); !hasKey {
		return nil, errPigpenNoAuthKey
	}

	typeLineIdx := -1
	for i, l := range lines {
		if l.Prefix == '!' {
			typeLineIdx = i
			break
		}
	}
	if typeLineIdx < 0 {
		return nil, errPigpenNoTypeLine
	}

	input, err := pigpenStripSelfBytes(lines)
	if err != nil {
		return nil, fmt.Errorf("pigpen: sign: reconstruct strip-self bytes: %w", err)
	}

	raw, err := signer.SignSlot9A(ctx, guid, input)
	if err != nil {
		return nil, fmt.Errorf("pigpen: sign: %w", err)
	}

	sigID, err := markl.Build(markl.PurposePigpenSelfSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		return nil, fmt.Errorf("pigpen: sign: build self-signature markl-id: %w", err)
	}

	signed := make([]hyphence.MetadataLine, 0, len(lines)+1)
	signed = append(signed, lines[:typeLineIdx]...)
	signed = append(signed, hyphence.MetadataLine{Prefix: '-', Value: sigID})
	signed = append(signed, lines[typeLineIdx:]...)

	doc := &hyphence.Document{Metadata: signed}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(strings.NewReader("")); err != nil {
		return nil, fmt.Errorf("pigpen: sign: re-encode signed document: %w", err)
	}

	return buf.Bytes(), nil
}
