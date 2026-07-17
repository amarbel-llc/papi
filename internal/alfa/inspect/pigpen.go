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
// PAPI-INVENTED PLACEHOLDER — piggy has not ratified a purpose name for this
// lock (piggy RFC 0008/0009, still draft). Expect this constant to be
// renamed the moment piggy ratifies the real one; do not treat it as stable
// wire format. See docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md
// ("Tuning levers").
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

// pigpenSignaturePoints verifies the /papi/pigpen document's self-signature
// (RFC-0001 §14.2, papi#54) against papi's PROVISIONAL, piggy-unratified
// scheme (the "papi-pigpen-self-sig-v1" purpose is papi's own placeholder —
// see docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md). This
// WILL need rework once piggy RFC 0008/0009 pins the real lock-line
// semantics; do not treat this as a stable wire-format check.
//
// /papi/pigpen is entirely OPTIONAL (RFC-0001 §14.1): a 404, any other
// non-200 status, or a fetch error is always a skip, never a fail, so this
// check never trips `papi validate`'s exit code against a server that simply
// doesn't implement it. Likewise a present-but-unsigned document (the
// self-signature is SHOULD, not MUST) is a skip. Only a present, well-formed,
// published-key lock that fails cryptographic verification is a MUST
// failure — mirroring signaturePoints' signed-but-invalid handling.
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

	lock, hasLock := extractPigpenTypeLock(lines)
	if !hasLock {
		return []point{skip("pigpen: unsigned (§14.2 SHOULD, experimental)",
			"no self-signature lock on the `! pigpen-v1` line")}
	}

	sigID, err := markl.Parse(lock)
	if err != nil || sigID.Purpose != purposePigpenSelfSig || sigID.Format != markl.FormatEcdsaP256Sig {
		return []point{skip(label+" unverifiable",
			"lock is not a "+purposePigpenSelfSig+"@ecdsa_p256_sig markl-id")}
	}

	keyID, keyPoint, hasKey := findPigpenAuthKey(lines)
	if !hasKey {
		return []point{skip(label+" unverifiable",
			"no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub line to verify the lock against")}
	}

	authIDs := fetchPiggyAuthIDs(ctx, c)
	if !keyPublishedMarkl(keyID, keyPoint, nil, authIDs) {
		return []point{skip(label+" unverifiable -> unsigned",
			"signing key is not published (piggy-ids)")}
	}

	pub, err := p256FromCompressed(keyPoint)
	if err != nil {
		return []point{mustFail(label+": signed-but-invalid",
			map[string]any{"error": err.Error(), "key": keyID})}
	}

	input, err := pigpenStripSelfBytes(lines)
	if err != nil {
		return []point{skip(label, "reconstruct strip-self bytes: "+err.Error())}
	}

	if !ecdsaVerifyRaw(pub, input, sigID.Payload) {
		return []point{mustFail(label+": signed-but-invalid", map[string]any{"key": keyID})}
	}
	return []point{ok(label + ": signed-and-valid")}
}
