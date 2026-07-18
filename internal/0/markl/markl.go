// Package markl parses "markl-id" self-describing identifier strings as
// specified by amarbel-llc/madder RFC-0002: an OPTIONAL `purpose@` decoration
// followed by a blech32-encoded `format-payload` body. papi needs this to read
// the `signatures[]` markl-ids of RFC-0001 §10 (Amendment 9) — the document
// signature `papi-doc-sig-v1@ecdsa_p256_sig-…` and its verifying key
// `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…`.
//
// madder's reference Go implementation lives in an internal/ package and is not
// importable, so this is a minimal, decode-focused port validated byte-for-byte
// against madder's RFC-0002 conformance vectors (see markl_test.go). Purpose ⇄
// format compatibility policy is left to the caller (the §10 verifier checks the
// exact purpose/format pair it expects); this package validates only the blech32
// envelope and the payload size of formats it knows.
//
// TEMPORARY: this package will be dropped in favor of piggy's shared markl Go
// library once the piggy#183 ownership inversion ships an importable module —
// tracked in amarbel-llc/papi#10. The surface (Parse, Build, ID, the format/
// purpose constants) is kept deliberately small so the swap is mechanical.
package markl

import (
	"errors"
	"fmt"
	"strings"
)

// ErrWrongSize is returned when a known format's decoded payload is the wrong
// length (RFC-0002 §5 registers a fixed byte size per format).
var ErrWrongSize = errors.New("markl: wrong payload size for format")

// formatSizes is the registered byte length of each markl format papi consumes
// (RFC-0002 §5). Formats absent here are decoded without a size check — an
// unknown format is the caller's to skip, not this package's to reject.
var formatSizes = map[string]int{
	FormatEcdsaP256Sig:           64, // ECDSA P-256 signature, raw r‖s fixed-width
	FormatSSHEcdsaNistp256Pub:    33, // SEC1-compressed P-256 public key
	FormatPigpenSelfSigEcdsaP256: 64, // ECDSA P-256 signature, raw r‖s fixed-width
}

// Known format identifiers papi consumes.
const (
	FormatEcdsaP256Sig        = "ecdsa_p256_sig"
	FormatSSHEcdsaNistp256Pub = "ssh_ecdsa_nistp256_pub"

	// FormatPigpenSelfSigEcdsaP256 is a single, atomic format tag for the
	// pigpen `!`-line self-signature lock (RFC-0001 §14.2, papi#54) — used
	// with an EMPTY purpose (Build("", FormatPigpenSelfSigEcdsaP256, raw)),
	// producing a bare `format-payload` markl-id with no `@` at all.
	//
	// This is deliberately NOT the general `purpose@format-payload` shape
	// papi uses for its own top-level JSON /papi document signatures
	// (PurposeDocSig+FormatEcdsaP256Sig, etc.). That split genuinely earns
	// its keep there, where many different purposes share a small set of
	// interchangeable formats. It does NOT fit hyphence/pigpen documents:
	// piggy's own lock-slot tags in the same document format — e.g.
	// pigpen_header_mac, pigpen_wrap_p256, pigpen_wrap_x25519 — are each one
	// atomic tag encoding both "what this is" and "what algorithm" together,
	// never a purpose+format pair. papi's pigpen self-signature originally
	// (papi#54 Tasks B3/C1/D1) copied the general two-field shape by habit;
	// piggy's actual parser (crates/piggy-pigpen/src/document.rs,
	// parse_type_line/decode_mac) only ever splits the `!`-line's value on
	// ONE `@`, then blech32-decodes everything after it as a single tag —
	// so a two-field lock's inner `@` broke the HRP piggy computed, and its
	// blech32 checksum (which is computed over the HRP) failed outright.
	// This format tag fixes that by following pigpen's own established
	// one-tag-per-(meaning,algorithm) convention instead.
	FormatPigpenSelfSigEcdsaP256 = "papi_pigpen_self_sig_ecdsa_p256_v1"
)

// Known purpose identifiers papi consumes (RFC-0002 §6.1).
const (
	PurposeDocSig    = "papi-doc-sig-v1"    // PAPI document signature (§10)
	PurposeProofSig  = "papi-proof-sig-v1"  // PAPI identity-proof claim signature (§9.3)
	PurposeEnrollAtt = "papi-enroll-att-v1" // PAPI enrollment-receipt attestation (FDR-0001)
	PurposeAuthSig   = "papi-auth-sig-v1"   // PAPI sign-challenge auth signature (§5.2)
	PurposePIVAuth   = "piggy-piv_auth-v1"  // PIV slot-9A authentication key
)

// ID is a parsed markl-id.
type ID struct {
	Purpose string // the `purpose` decoration, or "" when absent
	Format  string // the format (the blech32 human-readable part)
	Payload []byte // the decoded payload bytes
	Raw     string // the original string
}

// Parse decodes a markl-id string. It splits an OPTIONAL leading `purpose@`,
// blech32-decodes the `format-payload` body, and — for formats it knows —
// checks the payload size. Unknown formats decode without a size check.
func Parse(s string) (ID, error) {
	if s == "" {
		return ID{}, ErrSeparatorMissing
	}
	if !uniformCase(s) {
		return ID{}, ErrMixedCase
	}
	purpose, body := "", s
	if at := strings.IndexByte(s, '@'); at >= 0 {
		purpose, body = s[:at], s[at+1:]
	}
	format, payload, err := blech32Decode(body)
	if err != nil {
		return ID{}, err
	}
	if want, ok := formatSizes[format]; ok && len(payload) != want {
		return ID{}, fmt.Errorf("%w: %s is %d bytes, want %d", ErrWrongSize, format, len(payload), want)
	}
	return ID{Purpose: purpose, Format: format, Payload: payload, Raw: s}, nil
}

// Build encodes a markl-id from a purpose, format, and payload. Used by tests to
// construct fixtures byte-identically to a producer. A known format whose
// payload is the wrong size is rejected.
func Build(purpose, format string, payload []byte) (string, error) {
	if want, ok := formatSizes[format]; ok && len(payload) != want {
		return "", fmt.Errorf("%w: %s is %d bytes, want %d", ErrWrongSize, format, len(payload), want)
	}
	body, err := blech32Encode(format, payload)
	if err != nil {
		return "", err
	}
	if purpose == "" {
		return body, nil
	}
	return purpose + "@" + body, nil
}
