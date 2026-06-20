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
	FormatEcdsaP256Sig:        64, // ECDSA P-256 signature, raw r‖s fixed-width
	FormatSSHEcdsaNistp256Pub: 33, // SEC1-compressed P-256 public key
}

// Known format identifiers papi consumes.
const (
	FormatEcdsaP256Sig        = "ecdsa_p256_sig"
	FormatSSHEcdsaNistp256Pub = "ssh_ecdsa_nistp256_pub"
)

// Known purpose identifiers papi consumes (RFC-0002 §6.1).
const (
	PurposeDocSig  = "papi-doc-sig-v1"   // PAPI document signature
	PurposePIVAuth = "piggy-piv_auth-v1" // PIV slot-9A authentication key
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
