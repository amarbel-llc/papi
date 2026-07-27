// Package markl parses and builds "markl-id" self-describing identifier strings
// as specified by RFC 0011 (formerly madder RFC-0002): an OPTIONAL `purpose@`
// decoration followed by a blech32-encoded `format-payload` body. papi uses
// this to read the `signatures[]` markl-ids of RFC-0001 §10 (Amendment 9) —
// the document signature `papi-doc-sig-v1@ecdsa_p256_sig-…` and its verifying
// key `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…`.
//
// This package is a thin adapter over piggy's shared markl Go library
// (code.linenisgreat.com/piggy/go/pkgs/markl), fulfilling papi#10. The
// exported surface (Parse, Build, ID, the format/purpose constants) is
// identical to the former in-house port, so all call sites remain unchanged.
//
// For GOOS=wasip1, the piggy adapter is unavailable (purse-first/libs/dewey
// has no WASM stub for setUserChanges). markl_wasm.go provides a self-contained
// implementation using inline blech32 derived from piggy's own algorithm.
package markl

// Known format identifiers papi consumes (RFC 0011 §5).
// These are wire-format strings defined by the RFC; they must stay in sync with
// piggymarkl.FormatIdEcdsaP256Sig and piggymarkl.FormatIdSshEcdsaNistp256Pub.
const (
	FormatEcdsaP256Sig        = "ecdsa_p256_sig"
	FormatSSHEcdsaNistp256Pub = "ssh_ecdsa_nistp256_pub"
)

// Known purpose identifiers papi consumes (RFC 0011 §6.1).
// PurposeDocSig, PurposeProofSig, and PurposePIVAuth are jointly registered
// in piggy's canonical registry; the remaining three are papi-only purposes
// that piggy carries opaquely (madder#255 / RFC 0011 §4.3).
const (
	PurposeDocSig        = "papi-doc-sig-v1"         // PAPI document signature (§10)
	PurposeProofSig      = "papi-proof-sig-v1"       // PAPI identity-proof claim signature (§9.3)
	PurposePIVAuth       = "piggy-piv_auth-v1"       // PIV slot-9A authentication key
	PurposeEnrollAtt     = "papi-enroll-att-v1"      // PAPI enrollment-receipt attestation (FDR-0001)
	PurposeAuthSig       = "papi-auth-sig-v1"        // PAPI sign-challenge auth signature (§5.2)
	PurposePigpenSelfSig = "papi-pigpen-self-sig-v1" // pigpen document self-signature (RFC-0001 §14.2, papi#54)
)

// ID is a parsed markl-id.
type ID struct {
	Purpose string // the `purpose` decoration, or "" when absent
	Format  string // the blech32 human-readable part (the format identifier)
	Payload []byte // the decoded payload bytes
	Raw     string // the original wire string
}
