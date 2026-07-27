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
package markl

import (
	"fmt"

	piggymarkl "code.linenisgreat.com/piggy/go/pkgs/markl"
	_ "code.linenisgreat.com/piggy/go/pkgs/markl_registrations"
)

// Known format identifiers papi consumes (RFC 0011 §5).
const (
	FormatEcdsaP256Sig        = piggymarkl.FormatIdEcdsaP256Sig
	FormatSSHEcdsaNistp256Pub = piggymarkl.FormatIdSshEcdsaNistp256Pub
)

// Known purpose identifiers papi consumes (RFC 0011 §6.1).
// PurposeDocSig, PurposeProofSig, and PurposePIVAuth are jointly registered
// in piggy's canonical registry; the remaining three are papi-only purposes
// that piggy carries opaquely (madder#255 / RFC 0011 §4.3).
const (
	PurposeDocSig        = piggymarkl.PurposePapiDocSigV1   // PAPI document signature (§10)
	PurposeProofSig      = piggymarkl.PurposePapiProofSigV1 // PAPI identity-proof claim signature (§9.3)
	PurposePIVAuth       = piggymarkl.PurposePiggyPivAuthV1 // PIV slot-9A authentication key
	PurposeEnrollAtt     = "papi-enroll-att-v1"             // PAPI enrollment-receipt attestation (FDR-0001)
	PurposeAuthSig       = "papi-auth-sig-v1"               // PAPI sign-challenge auth signature (§5.2)
	PurposePigpenSelfSig = "papi-pigpen-self-sig-v1"        // pigpen document self-signature (RFC-0001 §14.2, papi#54)
)

// ID is a parsed markl-id.
type ID struct {
	Purpose string // the `purpose` decoration, or "" when absent
	Format  string // the blech32 human-readable part (the format identifier)
	Payload []byte // the decoded payload bytes
	Raw     string // the original wire string
}

// Parse decodes a markl-id wire string via piggy's canonical RFC 0011 implementation.
func Parse(s string) (ID, error) {
	if s == "" {
		return ID{}, fmt.Errorf("markl: empty id")
	}
	var pig piggymarkl.Id
	if err := pig.Set(s); err != nil {
		return ID{}, err
	}
	return ID{
		Purpose: pig.GetPurposeId(),
		Format:  pig.GetMarklFormat().GetMarklFormatId(),
		Payload: pig.GetBytes(),
		Raw:     s,
	}, nil
}

// Build encodes purpose, format, and payload as a markl-id wire string.
// A registered format whose payload is the wrong size is rejected.
func Build(purpose, format string, payload []byte) (string, error) {
	var pig piggymarkl.Id
	if err := pig.SetMarklId(format, payload); err != nil {
		return "", err
	}
	if purpose != "" {
		if err := pig.SetPurposeId(purpose); err != nil {
			return "", err
		}
	}
	return pig.StringWithFormat(), nil
}
