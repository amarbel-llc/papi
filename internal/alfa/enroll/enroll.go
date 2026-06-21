// Package enroll is the producing side of the new-YubiKey enrollment feature
// (FDR-0001): it assembles and signs a papi-enroll-receipt-v1 from a freshly
// provisioned card's identity material. It is deliberately downstream of piggy
// and papi-agnostic at the seam — the card primitives (generate, read back, sign
// bytes) sit behind the Signer interface, so the receipt assembly here is pure
// and unit-testable without hardware, while the real pivy-tool/piggy exec adapter
// implements Signer. papi owns everything papi-shaped (the claim, the papi-*
// markl purposes, the §10.2 canonicalization); piggy only signs bytes.
package enroll

import (
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

// Signer signs message bytes with the slot-9A key of the card identified by guid,
// returning the raw 64-byte r‖s ECDSA P-256 signature — the markl ecdsa_p256_sig
// payload (RFC-0001 §10.4: "no DER, no SSH-wire framing"). The card hashes
// SHA-256 internally, so msg is the bare bytes to sign, NOT a pre-hash. The
// production implementation wraps `pivy-tool -g <guid> sign 9a` (which emits
// ASN.1 DER) and reframes via DERToRawRS; a future `piggy sign-bytes` returns raw
// r‖s directly. This is the one piggy primitive the producing side needs.
type Signer interface {
	SignSlot9A(ctx context.Context, guid string, msg []byte) (rs []byte, err error)
}

// Card is the slot-9D + slot-9A identity material read off a provisioned card
// (the read-back primitive's result), keyed by the card GUID.
type Card struct {
	GUID         string // PIV card GUID (hex)
	RecipientID  string // slot-9D markl recipient: piggy-recipient-v1@pivy_ecdh_p256_pub-…
	SSHID        string // slot-9A markl auth key: piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…
	SSHLine      string // slot-9A OpenSSH authorized_keys line (served verbatim)
	AgeRecipient string // slot-9D age recipient: age1piggy… (convenience)
	CN           string // the card's common name (cn=)
}

// BuildReceipt assembles and signs a papi-enroll-receipt-v1 for newCard, targeting
// domain, attested by an already-bootstrapped trusted card. It signs the
// self_proof with newCard's slot-9A (binding its own 9D recipient to its 9A key)
// and the attestation with the trusted card's slot-9A (over the receipt's
// canonical bytes), driving both signatures through signer. trustedGUID selects
// the trusted card for signing; trustedKeyID is that card's published slot-9A
// markl-id, recorded as attestation.key. created is the unix timestamp (passed in
// for determinism). The returned bytes are the receipt JSON ready to write.
func BuildReceipt(ctx context.Context, signer Signer, newCard Card, domain, trustedGUID, trustedKeyID string, created int64) ([]byte, error) {
	if newCard.RecipientID == "" || newCard.SSHID == "" {
		return nil, fmt.Errorf("new card is missing its slot-9D recipient or slot-9A id")
	}

	claim := bindingClaim(newCard.RecipientID, newCard.SSHID)
	selfSig, err := signMarkl(ctx, signer, newCard.GUID, []byte(claim), markl.PurposeProofSig)
	if err != nil {
		return nil, fmt.Errorf("self_proof (new card slot-9A): %w", err)
	}

	g8 := guid8(newCard.GUID)
	r := papi.Receipt{
		Schema:  papi.ReceiptSchema,
		Domain:  domain,
		GUID:    newCard.GUID,
		Created: created,
		Recipient: papi.ReceiptRecipient{
			Visibility: "public",
			Label:      "yubikey-9d-" + g8,
			Scheme:     "piggy-recipient-v1",
			ID:         newCard.RecipientID,
		},
		SSH: papi.ReceiptSSH{
			Visibility: "public",
			Label:      "yubikey-9a-" + g8,
			ID:         newCard.SSHID,
			Purpose:    markl.PurposePIVAuth,
			KeyType:    "ecdsa-sha2-nistp256",
			Line:       newCard.SSHLine,
		},
		AgeRecipient: newCard.AgeRecipient,
		SelfProof:    papi.ReceiptSelfProof{Claim: claim, Sig: selfSig},
	}

	// The attestation covers the receipt with its own member stripped (§10.2
	// discipline). Marshal the receipt-so-far (attestation still zero), compute
	// the canonical input, sign, then fill the attestation in — the verifier
	// reconstructs the identical bytes by stripping whatever attestation it reads.
	noAtt, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	input, err := papi.CanonicalReceiptInput(noAtt)
	if err != nil {
		return nil, err
	}
	attSig, err := signMarkl(ctx, signer, trustedGUID, input, markl.PurposeEnrollAtt)
	if err != nil {
		return nil, fmt.Errorf("attestation (trusted card slot-9A): %w", err)
	}
	r.Attestation = papi.ReceiptAttestation{Key: trustedKeyID, Sig: attSig, Created: created}

	return json.MarshalIndent(r, "", "  ")
}

// bindingClaim is the self_proof claim string: it names both of the new card's
// slot ids so a signature over it proves the 9D recipient and 9A key are the same
// card. The verifier (inspect.VerifyReceipt) requires both ids to appear here.
func bindingClaim(recipientID, sshID string) string {
	return fmt.Sprintf("%s binds %s to %s", papi.ReceiptSchema, recipientID, sshID)
}

// signMarkl signs msg with the slot-9A key of card guid and wraps the raw r‖s in a
// markl-id of the given papi purpose under the ecdsa_p256_sig format.
func signMarkl(ctx context.Context, signer Signer, guid string, msg []byte, purpose string) (string, error) {
	rs, err := signer.SignSlot9A(ctx, guid, msg)
	if err != nil {
		return "", err
	}
	id, err := markl.Build(purpose, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		return "", fmt.Errorf("wrap signature as %s markl-id: %w", purpose, err)
	}
	return id, nil
}

// guid8 is the lowercased first 8 hex characters of a card GUID, used to label
// the receipt's recipient/ssh entries. A shorter GUID is used whole.
func guid8(guid string) string {
	g := strings.ToLower(strings.TrimSpace(guid))
	if len(g) > 8 {
		return g[:8]
	}
	return g
}

// DERToRawRS converts an ASN.1 DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER
// s }) to the raw 64-byte r‖s the markl ecdsa_p256_sig format wants — r and s each
// left-padded to 32 bytes. `pivy-tool sign 9a` emits DER, so the pivy-tool Signer
// adapter calls this; a `piggy sign-bytes` returning raw r‖s would not need it.
func DERToRawRS(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("parse DER ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("parse DER ECDSA signature: %d trailing bytes", len(rest))
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() < 0 || sig.S.Sign() < 0 {
		return nil, fmt.Errorf("DER ECDSA signature has a missing or negative r/s")
	}
	order := elliptic.P256().Params().N
	if sig.R.Cmp(order) >= 0 || sig.S.Cmp(order) >= 0 {
		return nil, fmt.Errorf("DER ECDSA signature r/s out of range for P-256")
	}
	rs := make([]byte, 64)
	sig.R.FillBytes(rs[:32])
	sig.S.FillBytes(rs[32:])
	return rs, nil
}
