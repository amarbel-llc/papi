package inspect

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

// ReceiptCheck is one verdict line from VerifyReceipt: a named check, whether it
// passed, and a human-readable detail.
type ReceiptCheck struct {
	Name   string
	OK     bool
	Detail string
}

// ReceiptResult is the verdict over a whole enrollment receipt: every check plus
// the conjunctive OK (true iff every check passed).
type ReceiptResult struct {
	Checks []ReceiptCheck
	OK     bool
}

// VerifyReceipt verifies a papi-enroll-receipt-v1 (FDR-0001) against the live
// domain c. Two checks, both of which MUST pass:
//
//   - self_proof — the new card binds its own two slots: a papi-proof-sig-v1
//     signature (§9.3) over a claim naming both the slot-9D recipient id and the
//     slot-9A key id, verified against the receipt's OWN slot-9A key.
//   - attestation — an already-trusted card authorizes publication: a
//     papi-enroll-att-v1 signature over the receipt's canonical bytes
//     (CanonicalReceiptInput), verified against a slot-9A key ALREADY published
//     on the domain's /papi/piggy-ids or ssh_authorized_keys[].
//
// The self_proof is verifiable offline; the attestation needs the live domain to
// confirm the attesting key is already trusted. The result is conjunctive.
func VerifyReceipt(ctx context.Context, c *papi.Client, raw []byte) (ReceiptResult, error) {
	var r papi.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return ReceiptResult{}, fmt.Errorf("receipt is not valid JSON: %w", err)
	}
	if r.Schema != papi.ReceiptSchema {
		return ReceiptResult{}, fmt.Errorf("receipt schema %q, want %q", r.Schema, papi.ReceiptSchema)
	}

	res := ReceiptResult{Checks: []ReceiptCheck{
		verifyReceiptSelfProof(r),
		verifyReceiptAttestation(ctx, c, r, raw),
	}}
	res.OK = true
	for _, ck := range res.Checks {
		if !ck.OK {
			res.OK = false
		}
	}
	return res, nil
}

// verifyReceiptSelfProof checks the new card's slot-9D ↔ slot-9A binding: the
// claim MUST name both slot ids, and self_proof.sig (a papi-proof-sig-v1 markl-id)
// MUST verify over the claim bytes against the new card's slot-9A key (ssh.id).
func verifyReceiptSelfProof(r papi.Receipt) ReceiptCheck {
	const name = "self_proof"
	keyID, err := markl.Parse(r.SSH.ID)
	if err != nil || keyID.Purpose != markl.PurposePIVAuth || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
		return ReceiptCheck{name, false, "ssh.id is not a piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub markl-id"}
	}
	pub, err := p256FromCompressed(keyID.Payload)
	if err != nil {
		return ReceiptCheck{name, false, "ssh.id is not a valid P-256 point: " + err.Error()}
	}
	sigID, err := markl.Parse(r.SelfProof.Sig)
	if err != nil || sigID.Purpose != markl.PurposeProofSig || sigID.Format != markl.FormatEcdsaP256Sig {
		return ReceiptCheck{name, false, "self_proof.sig is not a papi-proof-sig-v1@ecdsa_p256_sig markl-id"}
	}
	if r.Recipient.ID == "" || !strings.Contains(r.SelfProof.Claim, r.Recipient.ID) ||
		!strings.Contains(r.SelfProof.Claim, r.SSH.ID) {
		return ReceiptCheck{name, false, "self_proof.claim does not name both recipient.id (9D) and ssh.id (9A)"}
	}
	if !ecdsaVerifyRaw(pub, []byte(r.SelfProof.Claim), sigID.Payload) {
		return ReceiptCheck{name, false, "signature does not verify against the new card's slot-9A key"}
	}
	return ReceiptCheck{name, true, "new card's slot-9A key signs the 9D↔9A binding claim"}
}

// verifyReceiptAttestation checks that an already-trusted card authorized the new
// key: attestation.key (a slot-9A markl-id) MUST already be published on the live
// domain, and attestation.sig (a papi-enroll-att-v1 markl-id) MUST verify over the
// receipt's canonical bytes against that key.
func verifyReceiptAttestation(ctx context.Context, c *papi.Client, r papi.Receipt, raw []byte) ReceiptCheck {
	const name = "attestation"
	keyID, err := markl.Parse(r.Attestation.Key)
	if err != nil || keyID.Purpose != markl.PurposePIVAuth || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
		return ReceiptCheck{name, false, "attestation.key is not a piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub markl-id"}
	}
	trusted, err := p256FromCompressed(keyID.Payload)
	if err != nil {
		return ReceiptCheck{name, false, "attestation.key is not a valid P-256 point: " + err.Error()}
	}
	sigID, err := markl.Parse(r.Attestation.Sig)
	if err != nil || sigID.Purpose != markl.PurposeEnrollAtt || sigID.Format != markl.FormatEcdsaP256Sig {
		return ReceiptCheck{name, false, "attestation.sig is not a papi-enroll-att-v1@ecdsa_p256_sig markl-id"}
	}

	doc, _, _, err := c.Document(ctx)
	if err != nil {
		return ReceiptCheck{name, false, "GET /papi failed: " + err.Error()}
	}
	if !pubKeyPublished(trusted, publishedSigningKeys(ctx, c, doc)) {
		return ReceiptCheck{name, false,
			"attestation.key is not published on the domain (/papi/piggy-ids or ssh_authorized_keys) — no trusted attester"}
	}

	input, err := papi.CanonicalReceiptInput(raw)
	if err != nil {
		return ReceiptCheck{name, false, "canonicalize receipt: " + err.Error()}
	}
	if !ecdsaVerifyRaw(trusted, input, sigID.Payload) {
		return ReceiptCheck{name, false, "signature does not verify over the receipt's canonical bytes"}
	}
	return ReceiptCheck{name, true, "an already-published slot-9A key attests the receipt"}
}

// pubKeyPublished reports whether k matches any of the domain's published slot-9A
// keys by P-256 point (the same key set §10 verifies signatures against).
func pubKeyPublished(k *ecdsa.PublicKey, published []*ecdsa.PublicKey) bool {
	for _, p := range published {
		if p.X.Cmp(k.X) == 0 && p.Y.Cmp(k.Y) == 0 {
			return true
		}
	}
	return false
}
