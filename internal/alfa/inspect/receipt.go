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
// passed, and a human-readable detail. The json tags give the WASM module
// (cmd/papi-verify-wasm) a stable lowercase wire shape.
type ReceiptCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// ReceiptResult is the verdict over a whole enrollment receipt: every check plus
// the conjunctive OK (true iff every check passed).
type ReceiptResult struct {
	Checks []ReceiptCheck `json:"checks"`
	OK     bool           `json:"ok"`
}

// newReceiptResult bundles checks into a ReceiptResult with the conjunctive OK
// (true iff every check passed).
func newReceiptResult(checks ...ReceiptCheck) ReceiptResult {
	res := ReceiptResult{Checks: checks, OK: true}
	for _, ck := range checks {
		if !ck.OK {
			res.OK = false
		}
	}
	return res
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
//
// VerifyReceipt is the networked wrapper: it fetches the domain's published
// slot-9A keys, then delegates the actual crypto to VerifyReceiptWithKeys. Hosts
// without sockets (the WASM module, a php-wasm site that already holds its own
// /papi/piggy-ids) call VerifyReceiptWithKeys / VerifyReceiptWithPublishedIDs
// directly instead.
func VerifyReceipt(ctx context.Context, c *papi.Client, raw []byte) (ReceiptResult, error) {
	var r papi.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return ReceiptResult{}, fmt.Errorf("receipt is not valid JSON: %w", err)
	}
	if r.Schema != papi.ReceiptSchema {
		return ReceiptResult{}, fmt.Errorf("receipt schema %q, want %q", r.Schema, papi.ReceiptSchema)
	}

	self := verifyReceiptSelfProof(r)
	doc, _, _, err := c.Document(ctx)
	if err != nil {
		return newReceiptResult(self, ReceiptCheck{"attestation", false, "GET /papi failed: " + err.Error()}), nil
	}
	att := verifyReceiptAttestationWithKeys(r, raw, publishedSigningKeys(ctx, c, doc))
	return newReceiptResult(self, att), nil
}

// VerifyReceiptWithKeys is the network-free core of VerifyReceipt: it checks both
// the offline self_proof and the attestation against an explicitly-supplied set
// of trusted slot-9A keys (the domain's already-published signing keys). It does
// no I/O, so it compiles and runs under WASI/wasip1 (cmd/papi-verify-wasm).
func VerifyReceiptWithKeys(raw []byte, published []*ecdsa.PublicKey) (ReceiptResult, error) {
	var r papi.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return ReceiptResult{}, fmt.Errorf("receipt is not valid JSON: %w", err)
	}
	if r.Schema != papi.ReceiptSchema {
		return ReceiptResult{}, fmt.Errorf("receipt schema %q, want %q", r.Schema, papi.ReceiptSchema)
	}
	return newReceiptResult(
		verifyReceiptSelfProof(r),
		verifyReceiptAttestationWithKeys(r, raw, published),
	), nil
}

// VerifyReceiptWithPublishedIDs is VerifyReceiptWithKeys taking the trusted
// slot-9A keys as the markl-id strings a domain publishes at /papi/piggy-ids
// (e.g. "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…"). Each id is parsed to a
// P-256 point; ids that are not slot-9A signing keys (e.g. the slot-9D
// piggy-recipient-v1 entries in the same list) are skipped, so the caller can
// pass its whole piggy-ids set verbatim.
func VerifyReceiptWithPublishedIDs(raw []byte, publishedIDs []string) (ReceiptResult, error) {
	published := make([]*ecdsa.PublicKey, 0, len(publishedIDs))
	for _, id := range publishedIDs {
		keyID, err := markl.Parse(id)
		if err != nil || keyID.Purpose != markl.PurposePIVAuth || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
			continue
		}
		pub, err := p256FromCompressed(keyID.Payload)
		if err != nil {
			continue
		}
		published = append(published, pub)
	}
	return VerifyReceiptWithKeys(raw, published)
}

// RecipientResult is one receipt's outcome in VerifiedRecipients: a verified
// receipt carries its slot-9D recipient id (recipient.id, the encryption recipient
// a PIV-gated encrypt may trust); a failing one carries the exclusion reason.
type RecipientResult struct {
	RecipientID string // recipient.id — set iff Verified
	Verified    bool
	Reason      string // why excluded — set iff !Verified
}

// VerifiedRecipients verifies each receipt against domain c (the same self_proof +
// attestation checks as VerifyReceipt) and returns, in input order, the per-receipt
// outcome. It is the trust gate of the FDR-0002 composition: a card's slot-9D
// encryption recipient is yielded only when a trusted card has attested its
// enrollment — the verified set a downstream encryptor (linenisgreat's .pivy-ids)
// may be built from. It never errors as a batch; a bad receipt is one excluded
// RecipientResult, so one failure does not drop the rest.
func VerifiedRecipients(ctx context.Context, c *papi.Client, receipts [][]byte) []RecipientResult {
	out := make([]RecipientResult, 0, len(receipts))
	for _, raw := range receipts {
		res, err := VerifyReceipt(ctx, c, raw)
		switch {
		case err != nil:
			out = append(out, RecipientResult{Reason: err.Error()})
			continue
		case !res.OK:
			out = append(out, RecipientResult{Reason: receiptFailureReason(res)})
			continue
		}
		var r papi.Receipt
		if err := json.Unmarshal(raw, &r); err != nil {
			out = append(out, RecipientResult{Reason: err.Error()})
			continue
		}
		if r.Recipient.ID == "" {
			out = append(out, RecipientResult{Reason: "verified but carries no recipient.id"})
			continue
		}
		out = append(out, RecipientResult{RecipientID: r.Recipient.ID, Verified: true})
	}
	return out
}

// receiptFailureReason summarizes the failing checks of a non-OK ReceiptResult into
// one line ("name: detail; …") for the exclusion reason.
func receiptFailureReason(res ReceiptResult) string {
	var failed []string
	for _, ck := range res.Checks {
		if !ck.OK {
			failed = append(failed, ck.Name+": "+ck.Detail)
		}
	}
	if len(failed) == 0 {
		return "verification failed"
	}
	return strings.Join(failed, "; ")
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

// verifyReceiptAttestationWithKeys checks that an already-trusted card authorized
// the new key: attestation.key (a slot-9A markl-id) MUST be present in `published`
// (the domain's already-trusted slot-9A keys), and attestation.sig (a
// papi-enroll-att-v1 markl-id) MUST verify over the receipt's canonical bytes
// against that key. It takes `published` as input rather than fetching it, so it
// is pure (the WASM/php-wasm path supplies the keys from the site's own papi.json).
func verifyReceiptAttestationWithKeys(r papi.Receipt, raw []byte, published []*ecdsa.PublicKey) ReceiptCheck {
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

	if !pubKeyPublished(trusted, published) {
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
