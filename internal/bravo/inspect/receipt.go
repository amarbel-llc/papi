package inspect

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/0/webauthn"
	"code.linenisgreat.com/papi/internal/alfa/papi"
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
	r, err := parseReceipt(raw)
	if err != nil {
		return ReceiptResult{}, err
	}
	doc, _, _, err := c.Document(ctx)
	if err != nil {
		return newReceiptResult(append(offlineReceiptChecks(r),
			ReceiptCheck{"attestation", false, "GET /papi failed: " + err.Error()})...), nil
	}
	att := verifyReceiptAttestationWithKeys(r, raw, publishedSigningKeys(ctx, c, doc))
	return newReceiptResult(append(offlineReceiptChecks(r), att)...), nil
}

// parseReceipt decodes a receipt and checks its schema tag: v1, or v2 (which
// adds the webauthn member).
func parseReceipt(raw []byte) (papi.Receipt, error) {
	var r papi.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return papi.Receipt{}, fmt.Errorf("receipt is not valid JSON: %w", err)
	}
	if r.Schema != papi.ReceiptSchema && r.Schema != papi.ReceiptSchemaV2 {
		return papi.Receipt{}, fmt.Errorf("receipt schema %q, want %q or %q", r.Schema, papi.ReceiptSchema, papi.ReceiptSchemaV2)
	}
	return r, nil
}

// offlineReceiptChecks are the checks that need no domain: the 9D↔9A self_proof
// and, on a v2 receipt, the webauthn credential and its binding.
func offlineReceiptChecks(r papi.Receipt) []ReceiptCheck {
	checks := []ReceiptCheck{verifyReceiptSelfProof(r)}
	switch {
	case r.Schema == papi.ReceiptSchemaV2:
		checks = append(checks, verifyReceiptWebAuthn(r))
	case r.WebAuthn != nil:
		checks = append(checks, ReceiptCheck{"webauthn", false, "a " + papi.ReceiptSchema + " receipt must not carry a webauthn member"})
	}
	return checks
}

// VerifyReceiptWithKeys is the network-free core of VerifyReceipt: it checks both
// the offline self_proof and the attestation against an explicitly-supplied set
// of trusted slot-9A keys (the domain's already-published signing keys). It does
// no I/O, so it compiles and runs under WASI/wasip1 (cmd/papi-verify-wasm).
func VerifyReceiptWithKeys(raw []byte, published []*ecdsa.PublicKey) (ReceiptResult, error) {
	r, err := parseReceipt(raw)
	if err != nil {
		return ReceiptResult{}, err
	}
	return newReceiptResult(append(offlineReceiptChecks(r), verifyReceiptAttestationWithKeys(r, raw, published))...), nil
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

// verifyReceiptWebAuthn checks a v2 receipt's webauthn member offline: the
// registration evidence parses under webauthn.EnrollPolicy and re-derives
// the published credential id, COSE key, AAGUID and credProtect; the client-data
// hash is the one papi chooses for this card; and the binding claim is signed by
// the new card's own slot-9A key. The FIDO attestation certificate is not
// verified (it proves the vendor and model, not that this is the same card).
func verifyReceiptWebAuthn(r papi.Receipt) ReceiptCheck {
	const name = "webauthn"
	fail := func(detail string) ReceiptCheck { return ReceiptCheck{name, false, detail} }
	w := r.WebAuthn
	switch {
	case w == nil:
		return fail("a " + papi.ReceiptSchemaV2 + " receipt must carry a webauthn member")
	case !strings.EqualFold(w.GUID, r.GUID):
		return fail("webauthn.guid does not match the receipt's guid")
	case w.RPID == "":
		return fail("webauthn.rp_id is empty")
	case w.Alg != -7:
		return fail(fmt.Sprintf("webauthn.alg is %d, want -7 (ES256)", w.Alg))
	case w.Discoverable:
		return fail("webauthn credential must be non-discoverable")
	case w.CredProtect != webauthn.EnrollPolicy.RequireCredProtect:
		return fail(fmt.Sprintf("webauthn.cred_protect is %d, want %d", w.CredProtect, webauthn.EnrollPolicy.RequireCredProtect))
	}

	authData, err := base64.RawURLEncoding.DecodeString(w.Registration.AuthData)
	if err != nil {
		return fail("webauthn.registration.auth_data is not base64url: " + err.Error())
	}
	reg, err := webauthn.NewRegistration(w.Registration.Fmt, authData)
	if err != nil {
		return fail("webauthn.registration does not parse: " + err.Error())
	}
	cred, err := reg.Credential(w.RPID, webauthn.EnrollPolicy)
	if err != nil {
		return fail("webauthn.registration fails the enroll policy: " + err.Error())
	}
	att := reg.AuthData.Attested
	switch {
	case base64.RawURLEncoding.EncodeToString(cred.ID) != w.CredentialID:
		return fail("webauthn.credential_id does not match the registration's authenticator data")
	case base64.RawURLEncoding.EncodeToString(att.COSEKey) != w.PublicKey:
		return fail("webauthn.public_key does not match the registration's authenticator data")
	case hex.EncodeToString(att.AAGUID[:]) != strings.ToLower(w.AAGUID):
		return fail("webauthn.aaguid does not match the registration's authenticator data")
	case reg.AuthData.CredProtect != w.CredProtect:
		return fail("webauthn.cred_protect does not match the registration's authenticator data")
	}
	if w.Registration.ClientDataHash != base64.RawURLEncoding.EncodeToString(papi.WebAuthnClientDataHash(w.RPID, r.GUID, r.SSH.ID)) {
		return fail("webauthn.registration.client_data_hash is not the hash papi derives for this card")
	}

	keyID, err := markl.Parse(r.SSH.ID)
	if err != nil || keyID.Purpose != markl.PurposePIVAuth || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
		return fail("ssh.id is not a piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub markl-id")
	}
	pub, err := p256FromCompressed(keyID.Payload)
	if err != nil {
		return fail("ssh.id is not a valid P-256 point: " + err.Error())
	}
	if w.Binding.Claim != papi.WebAuthnBindingClaim(w.RPID, w.CredentialID, att.COSEKey, r.SSH.ID) {
		return fail("webauthn.binding.claim does not name this credential and ssh.id")
	}
	sigID, err := markl.Parse(w.Binding.Sig)
	if err != nil || sigID.Purpose != markl.PurposeProofSig || sigID.Format != markl.FormatEcdsaP256Sig {
		return fail("webauthn.binding.sig is not a papi-proof-sig-v1@ecdsa_p256_sig markl-id")
	}
	if !ecdsaVerifyRaw(pub, []byte(w.Binding.Claim), sigID.Payload) {
		return fail("webauthn.binding.sig does not verify against the new card's slot-9A key")
	}
	return ReceiptCheck{name, true, "the new card's slot-9A key binds a credProtect-2, device-bound ES256 credential for " + w.RPID}
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
		return ReceiptCheck{
			name, false,
			"attestation.key is not published on the domain (/papi/piggy-ids or ssh_authorized_keys) — no trusted attester",
		}
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
