package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/0/papi"
)

// testRecipientID is a well-formed §5.1 slot-9D recipient markl-id used as the
// receipt's recipient. The self_proof only needs it as a string the claim names,
// so a fixed valid-grammar value suffices.
const testRecipientID = "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"

// signRaw signs input (SHA-256) with priv and returns a markl-id of the given
// purpose over the raw 64-byte r‖s — the wire form ecdsaVerifyRaw checks.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, purpose string, input []byte) string {
	t.Helper()
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	id, err := markl.Build(purpose, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// receiptClient serves a /papi document publishing sshLines in
// piggy.ssh_authorized_keys and, when piggyIDs is non-nil, those ids at
// /papi/piggy-ids — the two surfaces VerifyReceipt checks the attester against.
func receiptClient(t *testing.T, sshLines, piggyIDs []string) *papi.Client {
	t.Helper()
	lines := make([]any, len(sshLines))
	for i, l := range sshLines {
		lines[i] = l
	}
	data, err := json.Marshal(map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": lines},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte(`,"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`))
	})
	if piggyIDs != nil {
		mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("# piggy-ids\n" + strings.Join(piggyIDs, "\n") + "\n"))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// buildReceipt assembles a fully valid receipt: newCard self-signs the 9D↔9A
// binding claim, and trusted attests the receipt's canonical bytes. The
// attestation is computed over the same CanonicalReceiptInput a verifier
// reconstructs (it strips the `attestation` member regardless of content).
func buildReceipt(t *testing.T, newCard, trusted marklSigner) []byte {
	t.Helper()
	claim := fmt.Sprintf("%s binds %s to %s", papi.ReceiptSchema, testRecipientID, newCard.keyID)
	r := papi.Receipt{
		Schema:    papi.ReceiptSchema,
		Domain:    "linenisgreat.com",
		GUID:      "DEADBEEF",
		Recipient: papi.ReceiptRecipient{ID: testRecipientID, Scheme: "piggy-recipient-v1"},
		SSH: papi.ReceiptSSH{
			ID: newCard.keyID, Line: newCard.sshLine,
			Purpose: "piggy-piv_auth-v1", KeyType: "ecdsa-sha2-nistp256",
		},
		SelfProof: papi.ReceiptSelfProof{
			Claim: claim,
			Sig:   signRaw(t, newCard.priv, markl.PurposeProofSig, []byte(claim)),
		},
	}
	noAtt, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	input, err := papi.CanonicalReceiptInput(noAtt)
	if err != nil {
		t.Fatal(err)
	}
	r.Attestation = papi.ReceiptAttestation{
		Key: trusted.keyID,
		Sig: signRaw(t, trusted.priv, markl.PurposeEnrollAtt, input),
	}
	full, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func TestVerifyReceiptValid(t *testing.T) {
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	raw := buildReceipt(t, newCard, trusted)
	c := receiptClient(t, []string{trusted.sshLine}, nil)

	res, err := VerifyReceipt(context.Background(), c, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("valid receipt rejected: %+v", res.Checks)
	}
}

func TestVerifyReceiptViaPiggyIDs(t *testing.T) {
	// The attester is published ONLY as a /papi/piggy-ids markl-id (no
	// ssh_authorized_keys), exercising the canonical string-match path.
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	raw := buildReceipt(t, newCard, trusted)
	c := receiptClient(t, nil, []string{trusted.keyID})

	res, err := VerifyReceipt(context.Background(), c, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("piggy-ids-published attester should verify: %+v", res.Checks)
	}
}

func TestVerifyReceiptUntrustedAttester(t *testing.T) {
	// The attesting key is not published on the domain → attestation fails, but
	// the offline self_proof still passes.
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	raw := buildReceipt(t, newCard, trusted)
	c := receiptClient(t, nil, nil)

	res, err := VerifyReceipt(context.Background(), c, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("receipt with an unpublished attester must fail")
	}
	if !res.Checks[0].OK {
		t.Errorf("self_proof should still pass: %+v", res.Checks[0])
	}
	if res.Checks[1].OK {
		t.Errorf("attestation should fail (unpublished attester): %+v", res.Checks[1])
	}
}

func TestVerifyReceiptTamperedField(t *testing.T) {
	// Mutating any signed field after attestation breaks the canonical bytes.
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	raw := buildReceipt(t, newCard, trusted)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["domain"] = json.RawMessage(`"evil.example"`)
	tampered, _ := json.Marshal(m)
	c := receiptClient(t, []string{trusted.sshLine}, nil)

	res, err := VerifyReceipt(context.Background(), c, tampered)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Checks[1].OK {
		t.Fatalf("tampered receipt must fail attestation: %+v", res.Checks)
	}
}

func TestVerifyReceiptForgedSelfProof(t *testing.T) {
	// self_proof signed by a key other than ssh.id must not verify.
	newCard, trusted, other := newMarklSigner(t), newMarklSigner(t), newMarklSigner(t)
	claim := fmt.Sprintf("%s binds %s to %s", papi.ReceiptSchema, testRecipientID, newCard.keyID)
	r := papi.Receipt{
		Schema:    papi.ReceiptSchema,
		Recipient: papi.ReceiptRecipient{ID: testRecipientID},
		SSH:       papi.ReceiptSSH{ID: newCard.keyID, Line: newCard.sshLine},
		SelfProof: papi.ReceiptSelfProof{
			Claim: claim,
			Sig:   signRaw(t, other.priv, markl.PurposeProofSig, []byte(claim)), // wrong signer
		},
	}
	noAtt, _ := json.Marshal(r)
	input, _ := papi.CanonicalReceiptInput(noAtt)
	r.Attestation = papi.ReceiptAttestation{
		Key: trusted.keyID,
		Sig: signRaw(t, trusted.priv, markl.PurposeEnrollAtt, input),
	}
	full, _ := json.Marshal(r)
	c := receiptClient(t, []string{trusted.sshLine}, nil)

	res, err := VerifyReceipt(context.Background(), c, full)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks[0].OK {
		t.Errorf("self_proof with the wrong signer must fail: %+v", res.Checks[0])
	}
}

func TestVerifyReceiptClaimMissingBinding(t *testing.T) {
	// A self_proof whose claim omits one slot id must fail even if the signature
	// is valid over that claim.
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	claim := "i hereby claim nothing in particular"
	r := papi.Receipt{
		Schema:    papi.ReceiptSchema,
		Recipient: papi.ReceiptRecipient{ID: testRecipientID},
		SSH:       papi.ReceiptSSH{ID: newCard.keyID, Line: newCard.sshLine},
		SelfProof: papi.ReceiptSelfProof{
			Claim: claim,
			Sig:   signRaw(t, newCard.priv, markl.PurposeProofSig, []byte(claim)),
		},
	}
	noAtt, _ := json.Marshal(r)
	input, _ := papi.CanonicalReceiptInput(noAtt)
	r.Attestation = papi.ReceiptAttestation{
		Key: trusted.keyID,
		Sig: signRaw(t, trusted.priv, markl.PurposeEnrollAtt, input),
	}
	full, _ := json.Marshal(r)
	c := receiptClient(t, []string{trusted.sshLine}, nil)

	res, err := VerifyReceipt(context.Background(), c, full)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks[0].OK {
		t.Errorf("claim not naming both slot ids must fail: %+v", res.Checks[0])
	}
}

func TestVerifyReceiptWrongSchema(t *testing.T) {
	c := receiptClient(t, nil, nil)
	_, err := VerifyReceipt(context.Background(), c, []byte(`{"schema":"bogus-v9"}`))
	if err == nil {
		t.Fatal("a non-papi-enroll-receipt-v1 schema should error")
	}
}

// TestVerifyReceiptWithPublishedIDs exercises the network-free entry point the
// WASM module (cmd/papi-verify-wasm) uses: the trusted slot-9A attester is
// supplied as a /papi/piggy-ids markl-id string rather than fetched.
func TestVerifyReceiptWithPublishedIDs(t *testing.T) {
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	raw := buildReceipt(t, newCard, trusted)

	// The caller may pass its whole piggy-ids list: the 9D recipient id is
	// skipped, the 9A attester id is matched. No network.
	res, err := VerifyReceiptWithPublishedIDs(raw, []string{testRecipientID, trusted.keyID})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("valid receipt rejected by keys-as-input verify: %+v", res.Checks)
	}

	// Without the attester id supplied, attestation fails but the offline
	// self_proof still holds — the same split the networked path produces.
	res, err = VerifyReceiptWithPublishedIDs(raw, []string{testRecipientID})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("receipt must fail when the attester key is not supplied")
	}
	if !res.Checks[0].OK {
		t.Errorf("self_proof should still pass offline: %+v", res.Checks[0])
	}
	if res.Checks[1].OK {
		t.Errorf("attestation should fail (attester not supplied): %+v", res.Checks[1])
	}
}

// TestVerifiedRecipients confirms the batch trust gate: a verified receipt yields
// its slot-9D recipient.id, an unattested one is excluded with a reason, and order
// is preserved.
func TestVerifiedRecipients(t *testing.T) {
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	good := buildReceipt(t, newCard, trusted)
	// A second receipt whose attester is NOT the published trusted key → excluded.
	stranger := newMarklSigner(t)
	bad := buildReceipt(t, newMarklSigner(t), stranger)
	c := receiptClient(t, []string{trusted.sshLine}, nil)

	got := VerifiedRecipients(context.Background(), c, [][]byte{good, bad})
	if len(got) != 2 {
		t.Fatalf("want 2 results, got %d", len(got))
	}
	if !got[0].Verified || got[0].RecipientID != testRecipientID {
		t.Errorf("result[0] should verify with recipient.id=%s, got %+v", testRecipientID, got[0])
	}
	if got[1].Verified || got[1].Reason == "" {
		t.Errorf("result[1] (unpublished attester) should be excluded with a reason, got %+v", got[1])
	}
}

// TestVerifyReceiptWithKeysTampered confirms the pure verify still binds every
// signed field: a key supplied directly verifies a clean receipt, and mutating a
// signed field breaks the canonical-bytes attestation.
func TestVerifyReceiptWithKeysTampered(t *testing.T) {
	newCard, trusted := newMarklSigner(t), newMarklSigner(t)
	raw := buildReceipt(t, newCard, trusted)
	trustedPub := &trusted.priv.PublicKey

	res, err := VerifyReceiptWithKeys(raw, []*ecdsa.PublicKey{trustedPub})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("valid receipt rejected by keys-as-input verify: %+v", res.Checks)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["domain"] = json.RawMessage(`"evil.example"`)
	tampered, _ := json.Marshal(m)
	res, err = VerifyReceiptWithKeys(tampered, []*ecdsa.PublicKey{trustedPub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Checks[1].OK {
		t.Fatalf("tampered receipt must fail attestation: %+v", res.Checks)
	}
}
