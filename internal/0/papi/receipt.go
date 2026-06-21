package papi

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// ReceiptSchema is the schema tag a papi-enroll-receipt-v1 carries (FDR-0001).
const ReceiptSchema = "papi-enroll-receipt-v1"

// Receipt is a card-enrollment receipt (FDR-0001): the identity material of a
// freshly-provisioned YubiKey plus the proofs that bind and authorize it.
// `papi enroll` produces it; `papi verify-receipt` and the site-side deploy gate
// consume it. The Recipient and SSH blocks use site-linenisgreat's papi.json
// field names verbatim so a deploy step can splice them into
// piggy.encryption_recipients[] / piggy.ssh_authorized_keys[] without reshaping.
// Lenient as the rest of the package: unknown members are ignored.
type Receipt struct {
	Schema       string             `json:"schema"`
	Domain       string             `json:"domain"`
	GUID         string             `json:"guid"`
	Created      int64              `json:"created"`
	Recipient    ReceiptRecipient   `json:"recipient"`
	SSH          ReceiptSSH         `json:"ssh"`
	AgeRecipient string             `json:"age_recipient,omitempty"`
	SelfProof    ReceiptSelfProof   `json:"self_proof"`
	Attestation  ReceiptAttestation `json:"attestation"`
}

// ReceiptRecipient is the new card's slot-9D entry, shaped for
// piggy.encryption_recipients[] (FDR-0001). ID is the slot-9D markl recipient
// (piggy-recipient-v1@pivy_ecdh_p256_pub-…), the §5.1 grammar the auth handshake
// trusts.
type ReceiptRecipient struct {
	Visibility string `json:"visibility,omitempty"`
	Label      string `json:"label,omitempty"`
	Scheme     string `json:"scheme,omitempty"`
	ID         string `json:"id"`
	Note       string `json:"note,omitempty"`
}

// ReceiptSSH is the new card's slot-9A entry, shaped for
// piggy.ssh_authorized_keys[] (FDR-0001). ID is the slot-9A markl auth key
// (piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…); Line is the literal OpenSSH
// authorized_keys line the site serves verbatim at /papi/ssh-authorized-keys.
type ReceiptSSH struct {
	Visibility string `json:"visibility,omitempty"`
	Label      string `json:"label,omitempty"`
	ID         string `json:"id"`
	Purpose    string `json:"purpose,omitempty"`
	KeyType    string `json:"key_type,omitempty"`
	Line       string `json:"line"`
}

// ReceiptSelfProof is the new card binding its own two slots: a §9.3
// papi-proof-sig-v1 signature, made by the new card's slot-9A key, over the
// Claim string — which names both the 9D recipient id and the 9A key id, proving
// they are the same card/holder.
type ReceiptSelfProof struct {
	Claim string `json:"claim"`
	Sig   string `json:"sig"`
}

// ReceiptAttestation is the trust upgrade (FDR-0001): an already-bootstrapped,
// already-published slot-9A key (Key, a piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub
// markl-id) signs the receipt's canonical bytes (§10.2 strip-and-canonicalize,
// applied to the receipt) under the papi-enroll-att-v1 purpose, so the deploy
// side publishes the new key only when an existing trusted card vouches for it.
type ReceiptAttestation struct {
	Key     string `json:"key"`
	Sig     string `json:"sig"`
	Created int64  `json:"created,omitempty"`
}

// CanonicalReceiptInput reconstructs the bytes the receipt attestation signs
// (FDR-0001): the receipt JSON with the `attestation` member removed, serialized
// by RFC 8785 JCS. Producer and verifier both compute it this way — strip the
// `attestation` key, then canonicalize — so they agree on the bytes regardless
// of key order, mirroring the §10.2 document-signature discipline applied to the
// receipt rather than the served document.
func CanonicalReceiptInput(raw []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("receipt is not a JSON object: %w", err)
	}
	delete(obj, "attestation")
	reser, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(reser)
}
