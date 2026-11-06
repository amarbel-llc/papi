package papi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// ReceiptSchema is the schema tag a papi-enroll-receipt-v1 carries (FDR-0001).
const ReceiptSchema = "papi-enroll-receipt-v1"

// ReceiptSchemaV2 is the schema tag of a receipt that also carries the card's
// WebAuthn credential (the webauthn member). Its v1 members are unchanged; a v1
// verifier rejects it on the tag rather than misreading it (amarbel-llc/circus#414).
const ReceiptSchemaV2 = "papi-enroll-receipt-v2"

// Receipt is a card-enrollment receipt (FDR-0001): the identity material of a
// freshly-provisioned YubiKey plus the proofs that bind and authorize it.
// `papi enroll` produces it; `papi verify-receipt` and the site-side deploy gate
// consume it. The Recipient and SSH blocks use site-linenisgreat's papi.json
// field names verbatim so a deploy step can splice them into
// piggy.encryption_recipients[] / piggy.ssh_authorized_keys[] without reshaping.
// Lenient as the rest of the package: unknown members are ignored.
type Receipt struct {
	Schema       string           `json:"schema"`
	Domain       string           `json:"domain"`
	GUID         string           `json:"guid"`
	Created      int64            `json:"created"`
	Recipient    ReceiptRecipient `json:"recipient"`
	SSH          ReceiptSSH       `json:"ssh"`
	AgeRecipient string           `json:"age_recipient,omitempty"`
	SelfProof    ReceiptSelfProof `json:"self_proof"`
	// WebAuthn is the card's FIDO2 credential (v2 only), shaped for
	// piggy.webauthn_credentials[]. The attestation covers it like any other member.
	WebAuthn    *ReceiptWebAuthn   `json:"webauthn,omitempty"`
	Attestation ReceiptAttestation `json:"attestation"`
}

// ReceiptWebAuthn is a v2 receipt's WebAuthn credential: one ES256,
// non-discoverable credential made on the same card at credProtect level 2, so
// one credential serves a touch-only tier and a touch-plus-PIN tier. Binding is
// the new card's slot-9A signature naming the credential and the 9A key;
// Registration is the authenticator's output, from which a verifier re-derives
// CredentialID, PublicKey, AAGUID and CredProtect.
type ReceiptWebAuthn struct {
	Visibility   string                      `json:"visibility,omitempty"`
	Label        string                      `json:"label,omitempty"`
	GUID         string                      `json:"guid"`          // the PIV GUID this credential is bound to
	RPID         string                      `json:"rp_id"`         // e.g. linenisgreat.com
	CredentialID string                      `json:"credential_id"` // base64url, no padding
	PublicKey    string                      `json:"public_key"`    // base64url COSE_Key, byte-exact from authData
	Alg          int                         `json:"alg"`           // -7 (ES256) only
	AAGUID       string                      `json:"aaguid"`        // lowercase hex
	CredProtect  int                         `json:"cred_protect"`
	Discoverable bool                        `json:"discoverable"`
	UVPolicy     map[string]string           `json:"uv_policy,omitempty"`
	Registration ReceiptWebAuthnRegistration `json:"registration"`
	Binding      ReceiptSelfProof            `json:"binding"`
}

// ReceiptWebAuthnRegistration is the make-credential evidence (base64url): the
// attestation format, the raw authenticator data, the client-data hash papi
// chose, and the attestation signature and certificate as fido2-cred(1) prints
// them. The attestation is kept but not verified: it chains to a vendor batch
// certificate, which says nothing about this card's PIV applet.
type ReceiptWebAuthnRegistration struct {
	Fmt            string `json:"fmt"`
	AuthData       string `json:"auth_data"`
	ClientDataHash string `json:"client_data_hash"`
	AttSig         string `json:"att_sig,omitempty"`
	X5C            string `json:"x5c,omitempty"`
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

// WebAuthnBindingClaim is the claim the new card's slot-9A key signs to bind a
// WebAuthn credential to it. It names the rp id, the credential id (base64url),
// a SHA-256 of the COSE key bytes, and the 9A key's markl-id; producer and
// verifier both build it here so they cannot drift.
func WebAuthnBindingClaim(rpID, credentialID string, coseKey []byte, sshID string) string {
	sum := sha256.Sum256(coseKey)
	return fmt.Sprintf("%s binds webauthn %s credential %s key sha256:%s to %s",
		ReceiptSchemaV2, rpID, credentialID, hex.EncodeToString(sum[:]), sshID)
}

// WebAuthnClientDataHash is the client-data hash papi hands the authenticator
// when making the credential: SHA-256("papi-webauthn-reg-v1\n" ‖ rp_id ‖ "\n" ‖
// guid ‖ "\n" ‖ sshID). The packed attestation signs authData ‖ this hash, so
// the evidence names the card it was made for. Nothing relies on it for trust.
func WebAuthnClientDataHash(rpID, guid, sshID string) []byte {
	sum := sha256.Sum256([]byte("papi-webauthn-reg-v1\n" + rpID + "\n" + guid + "\n" + sshID))
	return sum[:]
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
