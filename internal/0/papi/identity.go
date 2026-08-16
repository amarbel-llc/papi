package papi

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"code.linenisgreat.com/papi/internal/0/markl"
	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
)

// IdentityDocSchema is the schema tag carried by a papi-identity-doc-v1.
const IdentityDocSchema = "papi-identity-doc-v1"

// IdentityDoc is the signed authorized-card set published at GET /papi/identity
// (papi#71). Format reuses RFC-0001 vocabulary: Signatures[] are §10.1 entries
// with Key and Sig as markl-ids (papi-doc-sig-v1@ecdsa_p256_sig and
// piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub respectively). Clients enforce:
// schema matches, version never decreases (persisted last-seen, never-clobber),
// doc age within freshness window, and all signatures cryptographically verify.
//
// Recovery root (papi#71 design decision): fleet-TOFU. Losing ≥2 of N cards
// simultaneously deadlocks removals; the escape is deliberate client-side version
// reset — `papi identity reset-version --domain <domain>` — requiring manual
// operator action on every client. No standing cold recovery key is introduced;
// the recovery ceremony is loud, manual, and scoped to the deadlock case.
type IdentityDoc struct {
	Schema     string         `json:"schema"`
	Domain     string         `json:"domain"`
	Version    int64          `json:"version"`
	IssuedAt   int64          `json:"issued_at"`
	Cards      []IdentityCard `json:"cards"`
	Signatures []Signature    `json:"signatures"`
}

// IdentityCard is one authorized card's identity material: the slot-9A auth
// key (AuthKey, a piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-… markl-id) and
// the slot-9D encryption recipient (Recipient, a
// piggy-recipient-v1@pivy_ecdh_p256_pub-… markl-id). Both are the same card's
// keys, bound by the card's self-proof in its enrollment receipt (FDR-0001).
type IdentityCard struct {
	AuthKey   string `json:"auth_key"`
	Recipient string `json:"recipient"`
}

// CanonicalIdentityDocInput reconstructs the bytes the signatures[] entries in
// an IdentityDoc cover: the document JSON with the `signatures` member removed,
// serialized by RFC 8785 JCS. Same strip-and-canonicalize discipline as RFC-0001
// §10.2 and CanonicalReceiptInput.
func CanonicalIdentityDocInput(raw []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("identity doc is not a JSON object: %w", err)
	}
	delete(obj, "signatures")
	reser, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(reser)
}

// DecodeIdentityDoc unwraps the RFC-0001 §4.2 {data,meta} envelope and decodes
// the IdentityDoc. Returns an error when the body is not a valid envelope or the
// data block is not a valid IdentityDoc JSON object.
func DecodeIdentityDoc(body []byte) (*IdentityDoc, error) {
	data, _, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var doc IdentityDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("/papi/identity data: %w", err)
	}
	return &doc, nil
}

// IdentityDoc fetches GET /papi/identity and returns the signed authorized-card
// document (papi#71), unwrapping the RFC-0001 §4.2 envelope.
func (c *Client) IdentityDoc(ctx context.Context) (*IdentityDoc, int, error) {
	body, status, err := c.get(ctx, "/papi/identity")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("/papi/identity returned HTTP %d", status)
	}
	doc, err := DecodeIdentityDoc(body)
	return doc, status, err
}

// VerifyIdentityDocStructure checks the structural validity and freshness of an
// IdentityDoc: schema matches, version ≥ minVersion (never-decreases contract),
// IssuedAt within [now-maxAge, now], cards and signatures non-empty.
// This is the pure-structural half of the client verification contract (papi#71);
// pair with VerifyIdentityDocSigs for the cryptographic half.
func VerifyIdentityDocStructure(doc *IdentityDoc, minVersion int64, now time.Time, maxAge time.Duration) error {
	if doc.Schema != IdentityDocSchema {
		return fmt.Errorf("identity doc: unexpected schema %q (want %q)", doc.Schema, IdentityDocSchema)
	}
	if doc.Version < 1 {
		return fmt.Errorf("identity doc: version %d < 1", doc.Version)
	}
	if doc.Version < minVersion {
		return fmt.Errorf("identity doc: version %d < last-seen %d (replay or rollback)", doc.Version, minVersion)
	}
	issuedAt := time.Unix(doc.IssuedAt, 0)
	if issuedAt.After(now) {
		return fmt.Errorf("identity doc: issued_at %d is in the future", doc.IssuedAt)
	}
	if now.Sub(issuedAt) > maxAge {
		return fmt.Errorf("identity doc: issued_at %d is older than maxAge %v", doc.IssuedAt, maxAge)
	}
	if len(doc.Cards) == 0 {
		return errors.New("identity doc: cards is empty")
	}
	if len(doc.Signatures) == 0 {
		return errors.New("identity doc: signatures is empty")
	}
	return nil
}

// VerifyIdentityDocSigs cryptographically verifies every signature in
// doc.Signatures against raw (the wire bytes the doc was fetched as). Each
// signature's Key must be the AuthKey of a card in trustedCards, and the
// ECDSA P-256 signature must verify over SHA-256(CanonicalIdentityDocInput(raw)).
//
// On genesis (first TOFU fetch), pass doc.Cards as trustedCards — the doc
// bootstraps its own trust. On subsequent fetches, pass the cards from the
// previously-verified doc.
func VerifyIdentityDocSigs(doc *IdentityDoc, raw []byte, trustedCards []IdentityCard) error {
	canonical, err := CanonicalIdentityDocInput(raw)
	if err != nil {
		return fmt.Errorf("identity doc: canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)

	trustedKeys := make(map[string]bool, len(trustedCards))
	for _, c := range trustedCards {
		trustedKeys[c.AuthKey] = true
	}

	for i, sig := range doc.Signatures {
		if !trustedKeys[sig.Key] {
			return fmt.Errorf("identity doc: signature[%d]: key %q not in trusted card set", i, sig.Key)
		}
		if err := verifyECDSASig(sig.Key, sig.Sig, digest[:]); err != nil {
			return fmt.Errorf("identity doc: signature[%d]: %w", i, err)
		}
	}
	return nil
}

// verifyECDSASig verifies a papi-doc-sig-v1@ecdsa_p256_sig sigID against a
// piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub keyID over digest.
func verifyECDSASig(keyID, sigID string, digest []byte) error {
	keyMark, err := markl.Parse(keyID)
	if err != nil {
		return fmt.Errorf("parse key markl-id %q: %w", keyID, err)
	}
	if keyMark.Format != markl.FormatSSHEcdsaNistp256Pub {
		return fmt.Errorf("key %q: format %q (want %q)", keyID, keyMark.Format, markl.FormatSSHEcdsaNistp256Pub)
	}
	sigMark, err := markl.Parse(sigID)
	if err != nil {
		return fmt.Errorf("parse sig markl-id %q: %w", sigID, err)
	}
	if sigMark.Format != markl.FormatEcdsaP256Sig {
		return fmt.Errorf("sig %q: format %q (want %q)", sigID, sigMark.Format, markl.FormatEcdsaP256Sig)
	}
	sshPub, err := ssh.ParsePublicKey(keyMark.Payload)
	if err != nil {
		return fmt.Errorf("parse SSH key from %q: %w", keyID, err)
	}
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("SSH key %q does not implement CryptoPublicKey", keyID)
	}
	ecKey, ok := cryptoPub.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("SSH key %q is not an ECDSA key", keyID)
	}
	if !ecdsa.VerifyASN1(ecKey, digest, sigMark.Payload) {
		return fmt.Errorf("ECDSA signature invalid for key %q", keyID)
	}
	return nil
}

// CheckIdentityDocQuorum verifies the quorum rule for transitioning from prev to
// next (papi#71 operator-ratified quorum model, 2026-08-11):
//
//   - genesis (prev == nil): every card in next.Cards must sign; Version must be 1
//   - freshness (cards unchanged): ≥1 signature from any current-set card
//   - addition (one card added): all cards in prev.Cards + added card must sign
//   - removal (one card removed): all cards in prev.Cards except the removed card
//     must sign; exactly one removal per version step (the cap prevents a single-card
//     self-approval takeover)
//   - simultaneous add+remove, or >1 add, or >1 remove: rejected — rotation is
//     two discrete version steps (add then remove)
//
// Call VerifyIdentityDocSigs first to confirm all signatures are cryptographically
// valid; CheckIdentityDocQuorum checks only which keys must be present.
func CheckIdentityDocQuorum(prev, next *IdentityDoc) error {
	if prev == nil {
		if next.Version != 1 {
			return fmt.Errorf("identity doc genesis: version %d != 1", next.Version)
		}
		return requireAllSigners(next, next.Cards)
	}

	removed, added := identityCardSetDiff(prev.Cards, next.Cards)
	switch {
	case len(added) == 0 && len(removed) == 0:
		return requireAtLeastOneSigner(next, prev.Cards)
	case len(added) == 1 && len(removed) == 0:
		must := append(append([]IdentityCard(nil), prev.Cards...), added[0])
		return requireAllSigners(next, must)
	case len(removed) == 1 && len(added) == 0:
		var must []IdentityCard
		for _, c := range prev.Cards {
			if c.AuthKey != removed[0].AuthKey {
				must = append(must, c)
			}
		}
		return requireAllSigners(next, must)
	default:
		return fmt.Errorf(
			"identity doc: invalid transition (added %d, removed %d); rotation is two steps (add then remove)",
			len(added), len(removed),
		)
	}
}

// requireAllSigners checks that next.Signatures contains a signature from every
// card in must (matched by AuthKey).
func requireAllSigners(next *IdentityDoc, must []IdentityCard) error {
	found := make(map[string]bool, len(next.Signatures))
	for _, sig := range next.Signatures {
		found[sig.Key] = true
	}
	for _, c := range must {
		if !found[c.AuthKey] {
			return fmt.Errorf("identity doc: missing required signer %q", c.AuthKey)
		}
	}
	return nil
}

// requireAtLeastOneSigner checks that at least one signature in next.Signatures
// is keyed by a card in allowed.
func requireAtLeastOneSigner(next *IdentityDoc, allowed []IdentityCard) error {
	allowedKeys := make(map[string]bool, len(allowed))
	for _, c := range allowed {
		allowedKeys[c.AuthKey] = true
	}
	for _, sig := range next.Signatures {
		if allowedKeys[sig.Key] {
			return nil
		}
	}
	return errors.New("identity doc: no signature from an authorized card (freshness re-sign needs ≥1 current-set card)")
}

// identityCardSetDiff returns the cards added (in next but not prev) and removed
// (in prev but not next), keyed by AuthKey.
func identityCardSetDiff(prev, next []IdentityCard) (removed, added []IdentityCard) {
	prevSet := make(map[string]IdentityCard, len(prev))
	for _, c := range prev {
		prevSet[c.AuthKey] = c
	}
	nextSet := make(map[string]IdentityCard, len(next))
	for _, c := range next {
		nextSet[c.AuthKey] = c
	}
	for k, c := range prevSet {
		if _, ok := nextSet[k]; !ok {
			removed = append(removed, c)
		}
	}
	for k, c := range nextSet {
		if _, ok := prevSet[k]; !ok {
			added = append(added, c)
		}
	}
	return removed, added
}
