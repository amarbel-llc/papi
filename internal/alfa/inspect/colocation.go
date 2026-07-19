package inspect

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/0/papi"
)

// coLocationClaim is the canonical §9.6.2 Level-A statement a co_location proof's
// slot-9A signature covers: the domain-separated binding of a slot-9D recipient to
// a slot-9A key. The fixed `papi-key-co-location-v1` prefix keeps it disjoint from
// the §9.3 external-identity claim and the FDR-0001 receipt self_proof claim, so no
// signature can be replayed across the three.
func coLocationClaim(recipient, key string) string {
	return "papi-key-co-location-v1 binds " + recipient + " to " + key
}

// coLocationChecks verifies the document's key-co-location proofs (RFC-0001 §9.6)
// over the anonymous /papi document. Each entry yields verified (ok), unverified
// (a flag — the binding is not proven), or unverifiable (a skip — a malformed or
// unsupported entry), mirroring the §9.4 three-outcome model. Like the §9 proof
// checks these are third-party verdicts over public inputs, not server-conformance
// MUSTs, so none trips the exit code.
func coLocationChecks(ctx context.Context, c *papi.Client) []point {
	doc, _, _, err := c.Document(ctx)
	if err != nil {
		return []point{skip("co_location: §9.6 verification", "GET /papi failed: "+err.Error())}
	}
	if len(doc.CoLocation) == 0 {
		return []point{skip("co_location: §9.6 verification", "no co_location[] advertised")}
	}

	var recipients []json.RawMessage
	if doc.Piggy != nil {
		recipients = doc.Piggy.EncryptionRecipients
	}
	published := recipientIDSet(recipients)
	signingKeys := publishedSigningKeys(ctx, c, doc)
	seen := map[string]bool{}

	pts := make([]point, 0, len(doc.CoLocation))
	for i, cl := range doc.CoLocation {
		pts = append(pts, verifyCoLocation(cl, i, published, seen, signingKeys))
	}
	return pts
}

// verifyCoLocation evaluates one §9.6 co_location entry to the three-outcome
// verdict (§9.6.3). signingKeys are the subject's published slot-9A keys (§10.1
// union); the entry's `key` MUST be one of them and its `sig` MUST verify against
// it. Level B/C `evidence` is not yet pinned (RESERVED, §9.6.2), so a
// "co-control"/"attested" entry is verified only at the Level-A binding it MUST
// still carry, and reported as such — never as the stronger, unchecked level.
func verifyCoLocation(cl papi.CoLocation, i int, published, seen map[string]bool, signingKeys []*ecdsa.PublicKey) point {
	label := fmt.Sprintf("co_location[%d] %q", i, cl.ID)

	switch {
	case cl.ID == "":
		return skip(fmt.Sprintf("co_location: co_location[%d] unverifiable", i), "missing id (§9.6.1)")
	case seen[cl.ID]:
		return skip("co_location: "+label+" unverifiable", "duplicate id (§9.6.1)")
	}
	seen[cl.ID] = true

	switch {
	case !recipientGrammar.MatchString(cl.Recipient):
		return skip("co_location: "+label+" unverifiable", "recipient does not match the §5.1 grammar")
	case !published[cl.Recipient]:
		return skip("co_location: "+label+" unverifiable", "recipient not in piggy.encryption_recipients (§9.6.1)")
	}

	switch cl.Level {
	case "soft", "co-control", "attested":
		// All three MUST carry the Level-A binding (§9.6.2). B/C evidence is
		// RESERVED, so only the floor is verified below.
	default:
		return skip("co_location: "+label+" unverifiable", fmt.Sprintf("unrecognized level %q (§9.6.2)", cl.Level))
	}

	// The `key` MUST be a published slot-9A key, and its named public key is the one
	// the signature MUST verify against (§9.6.1–§9.6.2).
	keyID, err := markl.Parse(cl.Key)
	if err != nil || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
		return skip("co_location: "+label+" unverifiable", "key is not an …@ssh_ecdsa_nistp256_pub markl-id")
	}
	keyPub, err := p256FromCompressed(keyID.Payload)
	if err != nil {
		return skip("co_location: "+label+" unverifiable", "key is not a valid SEC1-compressed P-256 point")
	}
	if !publicKeyListed(keyPub, signingKeys) {
		return skip("co_location: "+label+" unverifiable",
			"key is not published (piggy-ids or ssh_authorized_keys) (§9.6.1)")
	}

	// `claim` MUST equal the canonical construction for this recipient/key (§9.6.2).
	want := coLocationClaim(cl.Recipient, cl.Key)
	if cl.Claim != want {
		return shouldFail("co_location: "+label+" unverified — claim is not the canonical §9.6.2 binding",
			map[string]any{"want": want, "got": cl.Claim})
	}

	// `sig` MUST be a papi-proof-sig-v1@ecdsa_p256_sig markl verifying over
	// SHA-256(claim) against the named key (§9.6.2).
	sigID, err := markl.Parse(cl.Sig)
	if err != nil || sigID.Purpose != markl.PurposeProofSig || sigID.Format != markl.FormatEcdsaP256Sig {
		return shouldFail("co_location: "+label+" unverified — sig is not a papi-proof-sig-v1@ecdsa_p256_sig markl-id",
			map[string]any{"sig": cl.Sig})
	}
	if !ecdsaVerifyRaw(keyPub, []byte(cl.Claim), sigID.Payload) {
		return shouldFail("co_location: "+label+" unverified — signature does not verify against the bound key (§9.6.2)",
			map[string]any{"key": cl.Key})
	}

	note := ""
	if cl.Level != "soft" {
		note = fmt.Sprintf(" (Level-A floor only; %q evidence RESERVED, not checked — §9.6.2)", cl.Level)
	}
	return ok(fmt.Sprintf("co_location: %s verified — slot-9A signs the soft binding of the recipient to its key (§9.6)%s", label, note))
}

// publicKeyListed reports whether pub (by curve point) appears in keys — the §10.1
// published slot-9A key set. Confirms a co_location entry's named key is published.
func publicKeyListed(pub *ecdsa.PublicKey, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		if k.X.Cmp(pub.X) == 0 && k.Y.Cmp(pub.Y) == 0 {
			return true
		}
	}
	return false
}
