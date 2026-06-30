package signchallenge

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/amarbel-llc/papi/internal/0/markl"
)

// Verify is the §5.2 sign-challenge verifier side: decode a papi-auth-sig-v1 markl
// to its raw r‖s and ECDSA-verify it over SHA-256(Preimage(domain, nonce)) with pub.
// This is what a sign-challenge verifier runs against a registered slot-9A public
// key — the reference PAPI server, or the authproxy forward-auth verifier. It is the
// exact mirror of Sign.
func Verify(pub *ecdsa.PublicKey, domain, nonce, signatureMarkl string) error {
	id, err := markl.Parse(signatureMarkl)
	if err != nil {
		return fmt.Errorf("parse signature markl: %w", err)
	}
	if id.Purpose != markl.PurposeAuthSig || id.Format != markl.FormatEcdsaP256Sig {
		return fmt.Errorf("signature is %s/%s, want %s/%s",
			id.Purpose, id.Format, markl.PurposeAuthSig, markl.FormatEcdsaP256Sig)
	}
	if len(id.Payload) != 64 {
		return fmt.Errorf("signature payload is %d bytes, want 64 (raw r‖s)", len(id.Payload))
	}
	r := new(big.Int).SetBytes(id.Payload[:32])
	s := new(big.Int).SetBytes(id.Payload[32:])
	digest := sha256.Sum256(Preimage(domain, nonce))
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("signature does not verify over the §5.2 preimage")
	}
	return nil
}
