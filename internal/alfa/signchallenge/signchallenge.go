// Package signchallenge is the producing side of the RFC-0001 §5.2 sign-challenge
// auth handshake (Amendment 14): given a server-minted challenge and the PAPI
// identity domain, it builds the domain-separated preimage, signs it with the
// caller's slot-9A PIV key, and emits the POST /papi/auth/response body. It is the
// client counterpart to the server's signature verifier — papi owns the preimage
// framing and the papi-auth-sig-v1 markl purpose; piggy only signs bytes (the
// Signer seam, structurally identical to enroll.Signer, so the same
// enroll.PiggySignBytesSigner drives both enrollment and challenge answering).
package signchallenge

import (
	"context"
	"encoding/json"
	"fmt"

	"code.linenisgreat.com/papi/internal/0/markl"
)

// preimagePrefix is the §5.2 domain-separation tag. The signed preimage is exactly
// prefix + "\n" + domain + "\n" + nonce — three fields joined by single LF bytes,
// no trailing newline — binding the signature to this site (cross-site relay
// defense). The server reconstructs identical bytes from its bound PAPI_AUTH_DOMAIN
// and the stored nonce, so this framing IS the handshake.
const preimagePrefix = "papi-auth-v1"

// Signer signs message bytes with the slot-9A key of the card identified by guid,
// returning the raw 64-byte r‖s ECDSA P-256 signature — the markl ecdsa_p256_sig
// payload (RFC-0001 §10.4: "no DER, no SSH-wire framing"). The card hashes SHA-256
// internally, so msg is the bare preimage to sign, NOT a pre-hash. The production
// implementation is enroll.PiggySignBytesSigner (`piggy sign-bytes --slot 9a
// --format raw`), which satisfies this interface structurally.
type Signer interface {
	SignSlot9A(ctx context.Context, guid string, msg []byte) (rs []byte, err error)
}

// Challenge is the server's POST /papi/auth/challenge response (§5.1). ExpiresAt is
// advisory to the client — the server enforces one-time/expiry — so only
// ChallengeID and Nonce drive the response.
type Challenge struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expires_at"`
}

// Response is the POST /papi/auth/response body the caller returns (§5.2): the
// echoed challenge_id and the slot-9A signature as a papi-auth-sig-v1 markl id.
type Response struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

// ParseChallenge decodes a §5.1 challenge JSON and checks the two fields the
// response needs are present (a missing challenge_id or nonce is the §5.1 shape
// the server would never mint, so it is a client-side error, not a 400 to chase).
func ParseChallenge(raw []byte) (Challenge, error) {
	var ch Challenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		return Challenge{}, fmt.Errorf("parse challenge JSON: %w", err)
	}
	if ch.ChallengeID == "" {
		return Challenge{}, fmt.Errorf("challenge JSON lacks challenge_id (§5.1)")
	}
	if ch.Nonce == "" {
		return Challenge{}, fmt.Errorf("challenge JSON lacks nonce (§5.1)")
	}
	return ch, nil
}

// Preimage builds the §5.2 domain-separated preimage the slot-9A key signs:
// "papi-auth-v1\n<domain>\n<nonce>", single LF separators, no trailing newline.
// domain and nonce are used verbatim (no trimming/normalization) — the server does
// the same, so byte-exactness here is mandatory.
func Preimage(domain, nonce string) []byte {
	return []byte(preimagePrefix + "\n" + domain + "\n" + nonce)
}

// Sign answers ch for domain by signing the §5.2 preimage with the slot-9A key of
// card guid (empty guid lets the signer pick when only one card is present) and
// wrapping the raw r‖s as a papi-auth-sig-v1@ecdsa_p256_sig markl id. The returned
// Response is the /papi/auth/response body. domain MUST be the PAPI identity domain
// — it is never echoed by the challenge (relay defense), so the caller supplies it
// out of band.
func Sign(ctx context.Context, signer Signer, guid, domain string, ch Challenge) (Response, error) {
	if domain == "" {
		return Response{}, fmt.Errorf("sign-challenge needs the PAPI identity domain (§5.2 preimage binding)")
	}
	rs, err := signer.SignSlot9A(ctx, guid, Preimage(domain, ch.Nonce))
	if err != nil {
		return Response{}, fmt.Errorf("slot-9A sign of the §5.2 preimage: %w", err)
	}
	sig, err := markl.Build(markl.PurposeAuthSig, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		return Response{}, fmt.Errorf("wrap signature as %s markl-id: %w", markl.PurposeAuthSig, err)
	}
	return Response{ChallengeID: ch.ChallengeID, Signature: sig}, nil
}
