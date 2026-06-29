// Package authproxy implements the PAPI-session forward-auth verifier (circus
// FDR-0014, papi#36 follow-on): an nginx `auth_request` target that validates a
// card-minted session cookie, plus the signed-token primitives the cookie, the
// oracle→verifier attestation, and the login state param share.
//
// PAPI stays a verifier, never an IdP. The session cookie is minted ONCE from a §5
// card login (validate-at-mint, RFC-0001 §5.3 — there is no session-introspection
// endpoint), then checked locally on every request.
//
// Trust split (client-side signing — the oracle runs on the cardholder's machine,
// the verifier on the server):
//   - the cookie and the login state are HMAC tokens under K_cookie, a secret held
//     ONLY by the verifier (it both mints and checks them);
//   - the attestation (the oracle proving a card login to the verifier, carried by
//     the browser) is ASYMMETRIC: the oracle signs with an Ed25519 PRIVATE key on
//     the card machine; the verifier holds only the PUBLIC key. This is deliberate —
//     a symmetric attestation key on the server would let the server FORGE logins (a
//     standing sign-as-you capability), which the design rejects. With Ed25519 the
//     server can verify a login but never mint one.
package authproxy

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrExpired is returned by the Parse* helpers when a token's exp is at or before
// the supplied time — distinct from a signature/format error so a caller can treat
// "expired" as "re-login" rather than "tampered".
var ErrExpired = errors.New("authproxy: token expired")

var b64 = base64.RawURLEncoding

// Sign returns "<b64url(payload)>.<b64url(HMAC-SHA256(key, payload))>" — a compact
// HS256-style token for the verifier's own cookie/state (K_cookie). key SHOULD be
// >= 32 bytes of CSPRNG output.
func Sign(key, payload []byte) string {
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(hmacSum(key, payload))
}

// Verify checks the HMAC in constant time and returns the raw payload.
func Verify(key []byte, token string) ([]byte, error) {
	payload, mac, err := split(token)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(mac, hmacSum(key, payload)) {
		return nil, errors.New("authproxy: signature mismatch")
	}
	return payload, nil
}

func hmacSum(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return m.Sum(nil)
}

// split parses "<b64url(payload)>.<b64url(sig)>" into the raw payload and signature.
func split(token string) (payload, sig []byte, err error) {
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return nil, nil, errors.New("authproxy: token missing '.' separator")
	}
	if payload, err = b64.DecodeString(token[:dot]); err != nil {
		return nil, nil, fmt.Errorf("authproxy: decode payload: %w", err)
	}
	if sig, err = b64.DecodeString(token[dot+1:]); err != nil {
		return nil, nil, fmt.Errorf("authproxy: decode signature: %w", err)
	}
	return payload, sig, nil
}

// SessionClaims is the __papi_session cookie payload — the verifier's own session,
// minted at login and checked locally thereafter. Exp = the PiggySession's
// expires_at (re-card on lapse).
type SessionClaims struct {
	Principal string   `json:"principal"`
	Groups    []string `json:"groups"`
	Exp       int64    `json:"exp"`
}

// AttestClaims is the oracle→verifier attestation carried by the browser: the oracle
// asserts the §5 card-login result, bound to this login (Nonce) and this verifier
// (Aud). Exp is the attestation's own short lifetime; SessionExp is the PiggySession
// expires_at the verifier copies into the cookie. Signed/verified with Ed25519.
type AttestClaims struct {
	Principal  string   `json:"principal"`
	Groups     []string `json:"groups"`
	Nonce      string   `json:"nonce"`
	Aud        string   `json:"aud"`
	SessionExp int64    `json:"session_exp"`
	Exp        int64    `json:"exp"`
}

// StateClaims is the verifier's login state param — stateless (HMAC'd under
// K_cookie, no server store): the post-login redirect and the nonce the attestation
// must echo.
type StateClaims struct {
	Nonce string `json:"nonce"`
	RD    string `json:"rd"`
	Exp   int64  `json:"exp"`
}

// MintSession / MintState sign the verifier's own tokens with the HMAC K_cookie.
func MintSession(key []byte, c SessionClaims) (string, error) { return mintHMAC(key, c) }
func MintState(key []byte, c StateClaims) (string, error)     { return mintHMAC(key, c) }

// ParseSession / ParseState verify the HMAC, decode, and reject an expired token.
func ParseSession(key []byte, token string, now time.Time) (SessionClaims, error) {
	var c SessionClaims
	if err := parseHMAC(key, token, &c); err != nil {
		return SessionClaims{}, err
	}
	if expired(c.Exp, now) {
		return SessionClaims{}, ErrExpired
	}
	return c, nil
}

func ParseState(key []byte, token string, now time.Time) (StateClaims, error) {
	var c StateClaims
	if err := parseHMAC(key, token, &c); err != nil {
		return StateClaims{}, err
	}
	if expired(c.Exp, now) {
		return StateClaims{}, ErrExpired
	}
	return c, nil
}

// MintAttest signs the attestation with the oracle's Ed25519 PRIVATE key (card
// machine only).
func MintAttest(priv ed25519.PrivateKey, c AttestClaims) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(b) + "." + b64.EncodeToString(ed25519.Sign(priv, b)), nil
}

// ParseAttest verifies the attestation with the oracle's Ed25519 PUBLIC key (the
// verifier holds only this — it can check a login but never forge one), then decodes
// and rejects an expired token.
func ParseAttest(pub ed25519.PublicKey, token string, now time.Time) (AttestClaims, error) {
	payload, sig, err := split(token)
	if err != nil {
		return AttestClaims{}, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return AttestClaims{}, errors.New("authproxy: attestation signature mismatch")
	}
	var c AttestClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return AttestClaims{}, fmt.Errorf("authproxy: decode attestation: %w", err)
	}
	if expired(c.Exp, now) {
		return AttestClaims{}, ErrExpired
	}
	return c, nil
}

func expired(exp int64, now time.Time) bool { return !now.Before(time.Unix(exp, 0)) }

func mintHMAC(key []byte, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return Sign(key, b), nil
}

func parseHMAC(key []byte, token string, v any) error {
	b, err := Verify(key, token)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
