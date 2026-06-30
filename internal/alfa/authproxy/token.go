// Package authproxy implements the PAPI-session forward-auth verifier (circus
// FDR-0014, papi#36 follow-on): an nginx `auth_request` target that validates a
// card-minted session cookie, plus the HMAC-signed tokens the cookie and the login
// state share.
//
// PAPI stays a verifier, never an IdP. The verifier is a §5.2 sign-challenge verifier
// (RFC-0001 §5.2): it issues a nonce, the cardholder's oracle card-signs it with
// slot-9A, and the verifier checks that signature against the registered slot-9A keys
// (synced from a papi-ssh-sync authorized_keys fragment). The ONLY signing key
// anywhere is the YubiKey. On a valid card login the verifier mints its own signed
// session cookie (validate-at-mint) and checks it locally on every request — there is
// no session-introspection endpoint (RFC §5.3) and no server signing key.
//
// This file is the HMAC token mechanism for the verifier's own cookie + login state
// (K_cookie, a secret the verifier alone holds — it both mints and checks them).
package authproxy

import (
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
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return nil, errors.New("authproxy: token missing '.' separator")
	}
	payload, err := b64.DecodeString(token[:dot])
	if err != nil {
		return nil, fmt.Errorf("authproxy: decode payload: %w", err)
	}
	mac, err := b64.DecodeString(token[dot+1:])
	if err != nil {
		return nil, fmt.Errorf("authproxy: decode mac: %w", err)
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

// SessionClaims is the __papi_session cookie payload — the verifier's own session,
// minted at login and checked locally thereafter. Exp bounds re-card.
type SessionClaims struct {
	Principal string   `json:"principal"`
	Groups    []string `json:"groups"`
	Exp       int64    `json:"exp"`
}

// StateClaims is the verifier's login state param — stateless (HMAC'd under
// K_cookie, no server store): the post-login redirect and the nonce the card
// signature must be over.
type StateClaims struct {
	Nonce string `json:"nonce"`
	RD    string `json:"rd"`
	Exp   int64  `json:"exp"`
}

// MintSession / MintState sign the verifier's own tokens with the HMAC K_cookie.
func MintSession(key []byte, c SessionClaims) (string, error) { return mint(key, c) }
func MintState(key []byte, c StateClaims) (string, error)     { return mint(key, c) }

// ParseSession / ParseState verify the HMAC, decode, and reject an expired token.
func ParseSession(key []byte, token string, now time.Time) (SessionClaims, error) {
	var c SessionClaims
	if err := parse(key, token, &c); err != nil {
		return SessionClaims{}, err
	}
	if expired(c.Exp, now) {
		return SessionClaims{}, ErrExpired
	}
	return c, nil
}

func ParseState(key []byte, token string, now time.Time) (StateClaims, error) {
	var c StateClaims
	if err := parse(key, token, &c); err != nil {
		return StateClaims{}, err
	}
	if expired(c.Exp, now) {
		return StateClaims{}, ErrExpired
	}
	return c, nil
}

func expired(exp int64, now time.Time) bool { return !now.Before(time.Unix(exp, 0)) }

func mint(key []byte, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return Sign(key, b), nil
}

func parse(key []byte, token string, v any) error {
	b, err := Verify(key, token)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
