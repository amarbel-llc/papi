// Package webauthn is the network-free, card-free core of papi's WebAuthn
// support (circus#414; design in docs/plans/2026-11-04-papi-enroll-webauthn.md):
// it parses a registration (attestationObject → authenticator data → COSE ES256
// key) and verifies an assertion against a registered credential under one of
// the two papi assurance tiers. It is stdlib-only (no cgo) so the wasm builds
// can link it; talking to an authenticator is not this package's job.
//
// Attestation statements are parsed but NOT verified: papi binds a credential
// to a card through the enrollment receipt (the new card's slot-9A signature and
// a trusted card's attestation), not through FIDO attestation.
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Authenticator data flag bits (WebAuthn L3 §6.1; libfido2 fido/param.h names
// UP/UV/AT/ED as CTAP_AUTHDATA_*).
const (
	FlagUP byte = 0x01 // user present
	FlagUV byte = 0x04 // user verified
	FlagBE byte = 0x08 // backup eligible
	FlagBS byte = 0x10 // backup state
	FlagAT byte = 0x40 // attested credential data included
	FlagED byte = 0x80 // extension data included
)

// COSE identifiers for the one key type papi accepts (RFC 9053; libfido2
// fido/param.h COSE_ES256 / COSE_KTY_EC2 / COSE_P256).
const (
	coseKtyEC2   = 2
	coseAlgES256 = -7
	coseCrvP256  = 1
)

var (
	ErrMalformed           = errors.New("webauthn: malformed data")
	ErrRPIDMismatch        = errors.New("webauthn: rpIdHash does not match the relying party id")
	ErrUserNotPresent      = errors.New("webauthn: user presence (UP) flag not set")
	ErrUserNotVerified     = errors.New("webauthn: user verification (UV) flag not set")
	ErrBackupState         = errors.New("webauthn: backup state (BS) set without backup eligibility (BE)")
	ErrNotDeviceBound      = errors.New("webauthn: credential is backup-eligible (not device-bound)")
	ErrCredProtect         = errors.New("webauthn: credProtect level is not the required one")
	ErrBadSignature        = errors.New("webauthn: signature does not verify")
	ErrSignCountRegression = errors.New("webauthn: signCount did not advance (possible cloned authenticator)")
	ErrClientData          = errors.New("webauthn: clientDataJSON check failed")
)

// AuthenticatorData is the parsed authenticator data (WebAuthn L3 §6.1).
type AuthenticatorData struct {
	RPIDHash   [32]byte
	Flags      byte
	SignCount  uint32
	Attested   *AttestedCredential // present iff FlagAT
	Extensions map[any]any         // present iff FlagED
}

// AttestedCredential is the attested credential data block (WebAuthn L3 §6.5.2).
type AttestedCredential struct {
	AAGUID       [16]byte
	CredentialID []byte
	PublicKey    *ecdsa.PublicKey
	COSEKey      []byte // the credential public key exactly as the authenticator encoded it
}

// CredProtect returns the credProtect extension output, when the authenticator
// reported one (a CTAP 2.1 extension output in the registration's authData).
func (a AuthenticatorData) CredProtect() (int, bool) {
	v, ok := a.Extensions["credProtect"].(int64)
	return int(v), ok
}

// ParseAuthenticatorData parses raw authenticator data. Trailing bytes after the
// last present component are an error.
func ParseAuthenticatorData(b []byte) (AuthenticatorData, error) {
	var ad AuthenticatorData
	if len(b) < 37 {
		return ad, fmt.Errorf("%w: authenticator data is %d bytes, need at least 37", ErrMalformed, len(b))
	}
	copy(ad.RPIDHash[:], b[:32])
	ad.Flags = b[32]
	ad.SignCount = binary.BigEndian.Uint32(b[33:37])
	rest := b[37:]

	if ad.Flags&FlagAT != 0 {
		if len(rest) < 18 {
			return ad, fmt.Errorf("%w: AT flag set but attested credential data is truncated", ErrMalformed)
		}
		ac := &AttestedCredential{}
		copy(ac.AAGUID[:], rest[:16])
		idLen := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if idLen > len(rest) {
			return ad, fmt.Errorf("%w: credential id length %d exceeds data", ErrMalformed, idLen)
		}
		ac.CredentialID = append([]byte(nil), rest[:idLen]...)
		rest = rest[idLen:]
		keyItem, n, err := decodeCBOR(rest)
		if err != nil {
			return ad, fmt.Errorf("%w: credential public key: %v", ErrMalformed, err)
		}
		pub, err := parseCOSEES256(keyItem)
		if err != nil {
			return ad, err
		}
		ac.PublicKey = pub
		ac.COSEKey = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
		ad.Attested = ac
	}
	if ad.Flags&FlagED != 0 {
		ext, n, err := decodeCBOR(rest)
		if err != nil {
			return ad, fmt.Errorf("%w: extensions: %v", ErrMalformed, err)
		}
		m, ok := ext.(map[any]any)
		if !ok {
			return ad, fmt.Errorf("%w: extensions are not a map", ErrMalformed)
		}
		ad.Extensions = m
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return ad, fmt.Errorf("%w: %d trailing bytes in authenticator data", ErrMalformed, len(rest))
	}
	return ad, nil
}

// parseCOSEES256 accepts only an EC2 / ES256 / P-256 COSE_Key whose point is on
// the curve.
func parseCOSEES256(item any) (*ecdsa.PublicKey, error) {
	m, ok := item.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: COSE key is not a map", ErrMalformed)
	}
	intField := func(k int64) (int64, bool) { v, ok := m[k].(int64); return v, ok }
	if v, ok := intField(1); !ok || v != coseKtyEC2 {
		return nil, fmt.Errorf("%w: COSE kty must be EC2 (2)", ErrMalformed)
	}
	if v, ok := intField(3); !ok || v != coseAlgES256 {
		return nil, fmt.Errorf("%w: COSE alg must be ES256 (-7)", ErrMalformed)
	}
	if v, ok := intField(-1); !ok || v != coseCrvP256 {
		return nil, fmt.Errorf("%w: COSE crv must be P-256 (1)", ErrMalformed)
	}
	x, xok := m[int64(-2)].([]byte)
	y, yok := m[int64(-3)].([]byte)
	if !xok || !yok || len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: COSE x/y must be 32-byte strings", ErrMalformed)
	}
	pt := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		return nil, fmt.Errorf("%w: COSE point: %v", ErrMalformed, err)
	}
	return pub, nil
}

// Registration is a parsed attestationObject (WebAuthn L3 §6.5).
type Registration struct {
	Format      string
	AttStmt     map[any]any // parsed, not verified (see the package comment)
	RawAuthData []byte
	AuthData    AuthenticatorData
}

// ParseAttestationObject parses a CBOR attestationObject {fmt, attStmt,
// authData}. The authData MUST carry attested credential data.
func ParseAttestationObject(b []byte) (Registration, error) {
	var reg Registration
	v, err := decodeCBORExact(b)
	if err != nil {
		return reg, fmt.Errorf("%w: attestationObject: %v", ErrMalformed, err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return reg, fmt.Errorf("%w: attestationObject is not a map", ErrMalformed)
	}
	reg.Format, ok = m["fmt"].(string)
	if !ok {
		return reg, fmt.Errorf("%w: attestationObject.fmt missing", ErrMalformed)
	}
	reg.AttStmt, ok = m["attStmt"].(map[any]any)
	if !ok {
		return reg, fmt.Errorf("%w: attestationObject.attStmt missing", ErrMalformed)
	}
	reg.RawAuthData, ok = m["authData"].([]byte)
	if !ok {
		return reg, fmt.Errorf("%w: attestationObject.authData missing", ErrMalformed)
	}
	reg.AuthData, err = ParseAuthenticatorData(reg.RawAuthData)
	if err != nil {
		return reg, err
	}
	if reg.AuthData.Attested == nil {
		return reg, fmt.Errorf("%w: registration authData has no attested credential data", ErrMalformed)
	}
	return reg, nil
}

// RegistrationPolicy is what `papi enroll` demands of a freshly-made credential.
type RegistrationPolicy struct {
	RequireUV          bool // the make-credential ceremony was PIN-verified
	RequireCredProtect int  // 0: don't check; else the credProtect level the authenticator must report
	RequireDeviceBound bool // reject a backup-eligible (synced) credential
}

// Credential checks the registration against rpID and policy and returns the
// credential record to publish (WebAuthn L3 §7.1, minus clientData and
// attestation-statement verification — see the package comment).
func (r Registration) Credential(rpID string, p RegistrationPolicy) (Credential, error) {
	ad := r.AuthData
	if err := checkCommon(ad, rpID); err != nil {
		return Credential{}, err
	}
	if ad.Flags&FlagUP == 0 {
		return Credential{}, ErrUserNotPresent
	}
	if p.RequireUV && ad.Flags&FlagUV == 0 {
		return Credential{}, ErrUserNotVerified
	}
	if p.RequireDeviceBound && ad.Flags&FlagBE != 0 {
		return Credential{}, ErrNotDeviceBound
	}
	if p.RequireCredProtect != 0 {
		if lvl, ok := ad.CredProtect(); !ok || lvl != p.RequireCredProtect {
			return Credential{}, fmt.Errorf("%w: want %d, authenticator reported %d (present=%v)",
				ErrCredProtect, p.RequireCredProtect, lvl, ok)
		}
	}
	return Credential{
		ID:        ad.Attested.CredentialID,
		PublicKey: ad.Attested.PublicKey,
		RPID:      rpID,
		SignCount: ad.SignCount,
	}, nil
}

// Credential is a registered credential record: what the served document
// publishes per card (plus SignCount, which only a stateful verifier tracks).
type Credential struct {
	ID        []byte
	PublicKey *ecdsa.PublicKey
	RPID      string
	SignCount uint32 // last seen; 0 when unknown or not tracked
}

// AssertionPolicy is the per-page assurance requirement. UP and UV are checked
// only when required: WebAuthn L3 §7.2 step 17 says to ignore UV when it was not
// required.
type AssertionPolicy struct {
	RequireUP bool
	RequireUV bool
}

var (
	// TierTouch gates data on a touch of the enrolled key (UP only).
	TierTouch = AssertionPolicy{RequireUP: true}
	// TierPIN gates data on touch plus the key's FIDO2 PIN (UP and UV).
	TierPIN = AssertionPolicy{RequireUP: true, RequireUV: true}
)

// VerifyAssertion verifies an assertion signature over authData ||
// clientDataHash (WebAuthn L3 §7.2 steps 15–22, with the hash supplied by the
// caller: a CTAP client such as fido2-assert(1) signs a caller-chosen hash). It
// returns the parsed authenticator data so the caller can record SignCount.
func VerifyAssertion(cred Credential, authData, clientDataHash, sig []byte, p AssertionPolicy) (AuthenticatorData, error) {
	if len(clientDataHash) != sha256.Size {
		return AuthenticatorData{}, fmt.Errorf("%w: client data hash is %d bytes", ErrMalformed, len(clientDataHash))
	}
	ad, err := ParseAuthenticatorData(authData)
	if err != nil {
		return ad, err
	}
	if err := checkCommon(ad, cred.RPID); err != nil {
		return ad, err
	}
	if p.RequireUP && ad.Flags&FlagUP == 0 {
		return ad, ErrUserNotPresent
	}
	if p.RequireUV && ad.Flags&FlagUV == 0 {
		return ad, ErrUserNotVerified
	}
	msg := append(append([]byte(nil), authData...), clientDataHash...)
	h := sha256.Sum256(msg)
	if cred.PublicKey == nil || !ecdsa.VerifyASN1(cred.PublicKey, h[:], sig) {
		return ad, ErrBadSignature
	}
	// Step 22: "a signal, but not proof" of cloning; papi treats it as a failure
	// whenever the caller tracks a count.
	if (cred.SignCount != 0 || ad.SignCount != 0) && ad.SignCount <= cred.SignCount {
		return ad, fmt.Errorf("%w: stored %d, got %d", ErrSignCountRegression, cred.SignCount, ad.SignCount)
	}
	return ad, nil
}

// VerifyBrowserAssertion is VerifyAssertion for a browser ceremony: it checks
// clientDataJSON (type webauthn.get, the server's challenge, an expected origin)
// and verifies the signature over SHA-256(clientDataJSON).
func VerifyBrowserAssertion(cred Credential, authData, clientDataJSON, sig, challenge []byte, origins []string, p AssertionPolicy) (AuthenticatorData, error) {
	if err := CheckClientDataJSON(clientDataJSON, "webauthn.get", challenge, origins); err != nil {
		return AuthenticatorData{}, err
	}
	h := sha256.Sum256(clientDataJSON)
	return VerifyAssertion(cred, authData, h[:], sig, p)
}

// CheckClientDataJSON applies WebAuthn L3 §7.2 steps 10–13: type, challenge,
// origin (exact match against origins), and crossOrigin not true.
func CheckClientDataJSON(raw []byte, wantType string, challenge []byte, origins []string) error {
	if len(challenge) == 0 {
		return fmt.Errorf("%w: no expected challenge supplied", ErrClientData)
	}
	var c struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("%w: %v", ErrClientData, err)
	}
	if c.Type != wantType {
		return fmt.Errorf("%w: type %q, want %q", ErrClientData, c.Type, wantType)
	}
	got, err := base64.RawURLEncoding.DecodeString(c.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return fmt.Errorf("%w: challenge mismatch", ErrClientData)
	}
	if !slices.Contains(origins, c.Origin) {
		return fmt.Errorf("%w: unexpected origin %q", ErrClientData, c.Origin)
	}
	if c.CrossOrigin {
		return fmt.Errorf("%w: crossOrigin is true", ErrClientData)
	}
	return nil
}

// checkCommon covers the checks every ceremony shares: rpIdHash (§7.2 step 15)
// and the BE/BS consistency rule (step 18).
func checkCommon(ad AuthenticatorData, rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad.RPIDHash[:], want[:]) {
		return ErrRPIDMismatch
	}
	if ad.Flags&FlagBE == 0 && ad.Flags&FlagBS != 0 {
		return ErrBackupState
	}
	return nil
}
