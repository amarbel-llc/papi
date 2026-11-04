// Package webauthn is the network-free, card-free core of papi's WebAuthn
// support (circus#414; design in docs/plans/2026-11-04-papi-enroll-webauthn.md):
// it parses a registration (attestationObject → authenticator data → COSE ES256
// key) and verifies an assertion against a registered credential, reporting the
// assurance it proves (touch, or touch plus PIN). It is stdlib-only (no cgo) so
// the wasm builds can link it; talking to an authenticator is not this package's
// job.
//
// Attestation statements are required to be present but are NOT verified: papi
// binds a credential to a card through the enrollment receipt (the new card's
// slot-9A signature and a trusted card's attestation), not through FIDO
// attestation.
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
	"io"
	"slices"
	"strings"
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

// maxCredentialIDLen: WebAuthn L3 §7.1 has the RP reject a credential id longer
// than 1023 bytes.
const maxCredentialIDLen = 1023

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

// Assurance is what a verified ceremony proves about the user. It is ordered:
// callers gate on `got >= required`. The zero value proves nothing and is what
// the verifiers return alongside an error.
type Assurance int

const (
	// AssuranceTouch: the user touched the authenticator (UP).
	AssuranceTouch Assurance = iota + 1
	// AssurancePIN: touch plus the authenticator's user verification, i.e. its
	// FIDO2 PIN (UP and UV).
	AssurancePIN
)

// AuthenticatorData is the parsed authenticator data (WebAuthn L3 §6.1).
type AuthenticatorData struct {
	RPIDHash    [32]byte
	Flags       byte
	SignCount   uint32
	Attested    *AttestedCredential // present iff FlagAT
	CredProtect int                 // credProtect extension output; 0 when absent
}

// AttestedCredential is the attested credential data block (WebAuthn L3 §6.5.2).
// AAGUID and COSEKey are kept for the enrollment receipt, which publishes the
// aaguid and the public key byte-exact as the authenticator encoded it.
type AttestedCredential struct {
	AAGUID       [16]byte
	CredentialID []byte
	PublicKey    *ecdsa.PublicKey
	COSEKey      []byte
}

// ParseAuthenticatorData parses raw authenticator data. Trailing bytes after the
// last present component are an error. The result shares no memory with b.
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
		if idLen > maxCredentialIDLen {
			return ad, fmt.Errorf("%w: credential id is %d bytes, at most %d allowed", ErrMalformed, idLen, maxCredentialIDLen)
		}
		if idLen > len(rest) {
			return ad, fmt.Errorf("%w: credential id length %d exceeds data", ErrMalformed, idLen)
		}
		ac.CredentialID = bytes.Clone(rest[:idLen])
		rest = rest[idLen:]
		keyItem, n, err := decodeItem(rest, 0)
		if err != nil {
			return ad, fmt.Errorf("credential public key: %w", err)
		}
		if ac.PublicKey, err = parseCOSEES256(keyItem); err != nil {
			return ad, err
		}
		ac.COSEKey = bytes.Clone(rest[:n])
		rest = rest[n:]
		ad.Attested = ac
	}
	if ad.Flags&FlagED != 0 {
		ext, n, err := decodeItem(rest, 0)
		if err != nil {
			return ad, fmt.Errorf("extensions: %w", err)
		}
		m, ok := ext.(map[any]any)
		if !ok {
			return ad, fmt.Errorf("%w: extensions are not a map", ErrMalformed)
		}
		if v, present := m["credProtect"]; present {
			lvl, ok := v.(int64)
			if !ok || lvl < 1 || lvl > 255 {
				return ad, fmt.Errorf("%w: credProtect output %v is not a level", ErrMalformed, v)
			}
			ad.CredProtect = int(lvl)
		}
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
	var pt [65]byte
	pt[0] = 4
	copy(pt[1:33], x)
	copy(pt[33:], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt[:])
	if err != nil {
		return nil, fmt.Errorf("%w: COSE point: %w", ErrMalformed, err)
	}
	return pub, nil
}

// Registration is a parsed attestationObject (WebAuthn L3 §6.5). The attStmt
// must be present but is neither kept nor verified (see the package comment).
type Registration struct {
	Format      string
	RawAuthData []byte
	AuthData    AuthenticatorData
}

// ParseAttestationObject parses a CBOR attestationObject {fmt, attStmt,
// authData} (a browser's create() result) and hands fmt and authData to
// NewRegistration. The result shares no memory with b.
func ParseAttestationObject(b []byte) (Registration, error) {
	v, err := decodeCBORExact(b)
	if err != nil {
		return Registration{}, fmt.Errorf("attestationObject: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return Registration{}, fmt.Errorf("%w: attestationObject is not a map", ErrMalformed)
	}
	format, ok := m["fmt"].(string)
	if !ok {
		return Registration{}, fmt.Errorf("%w: attestationObject.fmt missing", ErrMalformed)
	}
	if _, ok = m["attStmt"].(map[any]any); !ok {
		return Registration{}, fmt.Errorf("%w: attestationObject.attStmt missing", ErrMalformed)
	}
	authData, ok := m["authData"].([]byte)
	if !ok {
		return Registration{}, fmt.Errorf("%w: attestationObject.authData missing", ErrMalformed)
	}
	return NewRegistration(format, authData)
}

// NewRegistration builds a Registration from an attestation format name and raw
// authenticator data: the CLI path, where fido2-cred(1) prints fmt, the
// CBOR-wrapped authData (unwrap it with UnwrapByteString), the credential id,
// sig and x5c on separate lines instead of an attestationObject. The authData
// MUST carry attested credential data. The result shares no memory with
// authData. On error it returns the zero Registration.
func NewRegistration(format string, authData []byte) (Registration, error) {
	if format == "" {
		return Registration{}, fmt.Errorf("%w: attestation format is empty", ErrMalformed)
	}
	raw := bytes.Clone(authData)
	ad, err := ParseAuthenticatorData(raw)
	if err != nil {
		return Registration{}, err
	}
	if ad.Attested == nil {
		return Registration{}, fmt.Errorf("%w: registration authData has no attested credential data", ErrMalformed)
	}
	return Registration{Format: format, RawAuthData: raw, AuthData: ad}, nil
}

// RegistrationPolicy is what `papi enroll` demands of a freshly-made credential
// beyond what every ceremony checks (rpIdHash, BE/BS, UP).
type RegistrationPolicy struct {
	RequireUV          bool // the make-credential ceremony was PIN-verified
	RequireCredProtect int  // 0: don't check; else the credProtect level the authenticator must report
	RequireDeviceBound bool // reject a backup-eligible (synced) credential
}

// Credential checks the registration against rpID and policy and returns the
// credential record to publish (WebAuthn L3 §7.1, minus clientData and
// attestation-statement verification — see the package comment). The record
// copies the credential id and has SignCount 0 ("not tracked"), whatever count
// the registration carried: papi does not enforce signCount (design note §8
// Q4), and a YubiKey's counter is global across credentials anyway.
func (r Registration) Credential(rpID string, p RegistrationPolicy) (Credential, error) {
	ad := r.AuthData
	if ad.Flags&FlagAT == 0 || ad.Attested == nil {
		return Credential{}, fmt.Errorf("%w: registration authData has no attested credential data", ErrMalformed)
	}
	got, err := checkCeremony(ad, rpID)
	if err != nil {
		return Credential{}, err
	}
	if p.RequireUV && got < AssurancePIN {
		return Credential{}, ErrUserNotVerified
	}
	if p.RequireDeviceBound && ad.Flags&FlagBE != 0 {
		return Credential{}, ErrNotDeviceBound
	}
	if p.RequireCredProtect != 0 && ad.CredProtect != p.RequireCredProtect {
		return Credential{}, fmt.Errorf("%w: want %d, authenticator reported %d (0 = absent)",
			ErrCredProtect, p.RequireCredProtect, ad.CredProtect)
	}
	return Credential{
		ID:        bytes.Clone(ad.Attested.CredentialID),
		PublicKey: ad.Attested.PublicKey,
		RPID:      rpID,
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

// VerifyAssertion verifies an assertion signature over authData ||
// clientDataHash (WebAuthn L3 §7.2 steps 15–22, with the hash supplied by the
// caller: a CTAP client such as fido2-assert(1) signs a caller-chosen hash).
// User presence is always required, and authData carrying attested credential
// data (AT) is rejected: an assertion has none. On success it returns the parsed
// authenticator data, so the caller can record SignCount, and the assurance the
// assertion proves; the caller gates on `assurance >= required` (§7.2 step 17:
// UV matters only where the caller requires it). On every error it returns the
// zero AuthenticatorData and zero Assurance: nothing in authData is
// authenticated until the whole check passes.
func VerifyAssertion(cred Credential, authData, clientDataHash, sig []byte) (AuthenticatorData, Assurance, error) {
	ad, got, err := verifyAssertion(cred, authData, clientDataHash, sig)
	if err != nil {
		return AuthenticatorData{}, 0, err
	}
	return ad, got, nil
}

func verifyAssertion(cred Credential, authData, clientDataHash, sig []byte) (AuthenticatorData, Assurance, error) {
	if len(clientDataHash) != sha256.Size {
		return AuthenticatorData{}, 0, fmt.Errorf("%w: client data hash is %d bytes", ErrMalformed, len(clientDataHash))
	}
	ad, err := ParseAuthenticatorData(authData)
	if err != nil {
		return ad, 0, err
	}
	if ad.Flags&FlagAT != 0 {
		return ad, 0, fmt.Errorf("%w: assertion authData has the AT flag set", ErrMalformed)
	}
	got, err := checkCeremony(ad, cred.RPID)
	if err != nil {
		return ad, 0, err
	}
	if err := verifySignature(cred.PublicKey, authData, clientDataHash, sig); err != nil {
		return ad, 0, err
	}
	// Step 22: "a signal, but not proof" of cloning; papi treats it as a failure
	// whenever the caller tracks a count.
	if (cred.SignCount != 0 || ad.SignCount != 0) && ad.SignCount <= cred.SignCount {
		return ad, 0, fmt.Errorf("%w: stored %d, got %d", ErrSignCountRegression, cred.SignCount, ad.SignCount)
	}
	return ad, got, nil
}

// VerifyBrowserAssertion is VerifyAssertion for a browser ceremony: it checks
// clientDataJSON (type webauthn.get, the server's challenge, an expected origin)
// and verifies the signature over SHA-256(clientDataJSON).
func VerifyBrowserAssertion(cred Credential, authData, clientDataJSON, sig, challenge []byte, origins []string) (AuthenticatorData, Assurance, error) {
	if err := CheckClientDataJSON(clientDataJSON, "webauthn.get", challenge, origins); err != nil {
		return AuthenticatorData{}, 0, err
	}
	h := sha256.Sum256(clientDataJSON)
	return VerifyAssertion(cred, authData, h[:], sig)
}

// CheckClientDataJSON applies WebAuthn L3 §7.2 steps 10–13: type, challenge
// (canonical unpadded base64url), origin (exact match against origins), and
// crossOrigin not true. Parsing is strict where encoding/json is lax: raw must
// be one JSON object with no duplicate keys, and type/challenge/origin/
// crossOrigin are matched by exact case only (a key equal to one of them
// ignoring case, such as "Origin", is rejected). Other keys (topOrigin,
// tokenBinding, future members) are allowed and ignored.
func CheckClientDataJSON(raw []byte, wantType string, challenge []byte, origins []string) error {
	if len(challenge) == 0 {
		return fmt.Errorf("%w: no expected challenge supplied", ErrClientData)
	}
	c, err := parseClientData(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientData, err)
	}
	if c.Type != wantType {
		return fmt.Errorf("%w: type %q, want %q", ErrClientData, c.Type, wantType)
	}
	got, err := base64.RawURLEncoding.Strict().DecodeString(c.Challenge)
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

type clientData struct {
	Type        string
	Challenge   string
	Origin      string
	CrossOrigin bool
}

// parseClientData walks the top-level object key by key, so it sees every key
// exactly as written: duplicates and case variants of the four checked members
// are errors rather than silently resolved by encoding/json.
func parseClientData(raw []byte) (clientData, error) {
	var c clientData
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil {
		return c, err
	} else if tok != json.Delim('{') {
		return c, errors.New("clientDataJSON is not a JSON object")
	}
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return c, err
		}
		key := tok.(string) // inside an object the decoder only yields string keys here
		if seen[key] {
			return c, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var dst any
		switch key {
		case "type":
			dst = &c.Type
		case "challenge":
			dst = &c.Challenge
		case "origin":
			dst = &c.Origin
		case "crossOrigin":
			dst = &c.CrossOrigin
		default:
			for _, member := range []string{"type", "challenge", "origin", "crossOrigin"} {
				if strings.EqualFold(key, member) {
					return c, fmt.Errorf("key %q is a case variant of %q", key, member)
				}
			}
			dst = new(json.RawMessage)
		}
		if err := dec.Decode(dst); err != nil {
			return c, fmt.Errorf("key %q: %w", key, err)
		}
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return c, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return c, errors.New("trailing data after clientDataJSON object")
	}
	return c, nil
}

// checkCeremony covers the checks every ceremony shares — rpIdHash (§7.2 step
// 15), user presence (step 16) and the BE/BS consistency rule (step 18) — and
// returns the assurance the flags prove.
func checkCeremony(ad AuthenticatorData, rpID string) (Assurance, error) {
	if ad.RPIDHash != sha256.Sum256([]byte(rpID)) {
		return 0, ErrRPIDMismatch
	}
	if ad.Flags&FlagBE == 0 && ad.Flags&FlagBS != 0 {
		return 0, ErrBackupState
	}
	if ad.Flags&FlagUP == 0 {
		return 0, ErrUserNotPresent
	}
	if ad.Flags&FlagUV == 0 {
		return AssuranceTouch, nil
	}
	return AssurancePIN, nil
}

// verifySignature checks an ES256 signature over authData || clientDataHash
// (§7.2 step 20). It knows nothing of flags or counts.
func verifySignature(pub *ecdsa.PublicKey, authData, clientDataHash, sig []byte) error {
	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash)
	if pub == nil || !ecdsa.VerifyASN1(pub, h.Sum(nil), sig) {
		return ErrBadSignature
	}
	return nil
}
