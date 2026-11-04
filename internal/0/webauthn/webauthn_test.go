package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
)

// --- test-only CBOR encoder (the package itself only decodes) ---

type cborMap []cborKV

type cborKV struct {
	k, v any
}

func encHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	default:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
}

func enc(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return encHead(0, uint64(x))
		}
		return encHead(1, uint64(-1-x))
	case []byte:
		return append(encHead(2, uint64(len(x))), x...)
	case string:
		return append(encHead(3, uint64(len(x))), x...)
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case []any:
		out := encHead(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, enc(e)...)
		}
		return out
	case cborMap:
		out := encHead(5, uint64(len(x)))
		for _, kv := range x {
			out = append(out, enc(kv.k)...)
			out = append(out, enc(kv.v)...)
		}
		return out
	}
	panic("enc: unsupported type")
}

// --- deterministic fixtures ---

const testRPID = "linenisgreat.com"

// testKey is a fixed P-256 key so the fixtures are reproducible; only the ECDSA
// signatures vary (Go's ECDSA signing is randomized), and verification does not.
var testKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	d, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		panic(err)
	}
	return k
})

func coseES256(pub *ecdsa.PublicKey) cborMap {
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	return cborMap{{1, 2}, {3, -7}, {-1, 1}, {-2, raw[1:33]}, {-3, raw[33:65]}}
}

var testCredID = []byte("papi-test-credential-id-0123456789")

func buildAuthData(rpID string, flags byte, count uint32, attested []byte, ext []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte{}, h[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, count)
	b = append(b, attested...)
	b = append(b, ext...)
	return b
}

func attestedBlock(credID []byte, cose []byte) []byte {
	b := make([]byte, 16) // AAGUID (zero in the fixture)
	b = binary.BigEndian.AppendUint16(b, uint16(len(credID)))
	b = append(b, credID...)
	return append(b, cose...)
}

func registrationAuthData(flags byte, ext []byte) []byte {
	return buildAuthData(testRPID, flags, 0,
		attestedBlock(testCredID, enc(coseES256(&testKey().PublicKey))), ext)
}

func attObj(fmtName string, authData []byte) []byte {
	return enc(cborMap{{"fmt", fmtName}, {"attStmt", cborMap{}}, {"authData", authData}})
}

func sign(t *testing.T, authData, cdh []byte) []byte {
	t.Helper()
	msg := append(append([]byte{}, authData...), cdh...)
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, testKey(), h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func testCredential() Credential {
	return Credential{ID: testCredID, PublicKey: &testKey().PublicKey, RPID: testRPID}
}

func clientDataJSON(typ string, challenge []byte, origin string, crossOrigin bool) []byte {
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": crossOrigin,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// --- registration parsing ---

func TestParseRegistrationNone(t *testing.T) {
	ext := enc(cborMap{{"credProtect", 2}})
	ad := registrationAuthData(FlagUP|FlagUV|FlagAT|FlagED, ext)
	reg, err := ParseAttestationObject(attObj("none", ad))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Format != "none" {
		t.Errorf("fmt = %q", reg.Format)
	}
	ac := reg.AuthData.Attested
	if ac == nil {
		t.Fatal("no attested credential data")
	}
	if !bytes.Equal(ac.CredentialID, testCredID) {
		t.Errorf("credential id = %x", ac.CredentialID)
	}
	if !ac.PublicKey.Equal(&testKey().PublicKey) {
		t.Error("public key mismatch")
	}
	if !bytes.Equal(ac.COSEKey, enc(coseES256(&testKey().PublicKey))) {
		t.Error("COSE key bytes not preserved")
	}
	if reg.AuthData.CredProtect != 2 {
		t.Errorf("credProtect = %d; want 2", reg.AuthData.CredProtect)
	}
	if !bytes.Equal(reg.RawAuthData, ad) {
		t.Error("raw authData not preserved")
	}
	cred, err := reg.Credential(testRPID, RegistrationPolicy{RequireUV: true, RequireCredProtect: 2})
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if !bytes.Equal(cred.ID, testCredID) || cred.RPID != testRPID {
		t.Errorf("credential = %+v", cred)
	}
}

func TestRegistrationPolicyRejections(t *testing.T) {
	cases := []struct {
		name  string
		flags byte
		ext   []byte
		rpID  string
		pol   RegistrationPolicy
		want  error
	}{
		{"rpid mismatch", FlagUP | FlagAT, nil, "evil.example", RegistrationPolicy{}, ErrRPIDMismatch},
		{"no UP", FlagAT, nil, testRPID, RegistrationPolicy{}, ErrUserNotPresent},
		{"UV required", FlagUP | FlagAT, nil, testRPID, RegistrationPolicy{RequireUV: true}, ErrUserNotVerified},
		{"credProtect missing", FlagUP | FlagAT, nil, testRPID, RegistrationPolicy{RequireCredProtect: 2}, ErrCredProtect},
		{"credProtect wrong", FlagUP | FlagAT | FlagED, enc(cborMap{{"credProtect", 3}}), testRPID, RegistrationPolicy{RequireCredProtect: 2}, ErrCredProtect},
		{"backup eligible (synced passkey)", FlagUP | FlagAT | FlagBE | FlagED, enc(cborMap{{"credProtect", 2}}), testRPID, RegistrationPolicy{RequireDeviceBound: true}, ErrNotDeviceBound},
		{"BS without BE", FlagUP | FlagAT | FlagBS, nil, testRPID, RegistrationPolicy{}, ErrBackupState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, err := ParseAttestationObject(attObj("none", registrationAuthData(c.flags, c.ext)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reg.Credential(c.rpID, c.pol); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseAttestationObjectMalformed(t *testing.T) {
	good := registrationAuthData(FlagUP|FlagAT, nil)
	cases := map[string][]byte{
		"not a map":            enc([]any{1, 2}),
		"missing authData":     enc(cborMap{{"fmt", "none"}, {"attStmt", cborMap{}}}),
		"missing attStmt":      enc(cborMap{{"fmt", "none"}, {"authData", good}}),
		"trailing after map":   append(attObj("none", good), 0x00),
		"authData trailing":    attObj("none", append(append([]byte{}, good...), 0x01)),
		"AT flag but no data":  attObj("none", buildAuthData(testRPID, FlagUP|FlagAT, 0, nil, nil)),
		"short authData":       attObj("none", []byte{1, 2, 3}),
		"no AT flag":           attObj("none", buildAuthData(testRPID, FlagUP, 0, nil, nil)),
		"credProtect not int":  attObj("none", registrationAuthData(FlagUP|FlagAT|FlagED, enc(cborMap{{"credProtect", "2"}}))),
		"credProtect zero":     attObj("none", registrationAuthData(FlagUP|FlagAT|FlagED, enc(cborMap{{"credProtect", 0}}))),
		"extensions not a map": attObj("none", registrationAuthData(FlagUP|FlagAT|FlagED, enc(1))),
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAttestationObject(obj); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestCOSEKeyRejections(t *testing.T) {
	pub := coseES256(&testKey().PublicKey)
	with := func(k, v any) cborMap {
		m := append(cborMap{}, pub...)
		for i := range m {
			if m[i].k == k {
				m[i].v = v
			}
		}
		return m
	}
	without := func(k any) cborMap {
		var m cborMap
		for _, kv := range pub {
			if kv.k != k {
				m = append(m, kv)
			}
		}
		return m
	}
	offCurve := bytes.Repeat([]byte{0x01}, 32)
	cases := map[string]cborMap{
		"alg RS256":   with(3, -257),
		"kty OKP":     with(1, 1),
		"crv P-384":   with(-1, 2),
		"short x":     with(-2, []byte{1, 2, 3}),
		"off curve":   with(-3, offCurve),
		"missing alg": without(3),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			ad := buildAuthData(testRPID, FlagUP|FlagAT, 0, attestedBlock(testCredID, enc(m)), nil)
			if _, err := ParseAuthenticatorData(ad); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// --- assertions: the assurance each one proves ---

func TestVerifyAssertionAssurance(t *testing.T) {
	cdh := sha256.Sum256([]byte("cli client data"))
	cases := []struct {
		name  string
		flags byte
		want  Assurance
		err   error
	}{
		{"UP only proves touch", FlagUP, AssuranceTouch, nil},
		{"UP+UV proves PIN", FlagUP | FlagUV, AssurancePIN, nil},
		{"no UP is rejected", 0, 0, ErrUserNotPresent},
		{"UV without UP is rejected", FlagUV, 0, ErrUserNotPresent},
		{"BS without BE", FlagUP | FlagBS, 0, ErrBackupState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ad := buildAuthData(testRPID, c.flags, 7, nil, nil)
			_, got, err := VerifyAssertion(testCredential(), ad, cdh[:], sign(t, ad, cdh[:]))
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v", err, c.err)
			}
			if got != c.want {
				t.Fatalf("assurance = %d, want %d", got, c.want)
			}
		})
	}
	// One credential serves both tiers: a PIN assertion satisfies a touch gate.
	if AssurancePIN < AssuranceTouch {
		t.Fatal("assurance levels are not ordered")
	}
}

func TestVerifyAssertionRejections(t *testing.T) {
	cdh := sha256.Sum256([]byte("x"))
	ad := buildAuthData(testRPID, FlagUP, 1, nil, nil)
	sig := sign(t, ad, cdh[:])
	tampered := append([]byte{}, ad...)
	tampered[len(tampered)-1] ^= 0xff
	other := sha256.Sum256([]byte("y"))
	evil := buildAuthData("evil.example", FlagUP, 1, nil, nil)

	cases := []struct {
		name          string
		authData, cdh []byte
		sig           []byte
		want          error
	}{
		{"tampered authData", tampered, cdh[:], sig, ErrBadSignature},
		{"wrong cdh", ad, other[:], sig, ErrBadSignature},
		{"rpId mismatch", evil, cdh[:], sign(t, evil, cdh[:]), ErrRPIDMismatch},
		{"short cdh", ad, cdh[:16], sig, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got, err := VerifyAssertion(testCredential(), c.authData, c.cdh, c.sig)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if got != 0 {
				t.Fatalf("assurance %d returned with an error", got)
			}
		})
	}
}

func TestVerifyAssertionSignCount(t *testing.T) {
	cdh := sha256.Sum256([]byte("c"))
	cases := []struct {
		stored, got uint32
		want        error
	}{
		{0, 0, nil}, // authenticator without a counter
		{5, 6, nil}, // advanced
		{5, 5, ErrSignCountRegression},
		{5, 4, ErrSignCountRegression},
		{0, 9, nil}, // first use with a counter
		{9, 0, ErrSignCountRegression},
	}
	for _, c := range cases {
		cred := testCredential()
		cred.SignCount = c.stored
		ad := buildAuthData(testRPID, FlagUP, c.got, nil, nil)
		got, _, err := VerifyAssertion(cred, ad, cdh[:], sign(t, ad, cdh[:]))
		if !errors.Is(err, c.want) {
			t.Errorf("stored %d got %d: err = %v, want %v", c.stored, c.got, err, c.want)
		}
		if err == nil && got.SignCount != c.got {
			t.Errorf("returned count %d", got.SignCount)
		}
	}
}

// A credential made by a CLI CTAP client (any clientDataHash at registration)
// is asserted through a browser: the verifier needs only the registered public
// key + rpId and the assertion's own clientDataJSON (WebAuthn L3 §7.2).
func TestBrowserAssertionOfCLIMadeCredential(t *testing.T) {
	reg, err := ParseAttestationObject(attObj("none", registrationAuthData(FlagUP|FlagUV|FlagAT, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := reg.Credential(testRPID, RegistrationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("server-minted-challenge-32-bytes")
	origins := []string{"https://linenisgreat.com"}
	cdj := clientDataJSON("webauthn.get", challenge, origins[0], false)
	ad := buildAuthData(testRPID, FlagUP|FlagUV, 1, nil, nil)
	h := sha256.Sum256(cdj)
	sig := sign(t, ad, h[:])

	if _, got, err := VerifyBrowserAssertion(cred, ad, cdj, sig, challenge, origins); err != nil || got != AssurancePIN {
		t.Fatalf("browser assertion: assurance %d, err %v", got, err)
	}
	if _, _, err := VerifyBrowserAssertion(cred, ad, cdj, sig, []byte("other challenge"), origins); !errors.Is(err, ErrClientData) {
		t.Errorf("wrong challenge: %v", err)
	}
	if _, _, err := VerifyBrowserAssertion(cred, ad, cdj, sig, challenge, []string{"https://evil.example"}); !errors.Is(err, ErrClientData) {
		t.Errorf("wrong origin: %v", err)
	}
}

func TestCheckClientDataJSON(t *testing.T) {
	ch := []byte{1, 2, 3, 4}
	origins := []string{"https://linenisgreat.com"}
	if err := CheckClientDataJSON(clientDataJSON("webauthn.get", ch, origins[0], false), "webauthn.get", ch, origins); err != nil {
		t.Errorf("good: %v", err)
	}
	bad := map[string][]byte{
		"type create":  clientDataJSON("webauthn.create", ch, origins[0], false),
		"origin":       clientDataJSON("webauthn.get", ch, "https://linenisgreat.com.evil.example", false),
		"cross origin": clientDataJSON("webauthn.get", ch, origins[0], true),
		"not json":     []byte("{"),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			if err := CheckClientDataJSON(b, "webauthn.get", ch, origins); !errors.Is(err, ErrClientData) {
				t.Errorf("err = %v", err)
			}
		})
	}
	// Regression: an empty expected challenge must not match an empty one.
	emptyChallenge := clientDataJSON("webauthn.get", nil, origins[0], false)
	if err := CheckClientDataJSON(emptyChallenge, "webauthn.get", nil, origins); !errors.Is(err, ErrClientData) {
		t.Errorf("empty expected challenge accepted: %v", err)
	}
}

// Published vector: libfido2 1.17.0 regress/assert.c (valid ES256 assertion;
// es256_pk, cdh, authdata, sig, rp "localhost"; up=false, uv=false). The
// authdata is the CBOR byte string fido2-assert(1) emits, so this also exercises
// unwrapping the libfido2 tool output shape. The signature is valid, but papi
// always requires UP, so VerifyAssertion rejects it.
func TestLibfido2RegressAssertVector(t *testing.T) {
	pk := mustHex(t, "34eb9977029c3638bbc2aea0a018c664fce84992d7749e0c468c9da6df46f784"+
		"601e0f8b23854a9aecc1089f30d00dd7767b5548917c4f0f641a1df8be14908a")
	cdh := mustHex(t, "ec8d8f78424a2bb78234aaca07a1f656421cb6f6b3008652352da2624abe8976")
	wrapped := mustHex(t, "582549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630000000003")
	sig := mustHex(t, "3046022100f6d1a3d5242bdeeea09089cdf89ebd6b4d5579e4c14227b79b9ba40ae247640e"+
		"022100e5c9c2834731c726e525b2b439a7fc3d70bee9810d4a62a9ab4a91c07d2d231e")

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, pk...))
	if err != nil {
		t.Fatal(err)
	}
	ad, err := UnwrapByteString(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthenticatorData(ad)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SignCount != 3 || parsed.Flags != 0 {
		t.Errorf("count %d flags %#x", parsed.SignCount, parsed.Flags)
	}
	if err := verifySignature(pub, ad, cdh, sig); err != nil {
		t.Fatalf("libfido2 vector signature: %v", err)
	}
	cred := Credential{PublicKey: pub, RPID: "localhost"}
	if _, got, err := VerifyAssertion(cred, ad, cdh, sig); !errors.Is(err, ErrUserNotPresent) || got != 0 {
		t.Errorf("VerifyAssertion: assurance %d, err %v; want ErrUserNotPresent", got, err)
	}
}

// --- code-review regressions ---

// A Registration built by hand (not through a parser) may lack attested
// credential data; Credential must refuse it rather than dereference nil.
func TestRegistrationCredentialWithoutAttestedData(t *testing.T) {
	ad, err := ParseAuthenticatorData(buildAuthData(testRPID, FlagUP, 0, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	reg := Registration{Format: "none", AuthData: ad}
	if _, err := reg.Credential(testRPID, RegistrationPolicy{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// fido2-cred(1) prints fmt and the CBOR-wrapped authData on separate lines, not
// an attestationObject: NewRegistration is that path.
func TestNewRegistrationFromCLIOutput(t *testing.T) {
	ad := registrationAuthData(FlagUP|FlagUV|FlagAT, nil)
	unwrapped, err := UnwrapByteString(enc(ad))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistration("packed", unwrapped)
	if err != nil {
		t.Fatal(err)
	}
	fromObj, err := ParseAttestationObject(attObj("packed", ad))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reg, fromObj) {
		t.Errorf("NewRegistration and ParseAttestationObject disagree:\n%+v\n%+v", reg, fromObj)
	}
	unwrapped[40] ^= 0xff // shares no memory with the input
	if !bytes.Equal(reg.RawAuthData, ad) {
		t.Error("RawAuthData aliases the caller's slice")
	}
	if _, err := reg.Credential(testRPID, RegistrationPolicy{RequireUV: true}); err != nil {
		t.Errorf("Credential: %v", err)
	}

	bad := map[string]struct {
		fmt      string
		authData []byte
	}{
		"no AT flag":  {"packed", buildAuthData(testRPID, FlagUP, 0, nil, nil)},
		"short":       {"packed", []byte{1, 2, 3}},
		"empty fmt":   {"", ad},
		"AT but none": {"packed", buildAuthData(testRPID, FlagUP|FlagAT, 0, nil, nil)},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRegistration(c.fmt, c.authData); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// The returned AuthenticatorData is unauthenticated until the whole check
// passes, so every error returns the zero value (a caller must not record, say,
// a forged signCount of 0xFFFFFFFF).
func TestVerifyAssertionErrorReturnsZeroAuthData(t *testing.T) {
	cdh := sha256.Sum256([]byte("z"))
	forged := buildAuthData(testRPID, FlagUP, 0xFFFFFFFF, nil, nil)
	notPresent := buildAuthData(testRPID, 0, 0xFFFFFFFF, nil, nil)
	cases := map[string]struct {
		authData, sig []byte
		want          error
	}{
		"bad signature": {forged, []byte{0x30, 0x00}, ErrBadSignature},
		"no UP":         {notPresent, sign(t, notPresent, cdh[:]), ErrUserNotPresent},
		"trailing":      {append(append([]byte{}, forged...), 0), sign(t, forged, cdh[:]), ErrMalformed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cred := testCredential()
			cred.SignCount = 0xFFFFFFFF
			ad, got, err := VerifyAssertion(cred, c.authData, cdh[:], c.sig)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if !reflect.DeepEqual(ad, AuthenticatorData{}) || got != 0 {
				t.Fatalf("error returned non-zero results: ad %+v, assurance %d", ad, got)
			}
		})
	}
	// Signature valid, count regressed: still zero.
	cred := testCredential()
	cred.SignCount = 9
	ad := buildAuthData(testRPID, FlagUP, 3, nil, nil)
	if got, _, err := VerifyAssertion(cred, ad, cdh[:], sign(t, ad, cdh[:])); !errors.Is(err, ErrSignCountRegression) ||
		!reflect.DeepEqual(got, AuthenticatorData{}) {
		t.Fatalf("regression: ad %+v, err %v", got, err)
	}
}

func TestCheckClientDataJSONStrictKeys(t *testing.T) {
	ch := []byte{1, 2, 3, 4}
	chB64 := base64.RawURLEncoding.EncodeToString(ch)
	origin := "https://linenisgreat.com"
	origins := []string{origin}
	doc := func(body string) []byte { return []byte(body) }
	good := map[string][]byte{
		"exact keys": doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `","crossOrigin":false}`),
		"unknown keys allowed": doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin +
			`","topOrigin":"x","tokenBinding":{"status":"present","type":"nested"},"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"}`),
	}
	for name, b := range good {
		t.Run(name, func(t *testing.T) {
			if err := CheckClientDataJSON(b, "webauthn.get", ch, origins); err != nil {
				t.Fatalf("err = %v", err)
			}
		})
	}
	bad := map[string][]byte{
		"TYPE":             doc(`{"TYPE":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `"}`),
		"Origin":           doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","Origin":"` + origin + `"}`),
		"Origin shadow":    doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `","Origin":"` + origin + `"}`),
		"CrossOrigin":      doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `","CrossOrigin":true,"crossOrigin":false}`),
		"duplicate type":   doc(`{"type":"webauthn.create","challenge":"` + chB64 + `","origin":"` + origin + `","type":"webauthn.get"}`),
		"duplicate other":  doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `","x":1,"x":2}`),
		"type not string":  doc(`{"type":1,"challenge":"` + chB64 + `","origin":"` + origin + `"}`),
		"not an object":    doc(`["type"]`),
		"trailing data":    doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `"}{}`),
		"crossOrigin text": doc(`{"type":"webauthn.get","challenge":"` + chB64 + `","origin":"` + origin + `","crossOrigin":"true"}`),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			if err := CheckClientDataJSON(b, "webauthn.get", ch, origins); !errors.Is(err, ErrClientData) {
				t.Fatalf("err = %v, want ErrClientData", err)
			}
		})
	}
}

// Credential copies the id (no aliasing into the Registration) and records
// signCount 0: §8 Q4's default does not track counts.
func TestRegistrationCredentialCopiesIDAndZeroesCount(t *testing.T) {
	ad := buildAuthData(testRPID, FlagUP|FlagAT, 5,
		attestedBlock(testCredID, enc(coseES256(&testKey().PublicKey))), nil)
	reg, err := NewRegistration("none", ad)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := reg.Credential(testRPID, RegistrationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if cred.SignCount != 0 {
		t.Errorf("SignCount = %d, want 0", cred.SignCount)
	}
	reg.AuthData.Attested.CredentialID[0] ^= 0xff
	if !bytes.Equal(cred.ID, testCredID) {
		t.Error("Credential.ID aliases the registration's credential id")
	}
}

// WebAuthn L3 §7.1: a credential id longer than 1023 bytes is rejected.
func TestCredentialIDLengthLimit(t *testing.T) {
	cose := enc(coseES256(&testKey().PublicKey))
	ok := buildAuthData(testRPID, FlagUP|FlagAT, 0, attestedBlock(bytes.Repeat([]byte{7}, 1023), cose), nil)
	if _, err := ParseAuthenticatorData(ok); err != nil {
		t.Errorf("1023-byte id: %v", err)
	}
	long := buildAuthData(testRPID, FlagUP|FlagAT, 0, attestedBlock(bytes.Repeat([]byte{7}, 1024), cose), nil)
	if _, err := ParseAuthenticatorData(long); !errors.Is(err, ErrMalformed) {
		t.Errorf("1024-byte id: err = %v, want ErrMalformed", err)
	}
}

// An assertion's authData carries no attested credential data; reserved (RFU)
// flag bits are left alone for future use.
func TestVerifyAssertionFlagBits(t *testing.T) {
	cdh := sha256.Sum256([]byte("f"))
	withAT := buildAuthData(testRPID, FlagUP|FlagAT, 1,
		attestedBlock(testCredID, enc(coseES256(&testKey().PublicKey))), nil)
	if _, _, err := VerifyAssertion(testCredential(), withAT, cdh[:], sign(t, withAT, cdh[:])); !errors.Is(err, ErrMalformed) {
		t.Errorf("AT in assertion: err = %v, want ErrMalformed", err)
	}
	rfu := buildAuthData(testRPID, FlagUP|0x02|0x20, 1, nil, nil)
	if _, got, err := VerifyAssertion(testCredential(), rfu, cdh[:], sign(t, rfu, cdh[:])); err != nil || got != AssuranceTouch {
		t.Errorf("RFU bits: assurance %d, err %v", got, err)
	}
}

// The challenge must be canonical unpadded base64url: non-zero trailing bits
// decode to the same bytes under a lax decoder.
func TestCheckClientDataJSONNonCanonicalChallenge(t *testing.T) {
	ch := []byte{1, 2, 3, 4} // canonical "AQIDBA"
	origin := "https://linenisgreat.com"
	if got := base64.RawURLEncoding.EncodeToString(ch); got != "AQIDBA" {
		t.Fatalf("fixture: %q", got)
	}
	b := []byte(`{"type":"webauthn.get","challenge":"AQIDBB","origin":"` + origin + `"}`)
	if err := CheckClientDataJSON(b, "webauthn.get", ch, []string{origin}); !errors.Is(err, ErrClientData) {
		t.Fatalf("non-canonical challenge accepted: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- the CBOR subset decoder ---

func TestDecodeCBORRejects(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, maxCBORDepth+1)
	deep = append(deep, 0x00)
	cases := map[string][]byte{
		"indefinite bytes":    {0x5f, 0x41, 0x00, 0xff},
		"indefinite map":      {0xbf, 0xff},
		"tag":                 {0xc1, 0x00},
		"float":               {0xfa, 0, 0, 0, 0},
		"length overflow":     {0x5a, 0xff, 0xff, 0xff, 0xff},
		"array length lies":   {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00},
		"map length lies":     {0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00},
		"truncated":           {0x58},
		"truncated head":      {0x19, 0x01},
		"duplicate key":       enc(cborMap{{1, 1}, {1, 2}}),
		"byte string map key": {0xa1, 0x41, 0x00, 0x00},
		"too deep":            deep,
		"uint too big":        {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"nint too big":        {0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"text not UTF-8":      {0x62, 0xff, 0xfe},
		"map key not UTF-8":   {0xa1, 0x61, 0x80, 0x00},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeItem(in, 0); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestDecodeCBORValues(t *testing.T) {
	in := enc(cborMap{
		{"a", []any{1, -7, []byte{9}, "s", true, false}},
		{-2, cborMap{}},
		{"w", []any{24, 300, 70000, -25}}, // 1-, 2- and 4-byte arguments
	})
	v, n, err := decodeItem(in, 0)
	if err != nil || n != len(in) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	want := map[any]any{
		"a":       []any{int64(1), int64(-7), []byte{9}, "s", true, false},
		int64(-2): map[any]any{},
		"w":       []any{int64(24), int64(300), int64(70000), int64(-25)},
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("got %#v\nwant %#v", v, want)
	}
	// 8-byte argument (the test encoder stops at 4 bytes).
	if v, _, err := decodeItem([]byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}, 0); err != nil || v != int64(1<<32) {
		t.Errorf("uint64 head: %v, %v", v, err)
	}
}
