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
	"sort"
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
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	d, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func coseES256(pub *ecdsa.PublicKey) cborMap {
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	return cborMap{{1, 2}, {3, -7}, {-1, 1}, {-2, raw[1:33]}, {-3, raw[33:65]}}
}

var testCredID = []byte("papi-test-credential-id-0123456789")

func rpHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

func buildAuthData(rpID string, flags byte, count uint32, attested []byte, ext []byte) []byte {
	b := append([]byte{}, rpHash(rpID)...)
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

func registrationAuthData(t *testing.T, flags byte, ext []byte) []byte {
	t.Helper()
	return buildAuthData(testRPID, flags, 0,
		attestedBlock(testCredID, enc(coseES256(&testKey(t).PublicKey))), ext)
}

func attObj(fmtName string, authData []byte) []byte {
	return enc(cborMap{{"fmt", fmtName}, {"attStmt", cborMap{}}, {"authData", authData}})
}

func sign(t *testing.T, authData, cdh []byte) []byte {
	t.Helper()
	msg := append(append([]byte{}, authData...), cdh...)
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, testKey(t), h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func testCredential(t *testing.T) Credential {
	return Credential{ID: testCredID, PublicKey: &testKey(t).PublicKey, RPID: testRPID}
}

// --- registration parsing ---

func TestParseRegistrationNone(t *testing.T) {
	ext := enc(cborMap{{"credProtect", 2}})
	ad := registrationAuthData(t, FlagUP|FlagUV|FlagAT|FlagED, ext)
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
	if !ac.PublicKey.Equal(&testKey(t).PublicKey) {
		t.Error("public key mismatch")
	}
	if lvl, ok := reg.AuthData.CredProtect(); !ok || lvl != 2 {
		t.Errorf("credProtect = %d, %v; want 2", lvl, ok)
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
	cp2 := enc(cborMap{{"credProtect", 2}})
	cases := []struct {
		name string
		ad   func() []byte
		rpID string
		pol  RegistrationPolicy
		want error
	}{
		{"rpid mismatch", func() []byte { return registrationAuthData(t, FlagUP|FlagAT, nil) }, "evil.example", RegistrationPolicy{}, ErrRPIDMismatch},
		{"no UP", func() []byte { return registrationAuthData(t, FlagAT, nil) }, testRPID, RegistrationPolicy{}, ErrUserNotPresent},
		{"UV required", func() []byte { return registrationAuthData(t, FlagUP|FlagAT, nil) }, testRPID, RegistrationPolicy{RequireUV: true}, ErrUserNotVerified},
		{"credProtect missing", func() []byte { return registrationAuthData(t, FlagUP|FlagAT, nil) }, testRPID, RegistrationPolicy{RequireCredProtect: 2}, ErrCredProtect},
		{"credProtect wrong", func() []byte {
			return registrationAuthData(t, FlagUP|FlagAT|FlagED, enc(cborMap{{"credProtect", 3}}))
		}, testRPID, RegistrationPolicy{RequireCredProtect: 2}, ErrCredProtect},
		{"backup eligible (synced passkey)", func() []byte { return registrationAuthData(t, FlagUP|FlagAT|FlagBE|FlagED, cp2) }, testRPID, RegistrationPolicy{RequireDeviceBound: true}, ErrNotDeviceBound},
		{"BS without BE", func() []byte { return registrationAuthData(t, FlagUP|FlagAT|FlagBS, nil) }, testRPID, RegistrationPolicy{}, ErrBackupState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, err := ParseAttestationObject(attObj("none", c.ad()))
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
	good := registrationAuthData(t, FlagUP|FlagAT, nil)
	cases := map[string][]byte{
		"not a map":           enc([]any{1, 2}),
		"missing authData":    enc(cborMap{{"fmt", "none"}, {"attStmt", cborMap{}}}),
		"trailing after map":  append(attObj("none", good), 0x00),
		"authData trailing":   attObj("none", append(append([]byte{}, good...), 0x01)),
		"AT flag but no data": attObj("none", buildAuthData(testRPID, FlagUP|FlagAT, 0, nil, nil)),
		"short authData":      attObj("none", []byte{1, 2, 3}),
		"no AT flag":          attObj("none", buildAuthData(testRPID, FlagUP, 0, nil, nil)),
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAttestationObject(obj); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCOSEKeyRejections(t *testing.T) {
	pub := coseES256(&testKey(t).PublicKey)
	with := func(k, v any) cborMap {
		m := append(cborMap{}, pub...)
		for i := range m {
			if m[i].k == k {
				m[i].v = v
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
		"missing alg": {{1, 2}, {-1, 1}, {-2, pub[3].v}, {-3, pub[4].v}},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			ad := buildAuthData(testRPID, FlagUP|FlagAT, 0, attestedBlock(testCredID, enc(m)), nil)
			if _, err := ParseAuthenticatorData(ad); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// --- assertions: the two tiers ---

func TestVerifyAssertionTiers(t *testing.T) {
	cdh := sha256.Sum256([]byte("cli client data"))
	cases := []struct {
		name  string
		flags byte
		pol   AssertionPolicy
		want  error
	}{
		{"touch tier, UP only", FlagUP, TierTouch, nil},
		{"touch tier ignores UV", FlagUP | FlagUV, TierTouch, nil},
		{"pin tier, UP+UV", FlagUP | FlagUV, TierPIN, nil},
		{"pin tier rejects UP only", FlagUP, TierPIN, ErrUserNotVerified},
		{"touch tier rejects no UP", 0, TierTouch, ErrUserNotPresent},
		{"pin tier rejects UV without UP", FlagUV, TierPIN, ErrUserNotPresent},
		{"BS without BE", FlagUP | FlagBS, TierTouch, ErrBackupState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ad := buildAuthData(testRPID, c.flags, 7, nil, nil)
			_, err := VerifyAssertion(testCredential(t), ad, cdh[:], sign(t, ad, cdh[:]), c.pol)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestVerifyAssertionRejectsTamperAndRPID(t *testing.T) {
	cdh := sha256.Sum256([]byte("x"))
	ad := buildAuthData(testRPID, FlagUP, 1, nil, nil)
	sig := sign(t, ad, cdh[:])

	tampered := append([]byte{}, ad...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := VerifyAssertion(testCredential(t), tampered, cdh[:], sig, TierTouch); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered authData: %v", err)
	}
	other := sha256.Sum256([]byte("y"))
	if _, err := VerifyAssertion(testCredential(t), ad, other[:], sig, TierTouch); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong cdh: %v", err)
	}
	evil := buildAuthData("evil.example", FlagUP, 1, nil, nil)
	if _, err := VerifyAssertion(testCredential(t), evil, cdh[:], sign(t, evil, cdh[:]), TierTouch); !errors.Is(err, ErrRPIDMismatch) {
		t.Errorf("rpId: %v", err)
	}
	if _, err := VerifyAssertion(testCredential(t), ad, cdh[:16], sig, TierTouch); err == nil {
		t.Error("short client data hash accepted")
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
		cred := testCredential(t)
		cred.SignCount = c.stored
		ad := buildAuthData(testRPID, FlagUP, c.got, nil, nil)
		got, err := VerifyAssertion(cred, ad, cdh[:], sign(t, ad, cdh[:]), TierTouch)
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
	reg, err := ParseAttestationObject(attObj("none", registrationAuthData(t, FlagUP|FlagUV|FlagAT, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := reg.Credential(testRPID, RegistrationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("server-minted-challenge-32-bytes")
	cdj, _ := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      "https://linenisgreat.com",
		"crossOrigin": false,
	})
	ad := buildAuthData(testRPID, FlagUP|FlagUV, 1, nil, nil)
	h := sha256.Sum256(cdj)
	sig := sign(t, ad, h[:])
	origins := []string{"https://linenisgreat.com"}

	if _, err := VerifyBrowserAssertion(cred, ad, cdj, sig, challenge, origins, TierPIN); err != nil {
		t.Fatalf("browser assertion: %v", err)
	}
	if _, err := VerifyBrowserAssertion(cred, ad, cdj, sig, []byte("other challenge"), origins, TierPIN); !errors.Is(err, ErrClientData) {
		t.Errorf("wrong challenge: %v", err)
	}
	if _, err := VerifyBrowserAssertion(cred, ad, cdj, sig, challenge, []string{"https://evil.example"}, TierPIN); !errors.Is(err, ErrClientData) {
		t.Errorf("wrong origin: %v", err)
	}
}

func TestCheckClientDataJSON(t *testing.T) {
	ch := []byte{1, 2, 3, 4}
	mk := func(typ, origin string, cross bool) []byte {
		b, _ := json.Marshal(map[string]any{
			"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(ch),
			"origin": origin, "crossOrigin": cross,
		})
		return b
	}
	origins := []string{"https://linenisgreat.com"}
	if err := CheckClientDataJSON(mk("webauthn.get", origins[0], false), "webauthn.get", ch, origins); err != nil {
		t.Errorf("good: %v", err)
	}
	bad := map[string][]byte{
		"type create":  mk("webauthn.create", origins[0], false),
		"origin":       mk("webauthn.get", "https://linenisgreat.com.evil.example", false),
		"cross origin": mk("webauthn.get", origins[0], true),
		"not json":     []byte("{"),
	}
	for name, b := range bad {
		if err := CheckClientDataJSON(b, "webauthn.get", ch, origins); !errors.Is(err, ErrClientData) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	emptyChallenge, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": "", "origin": origins[0]})
	if err := CheckClientDataJSON(emptyChallenge, "webauthn.get", nil, origins); !errors.Is(err, ErrClientData) {
		t.Errorf("empty expected challenge accepted: %v", err)
	}
}

// Published vector: libfido2 1.17.0 regress/assert.c (valid ES256 assertion;
// es256_pk, cdh, authdata, sig, rp "localhost"; up=false, uv=false). The
// authdata is the CBOR byte string fido2-assert(1) emits, so this also exercises
// unwrapping the libfido2 tool output shape.
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
	cred := Credential{PublicKey: pub, RPID: "localhost"}
	got, err := VerifyAssertion(cred, ad, cdh, sig, AssertionPolicy{})
	if err != nil {
		t.Fatalf("libfido2 vector: %v", err)
	}
	if got.SignCount != 3 || got.Flags != 0 {
		t.Errorf("count %d flags %#x", got.SignCount, got.Flags)
	}
	// The same bytes fail either papi tier: the vector carries no UP bit.
	if _, err := VerifyAssertion(cred, ad, cdh, sig, TierTouch); !errors.Is(err, ErrUserNotPresent) {
		t.Errorf("TierTouch: %v", err)
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
		"indefinite bytes": {0x5f, 0x41, 0x00, 0xff},
		"indefinite map":   {0xbf, 0xff},
		"tag":              {0xc1, 0x00},
		"float":            {0xfa, 0, 0, 0, 0},
		"length overflow":  {0x5a, 0xff, 0xff, 0xff, 0xff},
		"truncated":        {0x58},
		"duplicate key":    enc(cborMap{{1, 1}, {1, 2}}),
		"too deep":         deep,
		"uint too big":     {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, _, err := decodeCBOR(cases[n]); err == nil {
			t.Errorf("%s: expected error", n)
		}
	}
}

func TestDecodeCBORValues(t *testing.T) {
	in := enc(cborMap{{"a", []any{1, -7, []byte{9}, "s", true, false}}, {-2, cborMap{}}})
	v, n, err := decodeCBOR(in)
	if err != nil || n != len(in) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	m := v.(map[any]any)
	arr := m["a"].([]any)
	if arr[0].(int64) != 1 || arr[1].(int64) != -7 || !bytes.Equal(arr[2].([]byte), []byte{9}) ||
		arr[3].(string) != "s" || arr[4].(bool) != true || arr[5].(bool) != false {
		t.Errorf("arr = %#v", arr)
	}
	if _, ok := m[int64(-2)].(map[any]any); !ok {
		t.Errorf("nested map missing: %#v", m)
	}
}
