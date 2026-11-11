package logingrant

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/0/markl"
)

const testDomain = "forge.example"

var (
	testNotBefore = time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	testExpires   = time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
)

// seedKey derives a deterministic ed25519 key so grant text and ids are byte-stable.
func seedKey(b byte) (ed25519.PrivateKey, ssh.PublicKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func goodGrant(t *testing.T) (Grant, ed25519.PrivateKey) {
	t.Helper()
	priv, pub := seedKey(7)
	return Grant{
		Principal:  "nikulin-session",
		Key:        pub,
		Domain:     testDomain,
		NotBefore:  testNotBefore,
		Expires:    testExpires,
		MaxSession: 2 * time.Hour,
		Nonce:      "AAECAwQFBgcICQoLDA0ODw",
	}, priv
}

func goodText(t *testing.T) []byte {
	t.Helper()
	g, _ := goodGrant(t)
	text, err := Build(g)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return text
}

func TestBuildParseRoundTrip(t *testing.T) {
	g, _ := goodGrant(t)
	text, err := Build(g)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(Build(g)): %v\n%s", err, text)
	}
	if !bytes.Equal(got.Text(), text) {
		t.Errorf("re-serialization differs:\n%s\nvs\n%s", got.Text(), text)
	}
	if got.Principal != g.Principal || got.Domain != g.Domain || !got.Expires.Equal(g.Expires) ||
		!got.NotBefore.Equal(g.NotBefore) || got.MaxSession != g.MaxSession || got.Nonce != g.Nonce {
		t.Errorf("fields did not round-trip: %+v", got)
	}
	if !bytes.Equal(got.Key.Marshal(), g.Key.Marshal()) {
		t.Error("key did not round-trip")
	}
}

// The exact bytes are part of the contract (RFC-0001 §5.2.1): fixed line order, LF,
// Z-suffixed whole-second UTC, trailing newline.
func TestCanonicalTextShape(t *testing.T) {
	lines := strings.Split(string(goodText(t)), "\n")
	want := []string{
		"papi login-grant v1",
		"principal: nikulin-session",
		"key: ssh-ed25519 ",
		"domain: forge.example",
		"not-before: 2026-11-11T00:00:00Z",
		"expires: 2026-11-18T00:00:00Z",
		"max-session: 7200",
		"nonce: AAECAwQFBgcICQoLDA0ODw",
		"",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), goodText(t))
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Errorf("line %d = %q, want prefix %q", i, lines[i], w)
		}
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	good := string(goodText(t))
	cases := map[string]string{
		"empty":                 "",
		"no trailing newline":   strings.TrimSuffix(good, "\n"),
		"extra trailing line":   good + "\n",
		"trailing junk":         good + "x: y\n",
		"CRLF":                  strings.ReplaceAll(good, "\n", "\r\n"),
		"wrong header":          strings.Replace(good, "login-grant v1", "login-grant v2", 1),
		"unknown field":         strings.Replace(good, "max-session: 7200\n", "max-session: 7200\nrepos: a/b\n", 1),
		"missing field":         strings.Replace(good, "max-session: 7200\n", "", 1),
		"reordered fields":      strings.Replace(strings.Replace(good, "domain: forge.example\n", "@@", 1), "principal: nikulin-session\n", "principal: nikulin-session\n@@", 1),
		"double space":          strings.Replace(good, "domain: forge", "domain:  forge", 1),
		"uppercase principal":   strings.Replace(good, "nikulin-session", "Nikulin", 1),
		"empty principal":       strings.Replace(good, "principal: nikulin-session", "principal: ", 1),
		"principal with slash":  strings.Replace(good, "nikulin-session", "a/b", 1),
		"principal too long":    strings.Replace(good, "nikulin-session", strings.Repeat("a", 65), 1),
		"uppercase domain":      strings.Replace(good, "forge.example", "Forge.Example", 1),
		"domain with scheme":    strings.Replace(good, "forge.example", "https://forge.example", 1),
		"non-ed25519 key":       strings.Replace(good, "ssh-ed25519", "ssh-rsa", 1),
		"key with comment":      strings.Replace(good, "\ndomain:", " comment\ndomain:", 1),
		"offset timestamp":      strings.Replace(good, "2026-11-11T00:00:00Z", "2026-11-11T01:00:00+01:00", 1),
		"fractional seconds":    strings.Replace(good, "2026-11-18T00:00:00Z", "2026-11-18T00:00:00.5Z", 1),
		"lowercase z":           strings.Replace(good, "2026-11-18T00:00:00Z", "2026-11-18T00:00:00z", 1),
		"date only":             strings.Replace(good, "2026-11-18T00:00:00Z", "2026-11-18", 1),
		"expires before start":  strings.Replace(good, "2026-11-18T00:00:00Z", "2026-11-10T00:00:00Z", 1),
		"expires equals start":  strings.Replace(good, "2026-11-18T00:00:00Z", "2026-11-11T00:00:00Z", 1),
		"window over 168h":      strings.Replace(good, "2026-11-18T00:00:00Z", "2026-11-18T00:00:01Z", 1),
		"max-session zero":      strings.Replace(good, "max-session: 7200", "max-session: 0", 1),
		"max-session negative":  strings.Replace(good, "max-session: 7200", "max-session: -1", 1),
		"max-session leading 0": strings.Replace(good, "max-session: 7200", "max-session: 07200", 1),
		"max-session over day":  strings.Replace(good, "max-session: 7200", "max-session: 86401", 1),
		"max-session unit":      strings.Replace(good, "max-session: 7200", "max-session: 2h", 1),
		"nonce padded":          strings.Replace(good, "AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0ODw==", 1),
		"nonce short":           strings.Replace(good, "AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0O", 1),
		"oversize":              good + strings.Repeat("a", maxTextBytes),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(text)); err == nil {
				t.Errorf("Parse accepted a non-canonical grant:\n%q", text)
			}
		})
	}
}

// The 168h bound is inclusive: exactly 168h is allowed, one second more is not.
func TestWindowBoundIsInclusive(t *testing.T) {
	g, _ := goodGrant(t)
	if testExpires.Sub(testNotBefore) != 168*time.Hour {
		t.Fatal("test window is not exactly 168h")
	}
	if _, err := Build(g); err != nil {
		t.Errorf("168h window refused: %v", err)
	}
	g.Expires = g.Expires.Add(time.Second)
	if _, err := Build(g); err == nil {
		t.Error("168h+1s window accepted")
	}
}

func TestBuildRefusesSubSecondAndNonUTC(t *testing.T) {
	g, _ := goodGrant(t)
	g.Expires = g.Expires.Add(-time.Millisecond)
	if _, err := Build(g); err == nil {
		t.Error("sub-second expiry accepted")
	}
	g, _ = goodGrant(t)
	g.NotBefore = g.NotBefore.In(time.FixedZone("x", 3600))
	// Same instant in another zone is fine: the text is always rendered in UTC.
	text, err := Build(g)
	if err != nil {
		t.Fatalf("same instant in another zone refused: %v", err)
	}
	if !strings.Contains(string(text), "not-before: 2026-11-11T00:00:00Z") {
		t.Errorf("not rendered in UTC:\n%s", text)
	}
}

func TestBuildRefusesRSAKey(t *testing.T) {
	g, _ := goodGrant(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g.Key, err = ssh.NewPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(g); err == nil {
		t.Error("an ECDSA login key was accepted; only ed25519 may be granted")
	}
}

func TestValidAt(t *testing.T) {
	g, _ := goodGrant(t)
	cases := []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"one second before not-before", testNotBefore.Add(-time.Second), false},
		{"at not-before", testNotBefore, true},
		{"mid window", testNotBefore.Add(24 * time.Hour), true},
		{"last second", testExpires.Add(-time.Second), true},
		{"at expires (exclusive)", testExpires, false},
		{"after expires", testExpires.Add(time.Second), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.ValidAt(c.now)
			if c.ok && err != nil {
				t.Errorf("want valid, got %v", err)
			}
			if !c.ok && err == nil {
				t.Error("want invalid, got nil")
			}
		})
	}
}

func TestIDIsContentAddressed(t *testing.T) {
	g, _ := goodGrant(t)
	id := g.ID()
	if len(id) != 32 || strings.ToLower(id) != id {
		t.Fatalf("id %q is not 32 lowercase hex chars", id)
	}
	sum := sha256.Sum256(g.Text())
	if want := bytesToHex(sum[:16]); id != want {
		t.Errorf("id = %s, want first 16 bytes of SHA-256 = %s", id, want)
	}
	g.Principal = "other"
	if g.ID() == id {
		t.Error("changing a field did not change the id")
	}
}

func bytesToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}

func TestPreimagesAreDomainSeparated(t *testing.T) {
	login := LoginPreimage(testDomain, "N1", "abcd")
	if want := "papi-auth-soft-v1\nforge.example\nN1\nabcd"; string(login) != want {
		t.Errorf("login preimage = %q, want %q", login, want)
	}
	if strings.HasPrefix(string(login), "papi-auth-v1\n") {
		t.Error("login preimage shares the card-login prefix")
	}
	gp := GrantPreimage([]byte("x"))
	if want := "papi-login-grant-v1\nx"; string(gp) != want {
		t.Errorf("grant preimage = %q, want %q", gp, want)
	}
}

type fakeCard struct{ priv *ecdsa.PrivateKey }

func (f fakeCard) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, f.priv, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	return rs, nil
}

func newCard(t *testing.T) fakeCard {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fakeCard{priv}
}

func TestGrantSignatureRoundTripAndTamper(t *testing.T) {
	card := newCard(t)
	other := newCard(t)
	text := goodText(t)
	sig, err := SignGrant(context.Background(), card, "", text)
	if err != nil {
		t.Fatalf("SignGrant: %v", err)
	}
	if id, err := markl.Parse(sig); err != nil || id.Purpose != markl.PurposeLoginGrantSig {
		t.Fatalf("signature purpose = %v (%v), want %s", id.Purpose, err, markl.PurposeLoginGrantSig)
	}
	if err := VerifyGrantSig(&card.priv.PublicKey, text, sig); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	if err := VerifyGrantSig(&other.priv.PublicKey, text, sig); err == nil {
		t.Error("signature verified under a different key")
	}
	tampered := append([]byte(nil), text...)
	tampered[len(tampered)-3] ^= 1
	if err := VerifyGrantSig(&card.priv.PublicKey, tampered, sig); err == nil {
		t.Error("signature verified over altered text")
	}
}

// A card login signature (papi-auth-sig-v1) over some bytes must never be accepted as a
// grant signature, even if the bytes were chosen to equal the grant preimage.
func TestGrantSignatureRejectsAuthSigPurpose(t *testing.T) {
	card := newCard(t)
	text := goodText(t)
	rs, err := card.SignSlot9A(context.Background(), "", GrantPreimage(text))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := markl.Build(markl.PurposeAuthSig, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGrantSig(&card.priv.PublicKey, text, wrong); err == nil {
		t.Error("papi-auth-sig-v1 accepted as a grant signature")
	}
}

func TestLoginSignature(t *testing.T) {
	g, priv := goodGrant(t)
	id := g.ID()
	sig := SignLogin(priv, testDomain, "N1", id)
	if err := g.VerifyLogin(testDomain, "N1", sig); err != nil {
		t.Fatalf("valid login signature rejected: %v", err)
	}
	for name, mutate := range map[string]func() error{
		"wrong nonce":  func() error { return g.VerifyLogin(testDomain, "N2", sig) },
		"wrong domain": func() error { return g.VerifyLogin("other.example", "N1", sig) },
		"wrong key": func() error {
			other, _ := seedKey(9)
			return g.VerifyLogin(testDomain, "N1", SignLogin(other, testDomain, "N1", id))
		},
		"wrong grant id": func() error {
			return g.VerifyLogin(testDomain, "N1", SignLogin(priv, testDomain, "N1", strings.Repeat("0", 32)))
		},
		"card-login preimage": func() error {
			raw := ed25519.Sign(priv, []byte("papi-auth-v1\n"+testDomain+"\nN1"))
			return g.VerifyLogin(testDomain, "N1", EncodeSig(raw))
		},
		"not base64url": func() error { return g.VerifyLogin(testDomain, "N1", "!!!") },
		"short":         func() error { return g.VerifyLogin(testDomain, "N1", EncodeSig([]byte{1, 2, 3})) },
		"empty":         func() error { return g.VerifyLogin(testDomain, "N1", "") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestTransportEncodingRoundTrip(t *testing.T) {
	text := goodText(t)
	got, err := DecodeText(EncodeText(text))
	if err != nil || !bytes.Equal(got, text) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := DecodeText("not base64 !"); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := DecodeText(EncodeText(bytes.Repeat([]byte("a"), maxTextBytes+1))); err == nil {
		t.Error("oversize accepted")
	}
}
