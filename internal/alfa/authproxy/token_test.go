package authproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

var (
	testKey  = []byte("0123456789abcdef0123456789abcdef")
	otherKey = []byte("ffffffffffffffffffffffffffffffff")
)

func TestSignVerifyRoundTrip(t *testing.T) {
	tok := Sign(testKey, []byte("hello"))
	got, err := Verify(testKey, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("payload = %q, want hello", got)
	}
}

func TestVerifyRejectsTamperAndWrongKey(t *testing.T) {
	tok := Sign(testKey, []byte("hello"))
	if _, err := Verify(otherKey, tok); err == nil {
		t.Error("Verify with the wrong key should fail")
	}
	bad := []byte(tok)
	if bad[0] == 'a' {
		bad[0] = 'b'
	} else {
		bad[0] = 'a'
	}
	if _, err := Verify(testKey, string(bad)); err == nil {
		t.Error("Verify of a tampered token should fail")
	}
	if _, err := Verify(testKey, "no-dot-separator"); err == nil {
		t.Error("Verify of a malformed token should fail")
	}
}

func TestSessionClaimsRoundTripAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := SessionClaims{Principal: "self", Groups: []string{"authenticated", "owner"}, Exp: now.Add(15 * time.Minute).Unix()}
	tok, err := MintSession(testKey, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSession(testKey, tok, now)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if got.Principal != "self" || len(got.Groups) != 2 || got.Groups[1] != "owner" {
		t.Errorf("claims = %+v", got)
	}
	if _, err := ParseSession(testKey, tok, time.Unix(c.Exp, 0)); !errors.Is(err, ErrExpired) {
		t.Errorf("at exp: err = %v, want ErrExpired", err)
	}
	if _, err := ParseSession(otherKey, tok, now); err == nil || errors.Is(err, ErrExpired) {
		t.Errorf("wrong key: err = %v, want a signature error", err)
	}
}

func TestStateClaimsRoundTripAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := StateClaims{Nonce: "n1", RD: "/admin", Exp: now.Add(5 * time.Minute).Unix()}
	tok, err := MintState(testKey, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseState(testKey, tok, now)
	if err != nil {
		t.Fatalf("ParseState: %v", err)
	}
	if got.Nonce != "n1" || got.RD != "/admin" {
		t.Errorf("state = %+v", got)
	}
	if _, err := ParseState(testKey, tok, now.Add(6*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired state: err = %v, want ErrExpired", err)
	}
}

// TestAttestEd25519: the oracle signs with the private key; the verifier checks with
// the public key. A DIFFERENT public key must fail — this is the property that stops
// the server (which holds only the public key) from forging a login.
func TestAttestEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	c := AttestClaims{
		Principal: "self", Groups: []string{"owner"}, Nonce: "n1", Aud: "https://krone/auth",
		SessionExp: now.Add(15 * time.Minute).Unix(), Exp: now.Add(2 * time.Minute).Unix(),
	}
	tok, err := MintAttest(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAttest(pub, tok, now)
	if err != nil {
		t.Fatalf("ParseAttest: %v", err)
	}
	if got.Nonce != "n1" || got.Aud != "https://krone/auth" || got.SessionExp != c.SessionExp {
		t.Errorf("attest = %+v", got)
	}
	// a different keypair's public key must NOT verify (no-forge property)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseAttest(otherPub, tok, now); err == nil {
		t.Error("ParseAttest with a different public key should fail")
	}
	// expiry
	if _, err := ParseAttest(pub, tok, now.Add(3*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired attest: err = %v, want ErrExpired", err)
	}
}
