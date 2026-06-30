package authproxy

import (
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
	c := SessionClaims{Principal: "tester", Groups: []string{"owner"}, Exp: now.Add(15 * time.Minute).Unix()}
	tok, err := MintSession(testKey, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSession(testKey, tok, now)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if got.Principal != "tester" {
		t.Errorf("principal = %q, want tester", got.Principal)
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
