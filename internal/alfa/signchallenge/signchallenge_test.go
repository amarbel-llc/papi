package signchallenge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/markl"
)

// TestPreimageBytes pins the §5.2 framing byte-for-byte: prefix, two single-LF
// separators, no trailing newline. The site-linenisgreat verifier reconstructs the
// identical bytes (PapiAuthService::preimage), so any drift here silently breaks the
// live round-trip — this is the guard against that.
func TestPreimageBytes(t *testing.T) {
	got := Preimage("staging.linenisgreat.com", "deadbeef")
	want := "papi-auth-v1\nstaging.linenisgreat.com\ndeadbeef"
	if string(got) != want {
		t.Fatalf("Preimage = %q, want %q", got, want)
	}
	if got[len(got)-1] == '\n' {
		t.Errorf("Preimage has a trailing newline; the server builds none (§5.2)")
	}
	if n := bytes.Count(got, []byte("\n")); n != 2 {
		t.Errorf("Preimage has %d LF separators, want exactly 2", n)
	}
	if bytes.Contains(got, []byte("\r")) {
		t.Errorf("Preimage contains CR; separators must be bare LF (§5.2)")
	}
}

func TestParseChallenge(t *testing.T) {
	ch, err := ParseChallenge([]byte(`{"challenge_id":"abc","nonce":"00ff","expires_at":1750000000}`))
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if ch.ChallengeID != "abc" || ch.Nonce != "00ff" || ch.ExpiresAt != 1750000000 {
		t.Errorf("ParseChallenge = %+v", ch)
	}
	for name, bad := range map[string]string{
		"no challenge_id": `{"nonce":"00ff"}`,
		"no nonce":        `{"challenge_id":"abc"}`,
		"not json":        `not json`,
	} {
		if _, err := ParseChallenge([]byte(bad)); err == nil {
			t.Errorf("ParseChallenge(%s) = nil err, want error", name)
		}
	}
}

// fakeSigner signs as a slot-9A card would: SHA-256 over the bare preimage, ECDSA
// P-256, returned as raw r‖s — exactly what `piggy sign-bytes --slot 9a --format
// raw` produces.
type fakeSigner struct{ priv *ecdsa.PrivateKey }

func (f fakeSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
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

// TestSignProducesVerifiableResponse is the end-to-end conformance check: the
// emitted signature MUST verify over SHA-256(preimage) with the signing key —
// exactly what the server's openssl_verify does against the registered slot-9A
// pubkey. It pins the preimage framing, the markl purpose/format, and the r‖s
// encoding in one shot.
func TestSignProducesVerifiableResponse(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ch := Challenge{ChallengeID: "chal-1", Nonce: "0011223344556677"}
	domain := "staging.linenisgreat.com"

	resp, err := Sign(context.Background(), fakeSigner{priv}, "GUID", domain, ch)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if resp.ChallengeID != ch.ChallengeID {
		t.Errorf("challenge_id = %q, want %q (echoed verbatim)", resp.ChallengeID, ch.ChallengeID)
	}

	id, err := markl.Parse(resp.Signature)
	if err != nil {
		t.Fatalf("Parse signature markl %q: %v", resp.Signature, err)
	}
	if id.Purpose != markl.PurposeAuthSig || id.Format != markl.FormatEcdsaP256Sig {
		t.Errorf("signature purpose/format = %q/%q, want %q/%q",
			id.Purpose, id.Format, markl.PurposeAuthSig, markl.FormatEcdsaP256Sig)
	}
	if len(id.Payload) != 64 {
		t.Fatalf("signature payload = %d bytes, want 64 raw r‖s", len(id.Payload))
	}

	r := new(big.Int).SetBytes(id.Payload[:32])
	s := new(big.Int).SetBytes(id.Payload[32:])
	digest := sha256.Sum256(Preimage(domain, ch.Nonce))
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("signature does not verify over SHA-256(preimage) with the signing key")
	}

	// The response must marshal to the exact {challenge_id, signature} wire body.
	wire, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(got) != 2 || got["challenge_id"] != ch.ChallengeID || got["signature"] != resp.Signature {
		t.Errorf("wire body = %s, want exactly {challenge_id, signature}", wire)
	}
}

func TestSignRequiresDomain(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(context.Background(), fakeSigner{priv}, "GUID", "", Challenge{Nonce: "x"}); err == nil {
		t.Error("Sign with empty domain = nil err, want error (§5.2 binding)")
	}
}

func TestSignPropagatesSignerError(t *testing.T) {
	if _, err := Sign(context.Background(), errSigner{}, "GUID", "d", Challenge{Nonce: "n"}); err == nil {
		t.Error("Sign = nil err when the signer fails, want propagation")
	}
}

type errSigner struct{}

func (errSigner) SignSlot9A(context.Context, string, []byte) ([]byte, error) {
	return nil, errCard
}

var errCard = &signErr{}

type signErr struct{}

func (*signErr) Error() string { return "errSigner: no card" }
