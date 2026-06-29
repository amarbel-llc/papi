package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// verifyRS checks a raw 64-byte r‖s against priv over SHA-256(msg) — exactly what
// the server's ECDSA verify does against the registered slot-9A pubkey. It is the
// guard that the SSH-blob → raw-r‖s reframe is correct.
func verifyRS(t *testing.T, priv *ecdsa.PrivateKey, msg, rs []byte) {
	t.Helper()
	if len(rs) != 64 {
		t.Fatalf("signature = %d bytes, want 64 raw r‖s", len(rs))
	}
	r := new(big.Int).SetBytes(rs[:32])
	s := new(big.Int).SetBytes(rs[32:])
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("r‖s does not verify over SHA-256(msg) — wrong framing")
	}
}

// TestSignSlot9AWithAgentReframesToRawRS proves the agent path end to end against an
// in-memory keyring (no card): the SSH ecdsa signature is reframed to a raw r‖s that
// verifies over SHA-256(preimage), matching the card / piggy-sign-bytes path.
func TestSignSlot9AWithAgentReframesToRawRS(t *testing.T) {
	priv := mustKey(t)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "PIV_slot_9A A1B2C3D4"}); err != nil {
		t.Fatal(err)
	}
	msg := []byte("papi-auth-v1\nstaging.linenisgreat.com\ndeadbeef")
	rs, err := signSlot9AWithAgent(kr, "", msg)
	if err != nil {
		t.Fatalf("signSlot9AWithAgent: %v", err)
	}
	verifyRS(t, priv, msg, rs)
}

// TestSignSlot9AWithAgentPicksSlot9A confirms the selector signs with the slot-9A
// key, not the slot-9D key sharing the agent.
func TestSignSlot9AWithAgentPicksSlot9A(t *testing.T) {
	priv9a, priv9d := mustKey(t), mustKey(t)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv9d, Comment: "PIV_slot_9D A1B2C3D4"}); err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(agent.AddedKey{PrivateKey: priv9a, Comment: "PIV_slot_9A A1B2C3D4"}); err != nil {
		t.Fatal(err)
	}
	msg := []byte("m")
	rs, err := signSlot9AWithAgent(kr, "", msg)
	if err != nil {
		t.Fatalf("signSlot9AWithAgent: %v", err)
	}
	verifyRS(t, priv9a, msg, rs)
}

// TestSignSlot9AWithAgentErrorsWhenAbsent: no slot-9A key in the agent is an error,
// not a silent wrong-key sign.
func TestSignSlot9AWithAgentErrorsWhenAbsent(t *testing.T) {
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: mustKey(t), Comment: "PIV_slot_9D A1B2C3D4"}); err != nil {
		t.Fatal(err)
	}
	if _, err := signSlot9AWithAgent(kr, "", []byte("m")); err == nil {
		t.Error("want error when no slot-9A key is present")
	}
}

// TestSignSlot9AWithAgentDisambiguatesByGUID: two attached cards (two slot-9A keys)
// are ambiguous without a guid, and the guid selects the right one.
func TestSignSlot9AWithAgentDisambiguatesByGUID(t *testing.T) {
	privA, privB := mustKey(t), mustKey(t)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: privA, Comment: "PIV_slot_9A AAAAAAAA"}); err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(agent.AddedKey{PrivateKey: privB, Comment: "PIV_slot_9A BBBBBBBB"}); err != nil {
		t.Fatal(err)
	}
	if _, err := signSlot9AWithAgent(kr, "", []byte("m")); err == nil {
		t.Error("want error when multiple slot-9A keys and no guid")
	}
	msg := []byte("m")
	rs, err := signSlot9AWithAgent(kr, "bbbbbbbb", msg)
	if err != nil {
		t.Fatalf("signSlot9AWithAgent with guid: %v", err)
	}
	verifyRS(t, privB, msg, rs)
}
