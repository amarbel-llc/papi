package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"code.linenisgreat.com/papi/internal/0/webauthn"
	"code.linenisgreat.com/papi/internal/alfa/papi"
	"code.linenisgreat.com/papi/internal/bravo/inspect"
)

const testRPID = "linenisgreat.com"

// testAuthData builds registration authenticator data as a YubiKey would emit
// it for papi's make-credential: rpIdHash, flags, signCount, attested
// credential data (AAGUID, id, ES256 COSE key) and the credProtect extension.
func testAuthData(t *testing.T, rpID string, flags byte, credProtect int, credID []byte) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)

	var b bytes.Buffer
	rp := sha256.Sum256([]byte(rpID))
	b.Write(rp[:])
	b.WriteByte(flags)
	_ = binary.Write(&b, binary.BigEndian, uint32(0))
	b.Write(bytes.Repeat([]byte{0xee}, 16)) // AAGUID
	_ = binary.Write(&b, binary.BigEndian, uint16(len(credID)))
	b.Write(credID)
	// COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y}
	b.Write([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20})
	b.Write(x)
	b.Write([]byte{0x22, 0x58, 0x20})
	b.Write(y)
	if flags&webauthn.FlagED != 0 {
		b.Write([]byte{0xa1, 0x6b})
		b.WriteString("credProtect")
		b.WriteByte(byte(credProtect))
	}
	return b.Bytes()
}

const regFlags = webauthn.FlagUP | webauthn.FlagUV | webauthn.FlagAT | webauthn.FlagED

type v2Fixture struct {
	newCard, trusted testCard
	signer           fakeSigner
	card             Card
}

func newV2Fixture(t *testing.T) v2Fixture {
	t.Helper()
	newCard := newTestCard(t, "AAAA1111")
	trusted := newTestCard(t, "BBBB2222")
	return v2Fixture{
		newCard: newCard,
		trusted: trusted,
		signer:  fakeSigner{cards: map[string]*ecdsa.PrivateKey{newCard.guid: newCard.priv, trusted.guid: trusted.priv}},
		card:    Card{GUID: newCard.guid, RecipientID: testRecipientID, SSHID: newCard.keyID, SSHLine: newCard.sshLine},
	}
}

func (f v2Fixture) made(t *testing.T, flags byte, credProtect int) MadeCredential {
	credID := []byte("credential-id-0123456789")
	return MadeCredential{
		Fmt:            "packed",
		AuthData:       testAuthData(t, testRPID, flags, credProtect, credID),
		CredentialID:   credID,
		AttSig:         []byte("att-sig"),
		X5C:            []byte("x5c"),
		ClientDataHash: papi.WebAuthnClientDataHash(testRPID, f.card.GUID, f.card.SSHID),
	}
}

// receipt builds and attests a v2 receipt, letting mutate change the webauthn
// block before the attestation is made (so only the webauthn check can fail).
func (f v2Fixture) receipt(t *testing.T, made MadeCredential, mutate func(*papi.ReceiptWebAuthn)) []byte {
	t.Helper()
	wa, err := BuildWebAuthnBlock(context.Background(), f.signer, f.card, testRPID, made)
	if err != nil {
		t.Fatalf("BuildWebAuthnBlock: %v", err)
	}
	if mutate != nil {
		mutate(wa)
	}
	raw, err := BuildReceiptWithWebAuthn(context.Background(), f.signer, f.card, testRPID, f.trusted.guid, f.trusted.keyID, 1750000000, wa)
	if err != nil {
		t.Fatalf("BuildReceiptWithWebAuthn: %v", err)
	}
	return raw
}

func (f v2Fixture) verify(t *testing.T, raw []byte) inspect.ReceiptResult {
	t.Helper()
	res, err := inspect.VerifyReceipt(context.Background(), serveTrusted(t, f.trusted.sshLine), raw)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	return res
}

func checkByName(res inspect.ReceiptResult, name string) (inspect.ReceiptCheck, bool) {
	for _, c := range res.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return inspect.ReceiptCheck{}, false
}

func TestV2ReceiptVerifies(t *testing.T) {
	f := newV2Fixture(t)
	raw := f.receipt(t, f.made(t, regFlags, 2), nil)
	var r papi.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.Schema != papi.ReceiptSchemaV2 || r.WebAuthn == nil || r.WebAuthn.CredProtect != 2 {
		t.Fatalf("not a v2 receipt with a credProtect-2 credential: %s", raw)
	}
	res := f.verify(t, raw)
	if !res.OK {
		t.Fatalf("v2 receipt did not verify: %+v", res.Checks)
	}
	if c, ok := checkByName(res, "webauthn"); !ok || !c.OK {
		t.Fatalf("webauthn check missing or failing: %+v", res.Checks)
	}
}

// The producer refuses a credential that fails the enroll policy.
func TestBuildWebAuthnBlockEnforcesPolicy(t *testing.T) {
	f := newV2Fixture(t)
	for name, made := range map[string]MadeCredential{
		"no UV":           f.made(t, webauthn.FlagUP|webauthn.FlagAT|webauthn.FlagED, 2),
		"credProtect 3":   f.made(t, regFlags, 3),
		"no credProtect":  f.made(t, webauthn.FlagUP|webauthn.FlagUV|webauthn.FlagAT, 0),
		"backup-eligible": f.made(t, regFlags|webauthn.FlagBE, 2),
	} {
		if _, err := BuildWebAuthnBlock(context.Background(), f.signer, f.card, testRPID, made); err == nil {
			t.Errorf("%s: want a policy error", name)
		}
	}
	m := f.made(t, regFlags, 2)
	m.CredentialID = []byte("a different id")
	if _, err := BuildWebAuthnBlock(context.Background(), f.signer, f.card, testRPID, m); err == nil {
		t.Error("a credential id that disagrees with authData should be refused")
	}
}

// The verifier rejects a webauthn block that does not match its own evidence
// or is not bound by the new card, even though the trusted card attested it.
func TestV2ReceiptWebAuthnTamper(t *testing.T) {
	f := newV2Fixture(t)
	other := newTestCard(t, "CCCC3333")
	for name, mutate := range map[string]func(*papi.ReceiptWebAuthn){
		"public key swapped": func(w *papi.ReceiptWebAuthn) { w.PublicKey = "AAAA" },
		"credential id":      func(w *papi.ReceiptWebAuthn) { w.CredentialID = "AAAA" },
		"aaguid":             func(w *papi.ReceiptWebAuthn) { w.AAGUID = "00" },
		"client data hash":   func(w *papi.ReceiptWebAuthn) { w.Registration.ClientDataHash = "AAAA" },
		"rp id":              func(w *papi.ReceiptWebAuthn) { w.RPID = "evil.example" },
		"discoverable":       func(w *papi.ReceiptWebAuthn) { w.Discoverable = true },
		"binding by another card": func(w *papi.ReceiptWebAuthn) {
			sig, err := signMarkl(context.Background(), fakeSigner{cards: map[string]*ecdsa.PrivateKey{"X": other.priv}}, "X", []byte(w.Binding.Claim), "papi-proof-sig-v1")
			if err != nil {
				t.Fatal(err)
			}
			w.Binding.Sig = sig
		},
	} {
		res := f.verify(t, f.receipt(t, f.made(t, regFlags, 2), mutate))
		c, ok := checkByName(res, "webauthn")
		if !ok || c.OK || res.OK {
			t.Errorf("%s: want the webauthn check to fail, got %+v", name, res.Checks)
		}
		if att, _ := checkByName(res, "attestation"); !att.OK {
			t.Errorf("%s: the attestation itself should still verify: %+v", name, att)
		}
	}
}

// A v1 receipt must not smuggle a webauthn member, and a v2 one must carry it.
func TestReceiptSchemaAndWebAuthnAgree(t *testing.T) {
	f := newV2Fixture(t)
	raw := f.receipt(t, f.made(t, regFlags, 2), nil)

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["schema"] = json.RawMessage(`"` + papi.ReceiptSchema + `"`)
	v1WithWA, _ := json.Marshal(m)
	if c, ok := checkByName(f.verify(t, v1WithWA), "webauthn"); !ok || c.OK {
		t.Errorf("a v1 receipt carrying webauthn should fail the webauthn check")
	}

	v2NoWA, err := BuildReceiptWithWebAuthn(context.Background(), f.signer, f.card, testRPID, f.trusted.guid, f.trusted.keyID, 1750000000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(v2NoWA, &m); err != nil {
		t.Fatal(err)
	}
	m["schema"] = json.RawMessage(`"` + papi.ReceiptSchemaV2 + `"`)
	delete(m, "webauthn")
	v2Bare, _ := json.Marshal(m)
	if c, ok := checkByName(f.verify(t, v2Bare), "webauthn"); !ok || c.OK {
		t.Errorf("a v2 receipt without webauthn should fail the webauthn check")
	}
}
