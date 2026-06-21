package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
	"golang.org/x/crypto/ssh"
)

// testRecipientID is a well-formed §5.1 slot-9D recipient markl-id; the receipt
// only needs it as a string the self_proof claim names.
const testRecipientID = "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"

// testCard is an ephemeral P-256 slot-9A key standing in for a provisioned card,
// expressed as the markl-id + OpenSSH line a real readback would surface.
type testCard struct {
	guid    string
	priv    *ecdsa.PrivateKey
	keyID   string
	sshLine string
}

func newTestCard(t *testing.T, guid string) testCard {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	keyID, err := markl.Build(markl.PurposePIVAuth, markl.FormatSSHEcdsaNistp256Pub, compressed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCard{guid, priv, keyID, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))}
}

// fakeSigner signs as the card's slot-9A would: SHA-256 over the bare message,
// then ECDSA, returned as raw r‖s — exactly the contract the pivy-tool adapter
// must reproduce after stripping DER.
type fakeSigner struct{ cards map[string]*ecdsa.PrivateKey }

func (f fakeSigner) SignSlot9A(_ context.Context, guid string, msg []byte) ([]byte, error) {
	priv := f.cards[guid]
	if priv == nil {
		return nil, errNoCard
	}
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	return rs, nil
}

var errNoCard = &cardErr{}

type cardErr struct{}

func (*cardErr) Error() string { return "fakeSigner: unknown card guid" }

// serveTrusted serves a /papi document publishing sshLine in
// piggy.ssh_authorized_keys — making that key an already-trusted attester for
// inspect.VerifyReceipt.
func serveTrusted(t *testing.T, sshLine string) *papi.Client {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{sshLine}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte(`,"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuildReceiptVerifies(t *testing.T) {
	newCard := newTestCard(t, "AAAA1111")
	trusted := newTestCard(t, "BBBB2222")
	signer := fakeSigner{cards: map[string]*ecdsa.PrivateKey{
		newCard.guid: newCard.priv,
		trusted.guid: trusted.priv,
	}}
	card := Card{
		GUID:         newCard.guid,
		RecipientID:  testRecipientID,
		SSHID:        newCard.keyID,
		SSHLine:      newCard.sshLine,
		AgeRecipient: "age1piggytestrecipient",
		CN:           "piv-auth@AAAA1111",
	}

	raw, err := BuildReceipt(context.Background(), signer, card,
		"linenisgreat.com", trusted.guid, trusted.keyID, 1750000000)
	if err != nil {
		t.Fatalf("BuildReceipt: %v", err)
	}

	// The receipt round-trips and carries the spliceable field names.
	var r papi.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("receipt is not valid JSON: %v", err)
	}
	if r.Recipient.ID != testRecipientID || r.SSH.ID != newCard.keyID {
		t.Errorf("receipt did not carry the card ids: %+v", r)
	}

	// And it verifies end-to-end against a domain publishing the trusted key.
	res, err := inspect.VerifyReceipt(context.Background(), serveTrusted(t, trusted.sshLine), raw)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if !res.OK {
		t.Fatalf("assembled receipt did not verify: %+v", res.Checks)
	}
}

func TestBuildReceiptRejectsEmptyCard(t *testing.T) {
	signer := fakeSigner{cards: map[string]*ecdsa.PrivateKey{}}
	_, err := BuildReceipt(context.Background(), signer, Card{GUID: "X"},
		"linenisgreat.com", "Y", "k", 1)
	if err == nil {
		t.Fatal("a card without a 9D recipient / 9A id should be rejected")
	}
}

func TestBuildReceiptPropagatesSignerError(t *testing.T) {
	// No cards registered → the new-card self_proof sign fails.
	signer := fakeSigner{cards: map[string]*ecdsa.PrivateKey{}}
	_, err := BuildReceipt(context.Background(), signer,
		Card{GUID: "AAAA", RecipientID: testRecipientID, SSHID: "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-q"},
		"linenisgreat.com", "BBBB", "k", 1)
	if err == nil {
		t.Fatal("a signer that cannot find the card should surface an error")
	}
}

func TestDERToRawRS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("attest these bytes"))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	rs, err := DERToRawRS(der)
	if err != nil {
		t.Fatalf("DERToRawRS: %v", err)
	}
	if len(rs) != 64 {
		t.Fatalf("raw r‖s is %d bytes, want 64", len(rs))
	}
	r := new(big.Int).SetBytes(rs[:32])
	s := new(big.Int).SetBytes(rs[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("raw r‖s recovered from DER does not verify")
	}
}

func TestDERToRawRSMalformed(t *testing.T) {
	if _, err := DERToRawRS([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("malformed DER should error")
	}
}
