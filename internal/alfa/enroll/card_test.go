package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

const (
	cardGUID       = "A1B2C3D4E5F60718293A4B5C6D7E8F90"
	cardRecipient  = "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
	cardSSHID      = "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qtc4lu9kwag5t7nzcqlm6vgyg92hs8rgln87uwccu80ean27u80d2yspu3k"
	cardSSHLine    = "ecdsa-sha2-nistp256 AAAAdummy piggy slot=9A guid=A1B2C3D4E5F60718293A4B5C6D7E8F90 cn=piv-auth@a1b2c3d4"
	cardAgeRecip   = "age1piggy1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0"
	otherCardGUID  = "0F1E2D3C4B5A69788796A5B4C3D2E1F0"
	otherRecipient = "piggy-recipient-v1@pivy_ecdh_p256_pub-qpother"
)

// ndjson mixing two cards' slots — parsePiggyIdentity must pick out the right one.
var sampleNDJSON = strings.Join([]string{
	`{"id":"` + otherRecipient + `","guid":"` + otherCardGUID + `","reader":"Yubico 1","slot":"9D"}`,
	`{"id":"` + cardRecipient + `","guid":"` + cardGUID + `","reader":"Yubico 2","slot":"9D"}`,
	`{"id":"` + cardSSHID + `","guid":"` + cardGUID + `","reader":"Yubico 2","slot":"9A","cn":"piv-auth@a1b2c3d4"}`,
	``,
}, "\n")

var sampleSSHOut = strings.Join([]string{
	"ecdsa-sha2-nistp256 AAAAother piggy slot=9A guid=" + otherCardGUID + " cn=piv-auth@0f1e2d3c",
	cardSSHLine,
}, "\n") + "\n"

var sampleAgeOut = "# recipient: " + cardAgeRecip + "\nAGE-PLUGIN-PIGGY-1QQQSECRETIDENTITYXXXXXXXXXXXXXXXXXXXX\n"

func TestParsePiggyIdentity(t *testing.T) {
	recipientID, sshID, cn, err := parsePiggyIdentity([]byte(sampleNDJSON), cardGUID)
	if err != nil {
		t.Fatal(err)
	}
	if recipientID != cardRecipient {
		t.Errorf("recipient = %q, want %q", recipientID, cardRecipient)
	}
	if sshID != cardSSHID {
		t.Errorf("sshID = %q, want %q", sshID, cardSSHID)
	}
	if cn != "piv-auth@a1b2c3d4" {
		t.Errorf("cn = %q", cn)
	}
}

func TestParsePiggyIdentityMissingSlot(t *testing.T) {
	// Only a 9D record for the card → no 9A id → error.
	nd := `{"id":"` + cardRecipient + `","guid":"` + cardGUID + `","slot":"9D"}`
	if _, _, _, err := parsePiggyIdentity([]byte(nd), cardGUID); err == nil {
		t.Fatal("missing slot-9A id should error")
	}
}

func TestParsePiggySSHLine(t *testing.T) {
	line, err := parsePiggySSHLine([]byte(sampleSSHOut), cardGUID)
	if err != nil {
		t.Fatal(err)
	}
	if line != cardSSHLine {
		t.Errorf("line = %q, want %q", line, cardSSHLine)
	}
	if _, err := parsePiggySSHLine([]byte(sampleSSHOut), "DEADBEEF"); err == nil {
		t.Error("a guid with no line should error")
	}
}

func TestParseAgeRecipient(t *testing.T) {
	r, err := parseAgeRecipient([]byte(sampleAgeOut))
	if err != nil {
		t.Fatal(err)
	}
	if r != cardAgeRecip {
		t.Errorf("age recipient = %q, want %q", r, cardAgeRecip)
	}
	if _, err := parseAgeRecipient([]byte("no recipient here")); err == nil {
		t.Error("output without a recipient should error")
	}
}

func TestReadCard(t *testing.T) {
	run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		switch {
		case key == "piggy list --format=ndjson":
			return []byte(sampleNDJSON), nil
		case key == "piggy list --format=ssh":
			return []byte(sampleSSHOut), nil
		case strings.HasPrefix(key, "age-plugin-piggy generate --guid "):
			return []byte(sampleAgeOut), nil
		}
		return nil, fmt.Errorf("unexpected command: %s", key)
	}
	card, err := ReadCard(context.Background(), run, cardGUID)
	if err != nil {
		t.Fatal(err)
	}
	if card.RecipientID != cardRecipient || card.SSHID != cardSSHID ||
		card.SSHLine != cardSSHLine || card.AgeRecipient != cardAgeRecip {
		t.Fatalf("ReadCard assembled the wrong card: %+v", card)
	}
}

func TestPivySignerReframesDER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var gotStdin []byte
	var gotArgs []string
	run := func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if name != "pivy-tool" {
			t.Errorf("ran %q, want pivy-tool", name)
		}
		gotStdin = stdin
		gotArgs = args
		// pivy-tool hashes SHA-256 internally and emits DER.
		digest := sha256.Sum256(stdin)
		return ecdsa.SignASN1(rand.Reader, priv, digest[:])
	}

	msg := []byte("the bytes to attest")
	rs, err := PivySigner{Run: run, PIN: "123456"}.SignSlot9A(context.Background(), cardGUID, msg)
	if err != nil {
		t.Fatal(err)
	}

	if string(gotStdin) != string(msg) {
		t.Errorf("signer fed %q, want the bare message %q", gotStdin, msg)
	}
	wantArgs := []string{"-P", "123456", "-g", cardGUID, "sign", "9a"}
	if strings.Join(gotArgs, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("args = %v, want %v", gotArgs, wantArgs)
	}

	if len(rs) != 64 {
		t.Fatalf("raw r‖s is %d bytes, want 64", len(rs))
	}
	digest := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(rs[:32])
	s := new(big.Int).SetBytes(rs[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("raw r‖s from the signer does not verify against the card key")
	}
}
