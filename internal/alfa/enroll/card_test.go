package enroll

import (
	"context"
	"fmt"
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

func TestPiggySignBytesSigner(t *testing.T) {
	want := make([]byte, 64)
	for i := range want {
		want[i] = byte(i + 1)
	}
	var gotStdin []byte
	var gotArgs []string
	run := func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if name != "piggy" {
			t.Errorf("ran %q, want piggy", name)
		}
		gotStdin = stdin
		gotArgs = args
		return want, nil // piggy sign-bytes --format raw returns the raw 64-byte r‖s
	}

	msg := []byte("the bytes to sign")
	rs, err := PiggySignBytesSigner{Run: run, PIN: "123456"}.SignSlot9A(context.Background(), cardGUID, msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(rs) != string(want) {
		t.Errorf("returned %x, want the runner's raw r‖s %x", rs, want)
	}
	if string(gotStdin) != string(msg) {
		t.Errorf("signer fed %q, want the bare message %q", gotStdin, msg)
	}
	wantArgs := []string{"sign-bytes", "--slot", "9a", "--format", "raw", "--guid", cardGUID, "-P", "123456"}
	if strings.Join(gotArgs, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("args = %v, want %v", gotArgs, wantArgs)
	}

	// A signature of the wrong length (not raw 64-byte r‖s) must error.
	short := func(_ context.Context, _ []byte, _ string, _ ...string) ([]byte, error) {
		return []byte("not 64 bytes"), nil
	}
	if _, err := (PiggySignBytesSigner{Run: short}).SignSlot9A(context.Background(), "G", nil); err == nil {
		t.Error("a non-64-byte signature should error")
	}
}

func TestRegisterGitHubKey(t *testing.T) {
	const pub = "ecdsa-sha2-nistp256 AAAAE2VjZHNhmzw= piggy slot=9A guid=X cn=laptop-alice"
	var calls []string
	run := func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if !strings.HasPrefix(string(stdin), "ecdsa-sha2-nistp256 AAAA") {
			t.Errorf("pubkey not fed on stdin: %q", stdin)
		}
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	}
	if err := RegisterGitHubKey(context.Background(), run, pub, "laptop-alice"); err != nil {
		t.Fatalf("RegisterGitHubKey: %v", err)
	}
	// Both an authentication AND a signing key are added (same material).
	if len(calls) != 2 {
		t.Fatalf("want 2 gh calls (auth + signing), got %d: %v", len(calls), calls)
	}
	if !strings.Contains(calls[0], "gh ssh-key add") ||
		!strings.Contains(calls[0], "--type authentication") ||
		!strings.Contains(calls[0], "--title laptop-alice") {
		t.Errorf("auth call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "--type signing") ||
		!strings.Contains(calls[1], "--title laptop-alice (signing)") {
		t.Errorf("signing call = %q", calls[1])
	}
}

func TestListGitHubKeys(t *testing.T) {
	run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if name != "gh" || len(args) < 2 || args[0] != "api" {
			t.Fatalf("unexpected exec: %s %v", name, args)
		}
		switch args[1] {
		case "user/keys":
			return []byte(`[{"key":"ssh-ed25519 AAAAauth1","title":"laptop"}]`), nil
		case "user/ssh_signing_keys":
			return []byte(`[{"key":"ssh-ed25519 AAAAsign1","title":"laptop-sign"}]`), nil
		}
		return nil, fmt.Errorf("unexpected gh api path %q", args[1])
	}
	keys, err := ListGitHubKeys(context.Background(), run)
	if err != nil {
		t.Fatalf("ListGitHubKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys (1 auth + 1 signing), got %d: %+v", len(keys), keys)
	}
	if keys[0].Kind != "authentication" || keys[0].Key != "ssh-ed25519 AAAAauth1" || keys[0].Title != "laptop" {
		t.Errorf("auth key = %+v", keys[0])
	}
	if keys[1].Kind != "signing" || keys[1].Title != "laptop-sign" {
		t.Errorf("signing key = %+v", keys[1])
	}
}
