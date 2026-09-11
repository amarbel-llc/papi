package enroll

import (
	"context"
	"strings"
	"testing"
)

// realProvisionedList is the real `piggy list --format=ndjson` FORMAT for a
// provisioned card (one record per slot, serial as a JSON number) — card serials
// are synthetic (real device serials aren't committed).
const realProvisionedList = `{"id":"piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qft20hts","guid":"55C3439DDF5E324B1A4DD9F9B75B6106","serial":19000001,"reader":"Yubico YubiKey OTP+FIDO+CCID 01 00","slot":"9A","cn":"piv-auth@55C3439D"}
{"id":"piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkux","guid":"55C3439DDF5E324B1A4DD9F9B75B6106","serial":19000001,"reader":"Yubico YubiKey OTP+FIDO+CCID 01 00","slot":"9D","cn":"piv-key-mgmt@55C3439D"}
{"id":"piggy-recipient-v1@pivy_ecdh_p256_pub-qdvs3net","guid":"55C3439DDF5E324B1A4DD9F9B75B6106","serial":19000001,"reader":"Yubico YubiKey OTP+FIDO+CCID 01 00","slot":"82","cn":"test"}`

// blankRecord is piggy#193's record for an uninitialized card (serial as a
// number, all-zeros guid, the explicit uninitialized:true marker, no slot record).
const blankRecord = `{"uninitialized":true,"serial":19000002,"guid":"00000000000000000000000000000000","reader":"Yubico YubiKey OTP+FIDO+CCID 00 00"}`

// serialLessHalfRecord is a pre-5.x YubiKey whose serial piggy can't read over PIV
// (papi#81): one slot-9D record, NO serial field, a real (non-zero) guid, and a
// placeholder CN. It reads as provisioned-but-not-an-attester (9D, no 9A) and can
// only be selected by reader or GUID — no --serial value matches it.
const serialLessHalfRecord = `{"id":"piggy-recipient-v1@pivy_ecdh_p256_pub-qds0a496","guid":"5DA19C98257243EFCD29BE3AE91EA7F8","reader":"Yubico YubiKey OTP+FIDO+CCID 02 00","slot":"9D","cn":"piv-key-mgmt@00000000"}`

func TestParseCardListProvisioned(t *testing.T) {
	cards, err := parseCardList([]byte(realProvisionedList))
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("want 1 card, got %d: %+v", len(cards), cards)
	}
	c := cards[0]
	if c.Serial != "19000001" || !c.Provisioned || !c.HasAuth || c.GUID != "55C3439DDF5E324B1A4DD9F9B75B6106" {
		t.Errorf("provisioned card mis-parsed: %+v", c)
	}
}

func TestParseCardListWithBlank(t *testing.T) {
	cards, err := parseCardList([]byte(realProvisionedList + "\n" + blankRecord))
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 2 {
		t.Fatalf("want 2 cards, got %d: %+v", len(cards), cards)
	}
	var blank *CardState
	for i := range cards {
		if cards[i].Serial == "19000002" {
			blank = &cards[i]
		}
	}
	if blank == nil {
		t.Fatalf("blank card not parsed: %+v", cards)
	}
	if blank.Provisioned || blank.HasAuth {
		t.Errorf("blank card marked provisioned/hasauth: %+v", *blank)
	}
	if blank.GUID != "" {
		t.Errorf("blank card GUID = %q, want empty (all-zeros dropped)", blank.GUID)
	}
	if displayGUID(*blank) != "unprovisioned" {
		t.Errorf("displayGUID(blank) = %q, want unprovisioned", displayGUID(*blank))
	}
}

// A pre-5.x YubiKey with no readable serial and only a 9D slot parses as a
// serial-less, provisioned-but-not-attester card keyed by GUID (papi#81).
func TestParseCardListSerialLessHalfProvisioned(t *testing.T) {
	cards, err := parseCardList([]byte(serialLessHalfRecord))
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("want 1 card, got %d: %+v", len(cards), cards)
	}
	c := cards[0]
	if c.Serial != "" {
		t.Errorf("serial = %q, want empty (unreadable)", c.Serial)
	}
	if c.GUID != "5DA19C98257243EFCD29BE3AE91EA7F8" {
		t.Errorf("guid = %q, want the real guid", c.GUID)
	}
	if c.Reader != "Yubico YubiKey OTP+FIDO+CCID 02 00" {
		t.Errorf("reader = %q", c.Reader)
	}
	if !c.Provisioned {
		t.Errorf("a 9D card should be Provisioned: %+v", c)
	}
	if c.HasAuth {
		t.Errorf("a 9D-only card must not be HasAuth (no 9A): %+v", c)
	}
}

func TestFindCardToEnroll(t *testing.T) {
	cards, _ := parseCardList([]byte(realProvisionedList + "\n" + blankRecord))

	// sole blank card, no target → picks it (either mode)
	if got, err := findCardToEnroll(cards, cardTarget{}, false); err != nil || got.Serial != "19000002" {
		t.Fatalf("findCardToEnroll(sole blank) = %+v, %v", got, err)
	}
	// blank by serial → matches
	if got, err := findCardToEnroll(cards, cardTarget{Serial: "19000002"}, false); err != nil || got.Serial != "19000002" {
		t.Errorf("findCardToEnroll(blank serial) = %+v, %v", got, err)
	}
	// a provisioned serial WITHOUT the flag → error pointing at --allow-reprovision
	if _, err := findCardToEnroll(cards, cardTarget{Serial: "19000001"}, false); err == nil {
		t.Error("a provisioned serial without --allow-reprovision should error")
	}
	// a provisioned serial WITH the flag → returns the provisioned card (to re-init)
	if got, err := findCardToEnroll(cards, cardTarget{Serial: "19000001"}, true); err != nil || got.Serial != "19000001" || !got.Provisioned {
		t.Errorf("findCardToEnroll(provisioned, allow) = %+v, %v; want the provisioned card", got, err)
	}
	// empty target never auto-picks a provisioned card, even under the flag
	only, _ := parseCardList([]byte(realProvisionedList))
	if _, err := findCardToEnroll(only, cardTarget{}, true); err == nil {
		t.Error("empty target with no blank card should error even under --allow-reprovision")
	}
}

// A serial-less card (a pre-5.x YubiKey) is selectable by GUID or reader — the
// papi#81 path, since no --serial value can match it. It reads as provisioned (9D),
// so it needs --allow-reprovision.
func TestFindCardToEnrollSerialLess(t *testing.T) {
	cards, _ := parseCardList([]byte(realProvisionedList + "\n" + serialLessHalfRecord))

	// by guid, without the flag → error (it's provisioned)
	if _, err := findCardToEnroll(cards, cardTarget{GUID: "5DA19C98257243EFCD29BE3AE91EA7F8"}, false); err == nil {
		t.Error("serial-less provisioned card by guid without --allow-reprovision should error")
	}
	// by guid (case-insensitive), with the flag → matches
	if got, err := findCardToEnroll(cards, cardTarget{GUID: "5da19c98257243efcd29be3ae91ea7f8"}, true); err != nil || got.Reader != "Yubico YubiKey OTP+FIDO+CCID 02 00" {
		t.Errorf("findCardToEnroll(serial-less by guid, allow) = %+v, %v", got, err)
	}
	// by reader substring, with the flag → matches unambiguously
	if got, err := findCardToEnroll(cards, cardTarget{Reader: "02 00"}, true); err != nil || got.GUID != "5DA19C98257243EFCD29BE3AE91EA7F8" {
		t.Errorf("findCardToEnroll(serial-less by reader, allow) = %+v, %v", got, err)
	}
	// an unknown reader → no match error
	if _, err := findCardToEnroll(cards, cardTarget{Reader: "99 99"}, true); err == nil {
		t.Error("unknown reader should error")
	}
}

// A blank card with a serial is provisioned via `piggy card init --serial <N>` —
// no --allow-reprovision, no `card reset`, no --cn-prefix.
func TestProvisionBySerial(t *testing.T) {
	var calls [][]string
	irun := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	list := func(_ context.Context, _ []byte, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"serial":19000002,"guid":"ABCD1234ABCD1234ABCD1234ABCD1234","reader":"Yubico YubiKey OTP+FIDO+CCID 00 00","slot":"9A","cn":"piv-auth@ABCD1234"}`), nil
	}
	card := CardState{Serial: "19000002", Reader: "Yubico YubiKey OTP+FIDO+CCID 00 00"}
	guid, err := Provision(context.Background(), irun, list, card)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if guid != "ABCD1234ABCD1234ABCD1234ABCD1234" {
		t.Errorf("guid = %q", guid)
	}
	if len(calls) != 1 {
		t.Fatalf("want 1 call, got %d: %v", len(calls), calls)
	}
	if got, want := strings.Join(calls[0], " "), "piggy card init --serial 19000002"; got != want {
		t.Errorf("call = %q, want %q", got, want)
	}
}

// The papi#81 path: re-provision a serial-less card selected by reader. The single
// call is `piggy card init --allow-reprovision --reader <NAME>` — NOT a `card reset`
// (which does not exist), and NO --cn-prefix (not a real flag). Read-back matches by
// reader (stable across the init; the GUID is reassigned).
func TestReprovisionCardByReader(t *testing.T) {
	var calls [][]string
	irun := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	list := func(_ context.Context, _ []byte, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"guid":"ABCD1234ABCD1234ABCD1234ABCD1234","reader":"Yubico YubiKey OTP+FIDO+CCID 02 00","slot":"9A","cn":"piv-auth@ABCD1234"}
{"guid":"ABCD1234ABCD1234ABCD1234ABCD1234","reader":"Yubico YubiKey OTP+FIDO+CCID 02 00","slot":"9D","cn":"piv-key-mgmt@ABCD1234"}`), nil
	}
	card := CardState{GUID: "5DA19C98257243EFCD29BE3AE91EA7F8", Reader: "Yubico YubiKey OTP+FIDO+CCID 02 00", Provisioned: true}
	guid, err := ReprovisionCard(context.Background(), irun, list, card)
	if err != nil {
		t.Fatalf("ReprovisionCard: %v", err)
	}
	if guid != "ABCD1234ABCD1234ABCD1234ABCD1234" {
		t.Errorf("guid = %q, want the re-init'd guid", guid)
	}
	if len(calls) != 1 {
		t.Fatalf("want 1 call, got %d: %v", len(calls), calls)
	}
	got := strings.Join(calls[0], " ")
	if want := "piggy card init --allow-reprovision --reader Yubico YubiKey OTP+FIDO+CCID 02 00"; got != want {
		t.Errorf("call = %q, want %q", got, want)
	}
	if strings.Contains(got, "reset") {
		t.Errorf("must not call `card reset` (it does not exist): %q", got)
	}
	if strings.Contains(got, "--cn-prefix") {
		t.Errorf("must not pass --cn-prefix (not a real flag): %q", got)
	}
}

func TestResolveTrustedGUID(t *testing.T) {
	cards, _ := parseCardList([]byte(realProvisionedList + "\n" + blankRecord))

	// explicit wins
	if g, err := ResolveTrustedGUID(cards, "EXPLICIT"); err != nil || g != "EXPLICIT" {
		t.Errorf("explicit trusted = %q, %v", g, err)
	}
	// sole card with a 9A auto-selected
	if g, err := ResolveTrustedGUID(cards, ""); err != nil || g != "55C3439DDF5E324B1A4DD9F9B75B6106" {
		t.Errorf("auto trusted = %q, %v", g, err)
	}
	// no card with a 9A → error
	blankOnly, _ := parseCardList([]byte(blankRecord))
	if _, err := ResolveTrustedGUID(blankOnly, ""); err == nil {
		t.Error("ResolveTrustedGUID with no attester should error")
	}
	// a 9D-only (serial-less half-provisioned) card is NOT an eligible attester
	halfOnly, _ := parseCardList([]byte(serialLessHalfRecord))
	if _, err := ResolveTrustedGUID(halfOnly, ""); err == nil {
		t.Error("a 9D-only card must not be an eligible attester")
	}
}

func TestIsZeroGUID(t *testing.T) {
	for _, z := range []string{"", "0000000000000000", "00000000000000000000000000000000", "  0000  "} {
		if !isZeroGUID(z) {
			t.Errorf("isZeroGUID(%q) = false, want true", z)
		}
	}
	for _, nz := range []string{"55C3439D", "0001"} {
		if isZeroGUID(nz) {
			t.Errorf("isZeroGUID(%q) = true, want false", nz)
		}
	}
}
