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

func TestParseCardListProvisioned(t *testing.T) {
	cards, err := parseCardList([]byte(realProvisionedList))
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("want 1 card, got %d: %+v", len(cards), cards)
	}
	c := cards[0]
	if c.Serial != "19000001" || !c.Provisioned || c.GUID != "55C3439DDF5E324B1A4DD9F9B75B6106" {
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
	if blank.Provisioned {
		t.Errorf("blank card marked provisioned: %+v", *blank)
	}
	if blank.GUID != "" {
		t.Errorf("blank card GUID = %q, want empty (all-zeros dropped)", blank.GUID)
	}
	if displayGUID(*blank) != "unprovisioned" {
		t.Errorf("displayGUID(blank) = %q, want unprovisioned", displayGUID(*blank))
	}
}

func TestFindCardToEnroll(t *testing.T) {
	cards, _ := parseCardList([]byte(realProvisionedList + "\n" + blankRecord))

	// sole blank card, no serial → picks it (either mode)
	if got, err := findCardToEnroll(cards, "", false); err != nil || got.Serial != "19000002" {
		t.Fatalf("findCardToEnroll(sole blank) = %+v, %v", got, err)
	}
	// blank by serial → matches
	if got, err := findCardToEnroll(cards, "19000002", false); err != nil || got.Serial != "19000002" {
		t.Errorf("findCardToEnroll(blank serial) = %+v, %v", got, err)
	}
	// a provisioned serial WITHOUT the flag → error pointing at --allow-reprovision
	if _, err := findCardToEnroll(cards, "19000001", false); err == nil {
		t.Error("a provisioned serial without --allow-reprovision should error")
	}
	// a provisioned serial WITH the flag → returns the provisioned card (to reset)
	if got, err := findCardToEnroll(cards, "19000001", true); err != nil || got.Serial != "19000001" || !got.Provisioned {
		t.Errorf("findCardToEnroll(provisioned, allow) = %+v, %v; want the provisioned card", got, err)
	}
	// empty serial never auto-picks a provisioned card, even under the flag
	only, _ := parseCardList([]byte(realProvisionedList))
	if _, err := findCardToEnroll(only, "", true); err == nil {
		t.Error("empty serial with no blank card should error even under --allow-reprovision")
	}
}

func TestReprovisionCard(t *testing.T) {
	var calls [][]string
	irun := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	// After reset + init the card reports provisioned with a fresh GUID.
	list := func(_ context.Context, _ []byte, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"serial":"19000002","guid":"ABCD1234ABCD1234","slot":"9D","cn":"piv-key-mgmt"}`), nil
	}
	guid, err := ReprovisionCard(context.Background(), irun, list, "19000002", "laptop-alice")
	if err != nil {
		t.Fatalf("ReprovisionCard: %v", err)
	}
	if guid != "ABCD1234ABCD1234" {
		t.Errorf("guid = %q, want ABCD1234ABCD1234", guid)
	}
	// reset MUST run before init — new keys land on a freshly-reset applet.
	if len(calls) != 2 || calls[0][2] != "reset" || calls[1][2] != "init" {
		t.Fatalf("calls = %v, want [piggy card reset …] then [piggy card init …]", calls)
	}
	// the CN prefix is threaded to init.
	if init := strings.Join(calls[1], " "); !strings.Contains(init, "--cn-prefix laptop-alice") {
		t.Errorf("init call should thread --cn-prefix laptop-alice, got %q", init)
	}
}

func TestResolveTrustedGUID(t *testing.T) {
	cards, _ := parseCardList([]byte(realProvisionedList + "\n" + blankRecord))

	// explicit wins
	if g, err := ResolveTrustedGUID(cards, "EXPLICIT"); err != nil || g != "EXPLICIT" {
		t.Errorf("explicit trusted = %q, %v", g, err)
	}
	// sole provisioned card auto-selected
	if g, err := ResolveTrustedGUID(cards, ""); err != nil || g != "55C3439DDF5E324B1A4DD9F9B75B6106" {
		t.Errorf("auto trusted = %q, %v", g, err)
	}
	// no provisioned card → error
	blankOnly, _ := parseCardList([]byte(blankRecord))
	if _, err := ResolveTrustedGUID(blankOnly, ""); err == nil {
		t.Error("ResolveTrustedGUID with no provisioned card should error")
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
