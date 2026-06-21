package enroll

import "testing"

// realProvisionedList is the real `piggy list --format=ndjson` FORMAT for a
// provisioned card (one record per slot, serial as a JSON number) — card serials
// are synthetic (real device serials aren't committed).
const realProvisionedList = `{"id":"piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qft20hts","guid":"55C3439DDF5E324B1A4DD9F9B75B6106","serial":19000001,"reader":"Yubico YubiKey OTP+FIDO+CCID 01 00","slot":"9A","cn":"piv-auth@55C3439D"}
{"id":"piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkux","guid":"55C3439DDF5E324B1A4DD9F9B75B6106","serial":19000001,"reader":"Yubico YubiKey OTP+FIDO+CCID 01 00","slot":"9D","cn":"piv-key-mgmt@55C3439D"}
{"id":"piggy-recipient-v1@pivy_ecdh_p256_pub-qdvs3net","guid":"55C3439DDF5E324B1A4DD9F9B75B6106","serial":19000001,"reader":"Yubico YubiKey OTP+FIDO+CCID 01 00","slot":"82","cn":"test"}`

// blankRecord is the assumed piggy#193 record for an uninitialized card (serial
// as a number, all-zeros guid, explicit state).
const blankRecord = `{"serial":19000002,"guid":"00000000000000000000000000000000","reader":"Yubico YubiKey OTP+FIDO+CCID 00 00","state":"uninitialized"}`

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

func TestFindBlankCard(t *testing.T) {
	cards, _ := parseCardList([]byte(realProvisionedList + "\n" + blankRecord))

	// sole blank card, no serial → picks it
	got, err := findBlankCard(cards, "")
	if err != nil || got.Serial != "19000002" {
		t.Fatalf("findBlankCard(sole) = %+v, %v", got, err)
	}
	// by serial → matches
	if got, err := findBlankCard(cards, "19000002"); err != nil || got.Serial != "19000002" {
		t.Errorf("findBlankCard(serial) = %+v, %v", got, err)
	}
	// a provisioned serial is not a blank card
	if _, err := findBlankCard(cards, "19000001"); err == nil {
		t.Error("findBlankCard on a provisioned serial should error")
	}
	// no blank card at all
	only, _ := parseCardList([]byte(realProvisionedList))
	if _, err := findBlankCard(only, ""); err == nil {
		t.Error("findBlankCard with no blank card should error")
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
