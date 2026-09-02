package papi

import (
	"encoding/json"
	"testing"
	"time"
)

func makeCard(authKey string) IdentityCard {
	return IdentityCard{AuthKey: authKey, Recipient: "recipient-" + authKey}
}

// ---------------------------------------------------------------------------
// CanonicalIdentityDocInput
// ---------------------------------------------------------------------------

func TestCanonicalIdentityDocInput_RemovesSignatures(t *testing.T) {
	raw := []byte(`{"domain":"example.com","schema":"papi-identity-doc-v1","signatures":[{"key":"k","sig":"s"}],"version":1}`)
	got, err := CanonicalIdentityDocInput(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if _, present := obj["signatures"]; present {
		t.Error("signatures key still present in canonical form")
	}
}

func TestCanonicalIdentityDocInput_Deterministic(t *testing.T) {
	raw := []byte(`{"b":2,"a":1,"signatures":[]}`)
	a, err := CanonicalIdentityDocInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalIdentityDocInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("not deterministic: %q vs %q", a, b)
	}
}

// ---------------------------------------------------------------------------
// VerifyIdentityDocStructure
// ---------------------------------------------------------------------------

func TestVerifyIdentityDocStructure_OK(t *testing.T) {
	now := time.Now()
	doc := IdentityDoc{
		Schema:     IdentityDocSchema,
		Domain:     "example.com",
		Version:    3,
		IssuedAt:   now.Add(-5 * time.Minute).Unix(),
		Cards:      []IdentityCard{makeCard("k1")},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	if err := VerifyIdentityDocStructure(&doc, 1, now, time.Hour); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyIdentityDocStructure_WrongSchema(t *testing.T) {
	now := time.Now()
	doc := IdentityDoc{
		Schema:     "wrong-schema",
		Version:    1,
		IssuedAt:   now.Unix(),
		Cards:      []IdentityCard{makeCard("k1")},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	if err := VerifyIdentityDocStructure(&doc, 1, now, time.Hour); err == nil {
		t.Error("expected error for wrong schema")
	}
}

func TestVerifyIdentityDocStructure_VersionTooLow(t *testing.T) {
	now := time.Now()
	doc := IdentityDoc{
		Schema:     IdentityDocSchema,
		Version:    2,
		IssuedAt:   now.Unix(),
		Cards:      []IdentityCard{makeCard("k1")},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	// minVersion=5 → should reject version=2
	if err := VerifyIdentityDocStructure(&doc, 5, now, time.Hour); err == nil {
		t.Error("expected error for version below minVersion")
	}
}

func TestVerifyIdentityDocStructure_Stale(t *testing.T) {
	now := time.Now()
	doc := IdentityDoc{
		Schema:     IdentityDocSchema,
		Version:    1,
		IssuedAt:   now.Add(-2 * time.Hour).Unix(),
		Cards:      []IdentityCard{makeCard("k1")},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	if err := VerifyIdentityDocStructure(&doc, 1, now, time.Hour); err == nil {
		t.Error("expected error for stale doc")
	}
}

func TestVerifyIdentityDocStructure_FutureIssuedAt(t *testing.T) {
	now := time.Now()
	doc := IdentityDoc{
		Schema:     IdentityDocSchema,
		Version:    1,
		IssuedAt:   now.Add(10 * time.Minute).Unix(),
		Cards:      []IdentityCard{makeCard("k1")},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	if err := VerifyIdentityDocStructure(&doc, 1, now, time.Hour); err == nil {
		t.Error("expected error for future issued_at")
	}
}

func TestVerifyIdentityDocStructure_EmptyCards(t *testing.T) {
	now := time.Now()
	doc := IdentityDoc{
		Schema:     IdentityDocSchema,
		Version:    1,
		IssuedAt:   now.Unix(),
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	if err := VerifyIdentityDocStructure(&doc, 1, now, time.Hour); err == nil {
		t.Error("expected error for empty cards")
	}
}

// ---------------------------------------------------------------------------
// CheckIdentityDocQuorum
// ---------------------------------------------------------------------------

func TestCheckIdentityDocQuorum_Genesis_OK(t *testing.T) {
	cards := []IdentityCard{makeCard("k1"), makeCard("k2")}
	next := &IdentityDoc{
		Schema:     IdentityDocSchema,
		Version:    1,
		Cards:      cards,
		Signatures: []Signature{{Key: "k1", Sig: "s1"}, {Key: "k2", Sig: "s2"}},
	}
	if err := CheckIdentityDocQuorum(nil, next); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckIdentityDocQuorum_Genesis_MissingSig(t *testing.T) {
	cards := []IdentityCard{makeCard("k1"), makeCard("k2")}
	next := &IdentityDoc{
		Schema:     IdentityDocSchema,
		Version:    1,
		Cards:      cards,
		Signatures: []Signature{{Key: "k1", Sig: "s1"}}, // k2 missing
	}
	if err := CheckIdentityDocQuorum(nil, next); err == nil {
		t.Error("expected error when not all genesis cards sign")
	}
}

func TestCheckIdentityDocQuorum_Genesis_WrongVersion(t *testing.T) {
	cards := []IdentityCard{makeCard("k1")}
	next := &IdentityDoc{
		Version:    2,
		Cards:      cards,
		Signatures: []Signature{{Key: "k1", Sig: "s1"}},
	}
	if err := CheckIdentityDocQuorum(nil, next); err == nil {
		t.Error("expected error: genesis must have version=1")
	}
}

func TestCheckIdentityDocQuorum_FreshnessResign_OK(t *testing.T) {
	cards := []IdentityCard{makeCard("k1"), makeCard("k2")}
	prev := &IdentityDoc{Version: 1, Cards: cards}
	next := &IdentityDoc{
		Version:    2,
		Cards:      cards,
		Signatures: []Signature{{Key: "k1", Sig: "s1"}}, // one signer is enough
	}
	if err := CheckIdentityDocQuorum(prev, next); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckIdentityDocQuorum_FreshnessResign_NoAuthorizedSigner(t *testing.T) {
	cards := []IdentityCard{makeCard("k1"), makeCard("k2")}
	prev := &IdentityDoc{Version: 1, Cards: cards}
	next := &IdentityDoc{
		Version:    2,
		Cards:      cards,
		Signatures: []Signature{{Key: "unknown-key", Sig: "s"}},
	}
	if err := CheckIdentityDocQuorum(prev, next); err == nil {
		t.Error("expected error: signer not in authorized set")
	}
}

func TestCheckIdentityDocQuorum_Addition_OK(t *testing.T) {
	k1, k2 := makeCard("k1"), makeCard("k2")
	prev := &IdentityDoc{Version: 1, Cards: []IdentityCard{k1}}
	next := &IdentityDoc{
		Version:    2,
		Cards:      []IdentityCard{k1, k2},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}, {Key: "k2", Sig: "s2"}},
	}
	if err := CheckIdentityDocQuorum(prev, next); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckIdentityDocQuorum_Addition_MissingNewCard(t *testing.T) {
	k1, k2 := makeCard("k1"), makeCard("k2")
	prev := &IdentityDoc{Version: 1, Cards: []IdentityCard{k1}}
	next := &IdentityDoc{
		Version:    2,
		Cards:      []IdentityCard{k1, k2},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}}, // k2 (new card) must co-sign
	}
	if err := CheckIdentityDocQuorum(prev, next); err == nil {
		t.Error("expected error: new card must co-sign addition")
	}
}

func TestCheckIdentityDocQuorum_Removal_OK(t *testing.T) {
	k1, k2 := makeCard("k1"), makeCard("k2")
	prev := &IdentityDoc{Version: 1, Cards: []IdentityCard{k1, k2}}
	next := &IdentityDoc{
		Version:    2,
		Cards:      []IdentityCard{k1},
		Signatures: []Signature{{Key: "k1", Sig: "s1"}}, // remaining card signs
	}
	if err := CheckIdentityDocQuorum(prev, next); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckIdentityDocQuorum_Removal_RemovedCardSigns(t *testing.T) {
	k1, k2 := makeCard("k1"), makeCard("k2")
	prev := &IdentityDoc{Version: 1, Cards: []IdentityCard{k1, k2}}
	next := &IdentityDoc{
		Version: 2,
		Cards:   []IdentityCard{k1},
		// k2 is removed, but only k2 signed — no remaining card signed
		Signatures: []Signature{{Key: "k2", Sig: "s2"}},
	}
	// k2 is not in the trusted set (it's removed), so VerifyIdentityDocSigs would
	// catch it; CheckIdentityDocQuorum also rejects because k1 (remaining) is absent
	if err := CheckIdentityDocQuorum(prev, next); err == nil {
		t.Error("expected error: removed card signature without remaining card")
	}
}

func TestCheckIdentityDocQuorum_SimultaneousAddRemove_Rejected(t *testing.T) {
	k1, k2, k3 := makeCard("k1"), makeCard("k2"), makeCard("k3")
	prev := &IdentityDoc{Version: 1, Cards: []IdentityCard{k1, k2}}
	next := &IdentityDoc{
		Version:    2,
		Cards:      []IdentityCard{k1, k3}, // k2 removed, k3 added simultaneously
		Signatures: []Signature{{Key: "k1", Sig: "s1"}, {Key: "k2", Sig: "s2"}, {Key: "k3", Sig: "s3"}},
	}
	if err := CheckIdentityDocQuorum(prev, next); err == nil {
		t.Error("expected error: simultaneous add+remove must be two steps")
	}
}

// ---------------------------------------------------------------------------
// identityCardSetDiff
// ---------------------------------------------------------------------------

func TestIdentityCardSetDiff_NoChange(t *testing.T) {
	cards := []IdentityCard{makeCard("k1"), makeCard("k2")}
	removed, added := identityCardSetDiff(cards, cards)
	if len(removed) != 0 || len(added) != 0 {
		t.Errorf("expected no diff, got removed=%v added=%v", removed, added)
	}
}

func TestIdentityCardSetDiff_AddOne(t *testing.T) {
	prev := []IdentityCard{makeCard("k1")}
	next := []IdentityCard{makeCard("k1"), makeCard("k2")}
	removed, added := identityCardSetDiff(prev, next)
	if len(removed) != 0 {
		t.Errorf("expected no removals, got %v", removed)
	}
	if len(added) != 1 || added[0].AuthKey != "k2" {
		t.Errorf("expected k2 added, got %v", added)
	}
}

func TestIdentityCardSetDiff_RemoveOne(t *testing.T) {
	prev := []IdentityCard{makeCard("k1"), makeCard("k2")}
	next := []IdentityCard{makeCard("k1")}
	removed, added := identityCardSetDiff(prev, next)
	if len(added) != 0 {
		t.Errorf("expected no additions, got %v", added)
	}
	if len(removed) != 1 || removed[0].AuthKey != "k2" {
		t.Errorf("expected k2 removed, got %v", removed)
	}
}
