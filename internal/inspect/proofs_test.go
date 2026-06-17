package inspect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/papi"
)

const proofRecipient = "piggy-recipient-v1@pivy_ecdh_p256_pub-aaa"

func proofServer(body string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
}

func TestVerifyProofVerified(t *testing.T) {
	srv := proofServer("github bio: " + proofRecipient + " — verified me")
	defer srv.Close()
	pr := papi.Proof{ID: "p1", Recipient: proofRecipient, Claim: "https://github.com/tester", ProofURI: srv.URL + "/proof"}
	p := verifyProof(context.Background(), srv.Client(), pr, 0, map[string]bool{proofRecipient: true}, map[string]bool{})
	if !p.ok || p.reason != "" {
		t.Fatalf("verified proof not accepted: %+v", p)
	}
	if !strings.Contains(p.desc, "verified") {
		t.Errorf("desc = %q", p.desc)
	}
}

func TestVerifyProofUnverified(t *testing.T) {
	srv := proofServer("this page has no backlink")
	defer srv.Close()
	pr := papi.Proof{ID: "p1", Recipient: proofRecipient, Claim: "https://github.com/tester", ProofURI: srv.URL + "/proof"}
	p := verifyProof(context.Background(), srv.Client(), pr, 0, map[string]bool{proofRecipient: true}, map[string]bool{})
	if p.ok || p.must || p.reason != "" {
		t.Fatalf("missing backlink should be unverified (a flag, not ok/must/skip): %+v", p)
	}
	if !strings.Contains(p.desc, "unverified") {
		t.Errorf("desc = %q", p.desc)
	}
}

func TestVerifyProofUnverifiable(t *testing.T) {
	published := map[string]bool{proofRecipient: true}
	cases := map[string]papi.Proof{
		"missing id":     {Recipient: proofRecipient, Claim: "c", ProofURI: "https://x/y"},
		"bad recipient":  {ID: "p", Recipient: "not-a-recipient", Claim: "c", ProofURI: "https://x/y"},
		"unpublished":    {ID: "p", Recipient: "piggy-recipient-v1@pivy_ecdh_p256_pub-zzz", Claim: "c", ProofURI: "https://x/y"},
		"unknown fmt":    {ID: "p", Recipient: proofRecipient, Claim: "c", ProofURI: "https://x/y", Fmt: "carrier-pigeon"},
		"signature fmt":  {ID: "p", Recipient: proofRecipient, Claim: "c", ProofURI: "https://x/y", Fmt: "signature"},
		"http proof_uri": {ID: "p", Recipient: proofRecipient, Claim: "c", ProofURI: "http://x/y"},
	}
	for name, pr := range cases {
		p := verifyProof(context.Background(), http.DefaultClient, pr, 0, published, map[string]bool{})
		if p.reason == "" {
			t.Errorf("%s: expected unverifiable (a skip), got %+v", name, p)
		}
	}
}

func TestVerifyProofDuplicateID(t *testing.T) {
	seen := map[string]bool{}
	published := map[string]bool{proofRecipient: true}
	pr := papi.Proof{ID: "dup", Recipient: proofRecipient, Claim: "c", ProofURI: "https://x/y", Fmt: "signature"}
	_ = verifyProof(context.Background(), http.DefaultClient, pr, 0, published, seen)
	p := verifyProof(context.Background(), http.DefaultClient, pr, 1, published, seen)
	if p.reason == "" || !strings.Contains(p.reason, "duplicate") {
		t.Fatalf("duplicate id not flagged unverifiable: %+v", p)
	}
}

func TestRecipientIDSet(t *testing.T) {
	entries := []json.RawMessage{
		json.RawMessage(`"piggy-recipient-v1@pivy_ecdh_p256_pub-aaa"`),
		json.RawMessage(`{"id":"piggy-recipient-v1@pivy_ecdh_p256_pub-bbb","label":"x"}`),
		json.RawMessage(`{"nope":"y"}`),
	}
	set := recipientIDSet(entries)
	if !set["piggy-recipient-v1@pivy_ecdh_p256_pub-aaa"] || !set["piggy-recipient-v1@pivy_ecdh_p256_pub-bbb"] {
		t.Errorf("recipientIDSet missed entries: %v", set)
	}
	if len(set) != 2 {
		t.Errorf("recipientIDSet size = %d, want 2: %v", len(set), set)
	}
}
