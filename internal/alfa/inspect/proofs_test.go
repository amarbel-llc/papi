package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

// withTXTLookup swaps the package txtLookup resolver for the duration of a test.
func withTXTLookup(t *testing.T, fn func(context.Context, string) ([]string, error)) {
	t.Helper()
	prev := txtLookup
	txtLookup = fn
	t.Cleanup(func() { txtLookup = prev })
}

func dnsProof() papi.Proof {
	return papi.Proof{ID: "d1", Recipient: proofRecipient, Claim: "dns:linenisgreat.com", ProofURI: "dns:linenisgreat.com"}
}

func verifyDNSProof(t *testing.T, pr papi.Proof) point {
	t.Helper()
	return verifyProof(context.Background(), http.DefaultClient, pr, 0,
		map[string]bool{proofRecipient: true}, map[string]bool{}, nil)
}

func TestVerifyProofDNSVerified(t *testing.T) {
	withTXTLookup(t, func(_ context.Context, name string) ([]string, error) {
		if name != "linenisgreat.com" {
			t.Errorf("looked up %q, want linenisgreat.com (the opaque dns: name)", name)
		}
		return []string{"v=spf1 -all", "papi-proof=" + proofRecipient}, nil
	})
	p := verifyDNSProof(t, dnsProof())
	if !p.ok || p.reason != "" {
		t.Fatalf("dns proof whose TXT backlinks the recipient should verify: %+v", p)
	}
	if !strings.Contains(p.desc, "TXT record backlinks") {
		t.Errorf("desc = %q", p.desc)
	}
}

func TestVerifyProofDNSUnverified(t *testing.T) {
	withTXTLookup(t, func(context.Context, string) ([]string, error) {
		return []string{"v=spf1 -all"}, nil
	})
	p := verifyDNSProof(t, dnsProof())
	if p.ok || p.must || p.reason != "" {
		t.Fatalf("a TXT set without the recipient id should be unverified (a flag): %+v", p)
	}
}

func TestVerifyProofDNSLookupFails(t *testing.T) {
	withTXTLookup(t, func(context.Context, string) ([]string, error) {
		return nil, errors.New("NXDOMAIN")
	})
	p := verifyDNSProof(t, dnsProof())
	if p.ok || p.must || p.reason != "" {
		t.Fatalf("a failed TXT lookup should be unverified (a flag), never verified: %+v", p)
	}
}

func TestVerifyProofDNSNoHostname(t *testing.T) {
	pr := dnsProof()
	pr.ProofURI = "dns:"
	p := verifyDNSProof(t, pr)
	if p.reason == "" {
		t.Fatalf("a dns: proof_uri with no hostname should be unverifiable (a skip): %+v", p)
	}
}

func TestVerifyProofUnsupportedScheme(t *testing.T) {
	pr := dnsProof()
	pr.ProofURI = "ftp://x/y"
	p := verifyDNSProof(t, pr)
	if p.reason == "" || !strings.Contains(p.reason, "scheme") {
		t.Fatalf("an unsupported proof_uri scheme should be unverifiable (a skip): %+v", p)
	}
}

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
	p := verifyProof(context.Background(), srv.Client(), pr, 0, map[string]bool{proofRecipient: true}, map[string]bool{}, nil)
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
	p := verifyProof(context.Background(), srv.Client(), pr, 0, map[string]bool{proofRecipient: true}, map[string]bool{}, nil)
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
		"http proof_uri": {ID: "p", Recipient: proofRecipient, Claim: "c", ProofURI: "http://x/y"},
	}
	for name, pr := range cases {
		p := verifyProof(context.Background(), http.DefaultClient, pr, 0, published, map[string]bool{}, nil)
		if p.reason == "" {
			t.Errorf("%s: expected unverifiable (a skip), got %+v", name, p)
		}
	}
}

func TestVerifyProofDuplicateID(t *testing.T) {
	seen := map[string]bool{}
	published := map[string]bool{proofRecipient: true}
	// An unsupported scheme keeps the first call hermetic (no network); the
	// duplicate-id check fires before scheme dispatch on the second call anyway.
	pr := papi.Proof{ID: "dup", Recipient: proofRecipient, Claim: "c", ProofURI: "ftp://x/y"}
	_ = verifyProof(context.Background(), http.DefaultClient, pr, 0, published, seen, nil)
	p := verifyProof(context.Background(), http.DefaultClient, pr, 1, published, seen, nil)
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

// --- §9.3 fmt="signature" (papi-proof-sig-v1 markl-id) ---

// proofSig signs the claim string with priv (slot-9A style) and returns a
// papi-proof-sig-v1@ecdsa_p256_sig markl-id — the backlink a producer embeds.
func proofSig(t *testing.T, priv *ecdsa.PrivateKey, claim string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(claim))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	id, err := markl.Build(markl.PurposeProofSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

const sigClaim = "https://github.com/tester"

func sigProof(uri string) papi.Proof {
	return papi.Proof{ID: "ps", Recipient: proofRecipient, Claim: sigClaim, ProofURI: uri, Fmt: "signature"}
}

func TestVerifySignatureProofVerified(t *testing.T) {
	s := newMarklSigner(t)
	srv := proofServer("my identity proof: " + proofSig(t, s.priv, sigClaim) + " — done")
	defer srv.Close()
	p := verifySignatureProof(context.Background(), srv.Client(), sigProof(srv.URL+"/p"),
		`proof[0] "ps"`, []*ecdsa.PublicKey{&s.priv.PublicKey})
	if !p.ok || p.reason != "" {
		t.Fatalf("valid proof signature not accepted: %+v", p)
	}
	if !strings.Contains(p.desc, "papi-proof-sig-v1") {
		t.Errorf("desc = %q", p.desc)
	}
}

func TestVerifySignatureProofWrongKey(t *testing.T) {
	s, other := newMarklSigner(t), newMarklSigner(t)
	srv := proofServer(proofSig(t, s.priv, sigClaim))
	defer srv.Close()
	// Verified against a different published key only → unverified (a flag).
	p := verifySignatureProof(context.Background(), srv.Client(), sigProof(srv.URL+"/p"),
		`proof[0] "ps"`, []*ecdsa.PublicKey{&other.priv.PublicKey})
	if p.ok || p.must || p.reason != "" {
		t.Fatalf("signature matching no published key should be unverified: %+v", p)
	}
}

func TestVerifySignatureProofNoMarklID(t *testing.T) {
	s := newMarklSigner(t)
	srv := proofServer("this page has no proof signature")
	defer srv.Close()
	p := verifySignatureProof(context.Background(), srv.Client(), sigProof(srv.URL+"/p"),
		`proof[0] "ps"`, []*ecdsa.PublicKey{&s.priv.PublicKey})
	if p.ok || p.reason != "" || !strings.Contains(p.desc, "no papi-proof-sig-v1") {
		t.Fatalf("missing markl-id should be unverified: %+v", p)
	}
}

func TestVerifySignatureProofNoPublishedKeys(t *testing.T) {
	s := newMarklSigner(t)
	srv := proofServer(proofSig(t, s.priv, sigClaim))
	defer srv.Close()
	// A well-formed signature but no published slot-9A key to check it → skip.
	p := verifySignatureProof(context.Background(), srv.Client(), sigProof(srv.URL+"/p"), `proof[0] "ps"`, nil)
	if p.reason == "" {
		t.Fatalf("no published signing key should be unverifiable (a skip): %+v", p)
	}
}

func TestFindProofSigMarklID(t *testing.T) {
	s := newMarklSigner(t)
	id := proofSig(t, s.priv, sigClaim)
	got, ok := findProofSigMarklID("noise " + id + " trailing words")
	if !ok || got.Raw != id {
		t.Fatalf("findProofSigMarklID = %q,%v, want %q", got.Raw, ok, id)
	}
	if _, ok := findProofSigMarklID("no markl-id here"); ok {
		t.Error("findProofSigMarklID matched nothing-string")
	}
}
