package inspect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// discoverySignaturePointsFor serves data at /papi and runs the §4.1 check
// against a discovery document carrying discSigs.
func discoverySignaturePointsFor(t *testing.T, data []byte, discSigs []papi.Signature) []point {
	t.Helper()
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
	return discoverySignaturePoints(context.Background(), c, &papi.Discovery{Signatures: discSigs})
}

// signedMarklDoc returns a /papi document signed by s, and its signatures.
func signedMarklDoc(t *testing.T, s marklSigner) ([]byte, []papi.Signature) {
	t.Helper()
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{s.sshLine}},
	}
	sig := papi.Signature{Key: s.keyID, Sig: s.sigID(t, marklInput(t, base))}
	base["signatures"] = []any{map[string]any{"key": sig.Key, "sig": sig.Sig}}
	return marshalDoc(t, base), []papi.Signature{sig}
}

func TestDiscoverySignaturesEqualEcho(t *testing.T) {
	doc, sigs := signedMarklDoc(t, newMarklSigner(t))
	pts := discoverySignaturePointsFor(t, doc, sigs)
	if len(pts) != 1 || !pts[0].ok || pts[0].reason != "" {
		t.Fatalf("an equal echo should be one ok point, got %+v", pts)
	}
}

func TestDiscoverySignaturesMissingEchoFails(t *testing.T) {
	doc, _ := signedMarklDoc(t, newMarklSigner(t))
	pts := discoverySignaturePointsFor(t, doc, nil)
	if len(pts) != 1 || pts[0].ok || !pts[0].must {
		t.Fatalf("a missing echo should be one MUST failure, got %+v", pts)
	}
}

// An echo that differs from /papi fails §4.1, and each discovery entry is still
// verified (§10.3): here a second card's valid signature verifies.
func TestDiscoverySignaturesDifferingEchoIsVerified(t *testing.T) {
	a, b := newMarklSigner(t), newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{a.sshLine, b.sshLine}},
	}
	input := marklInput(t, base)
	sigA := papi.Signature{Key: a.keyID, Sig: a.sigID(t, input)}
	sigB := papi.Signature{Key: b.keyID, Sig: b.sigID(t, input)}
	base["signatures"] = []any{map[string]any{"key": sigA.Key, "sig": sigA.Sig}}

	pts := discoverySignaturePointsFor(t, marshalDoc(t, base), []papi.Signature{sigB})
	if len(pts) != 2 {
		t.Fatalf("want a mismatch point and one entry verdict, got %+v", pts)
	}
	if pts[0].ok || !pts[0].must {
		t.Errorf("a differing echo should be a MUST failure, got %+v", pts[0])
	}
	if !pts[1].ok || pts[1].reason != "" {
		t.Errorf("the discovery entry's valid signature should verify, got %+v", pts[1])
	}
}

func TestDiscoverySignaturesUnsignedSkips(t *testing.T) {
	pts := discoverySignaturePointsFor(t, []byte(`{"version":"papi/v0"}`), nil)
	if len(pts) != 1 || pts[0].reason == "" {
		t.Fatalf("an unsigned document should be one skip, got %+v", pts)
	}
}
