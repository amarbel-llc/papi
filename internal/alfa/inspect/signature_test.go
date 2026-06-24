package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
)

// signDoc builds a §10.4 ssh-9a-signed PAPI document around doc (a map without a
// signature member), signing the same way piggy does: full SSH-wire blob
// string(alg) || string(r,s) over the RFC 8785 JCS bytes. It publishes the
// signer's key in piggy.ssh_authorized_keys and returns the full document JSON.
func signDoc(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	piggy, _ := doc["piggy"].(map[string]any)
	if piggy == nil {
		piggy = map[string]any{}
		doc["piggy"] = piggy
	}
	piggy["ssh_authorized_keys"] = []any{keyLine}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	sshSig, err := signer.Sign(rand.Reader, canon)
	if err != nil {
		t.Fatal(err)
	}

	wire := append(sshString([]byte(sshSig.Format)), sshString([]byte(sshSig.Blob))...)
	doc["signature"] = map[string]any{
		"alg": "ssh-9a",
		"key": keyLine,
		"sig": base64.StdEncoding.EncodeToString(wire),
	}
	full, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func serveDoc(data []byte) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte(`,"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`))
	})
	return httptest.NewServer(mux)
}

func signaturePointFor(t *testing.T, data []byte) point {
	t.Helper()
	pts := signaturePointsFor(t, data, nil)
	return pts[len(pts)-1]
}

// signaturePointsFor runs signaturePoints against a server that serves data at
// /papi and, when piggyIDs is non-nil, those ids at /papi/piggy-ids.
func signaturePointsFor(t *testing.T, data []byte, piggyIDs []string) []point {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte(`,"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`))
	})
	if piggyIDs != nil {
		mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("# piggy-ids\n" + strings.Join(piggyIDs, "\n") + "\n"))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return signaturePoints(context.Background(), c)
}

func TestSignatureValid(t *testing.T) {
	full := signDoc(t, map[string]any{"version": "papi/v0", "person": map[string]any{"handle": "tester"}})
	p := signaturePointFor(t, full)
	if !p.ok || p.reason != "" {
		t.Fatalf("valid signature not accepted: %+v", p)
	}
	if !strings.Contains(p.desc, "signed-and-valid") {
		t.Errorf("desc = %q", p.desc)
	}
}

func TestSignatureTampered(t *testing.T) {
	full := signDoc(t, map[string]any{"version": "papi/v0", "person": map[string]any{"handle": "tester"}})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(full, &m); err != nil {
		t.Fatal(err)
	}
	m["person"] = json.RawMessage(`{"handle":"attacker"}`) // change signed content
	tampered, _ := json.Marshal(m)
	p := signaturePointFor(t, tampered)
	if p.ok || !p.must {
		t.Fatalf("tampered signature not flagged signed-but-invalid: %+v", p)
	}
}

func TestSignatureUnsigned(t *testing.T) {
	p := signaturePointFor(t, []byte(`{"version":"papi/v0","person":{"handle":"t"}}`))
	if p.reason == "" {
		t.Fatalf("unsigned doc should be a skip, got %+v", p)
	}
}

func TestSignatureKeyNotPublished(t *testing.T) {
	full := signDoc(t, map[string]any{"version": "papi/v0"})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(full, &m); err != nil {
		t.Fatal(err)
	}
	m["piggy"] = json.RawMessage(`{"ssh_authorized_keys":[]}`) // unpublish the signing key
	unpub, _ := json.Marshal(m)
	p := signaturePointFor(t, unpub)
	if p.reason == "" {
		t.Fatalf("unpublished key should be a skip (unverifiable), got %+v", p)
	}
}

// --- Amendment 9: signatures[] (markl-id, conjunctive) ---

// marklSigner is an ephemeral slot-9A-style P-256 signer expressed as the
// markl-ids an Amendment 9 signatures[] entry uses.
type marklSigner struct {
	priv    *ecdsa.PrivateKey
	keyID   string // piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…
	sshLine string // OpenSSH ecdsa-sha2-nistp256 line
}

func newMarklSigner(t *testing.T) marklSigner {
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
	return marklSigner{priv: priv, keyID: keyID, sshLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))}
}

// sigID returns a papi-doc-sig-v1@ecdsa_p256_sig markl-id over input (raw r‖s).
func (s marklSigner) sigID(t *testing.T, input []byte) string {
	t.Helper()
	digest := sha256.Sum256(input)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	id, err := markl.Build(markl.PurposeDocSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// marklInput computes the §10.2 signing input for base, which MUST NOT yet carry
// a signatures member (it is the JCS bytes a verifier reconstructs after strip).
func marklInput(t *testing.T, base map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	in, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func marshalDoc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignaturesValidPointMatch(t *testing.T) {
	s := newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{s.sshLine}},
	}
	input := marklInput(t, base)
	base["signatures"] = []any{map[string]any{"key": s.keyID, "sig": s.sigID(t, input)}}

	pts := signaturePointsFor(t, marshalDoc(t, base), nil) // no piggy-ids → ssh-keys point-match
	if len(pts) != 1 || !pts[0].ok || pts[0].reason != "" {
		t.Fatalf("valid markl signature not accepted: %+v", pts)
	}
	if !strings.Contains(pts[0].desc, "papi-doc-sig-v1") {
		t.Errorf("desc = %q", pts[0].desc)
	}
}

// TestVerifyDocumentWithPublishedIDs exercises the network-free §10 verify the
// wasm client uses (FDR-0007): a validly-signed document is authentic; a tampered
// one is not (signed-but-invalid); an unsigned one is not (a neutral skip).
func TestVerifyDocumentWithPublishedIDs(t *testing.T) {
	s := newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{s.sshLine}},
	}
	input := marklInput(t, base)
	base["signatures"] = []any{map[string]any{"key": s.keyID, "sig": s.sigID(t, input)}}

	res, err := VerifyDocumentWithPublishedIDs(marshalDoc(t, base), []string{s.keyID})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Authentic {
		t.Fatalf("validly-signed document not authentic: %+v", res)
	}

	// Tamper a signed field: the recomputed canonical input no longer matches the
	// signature → signed-but-invalid → not authentic.
	base["version"] = "papi/v0-tampered"
	res, err = VerifyDocumentWithPublishedIDs(marshalDoc(t, base), []string{s.keyID})
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	if res.Authentic {
		t.Errorf("tampered document should not be authentic: %+v", res)
	}

	// Unsigned → not authentic, but a neutral skip (no MUST failure).
	res, err = VerifyDocumentWithPublishedIDs([]byte(`{"version":"papi/v0"}`), nil)
	if err != nil {
		t.Fatalf("verify unsigned: %v", err)
	}
	if res.Authentic || len(res.Checks) != 1 || !res.Checks[0].Skipped {
		t.Errorf("unsigned document verdict = %+v", res)
	}
}

func TestSignaturesValidViaPiggyIDs(t *testing.T) {
	s := newMarklSigner(t)
	// Key published ONLY as a piggy-ids markl-id (ssh_authorized_keys empty),
	// exercising the canonical string-equality match.
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{}},
	}
	input := marklInput(t, base)
	base["signatures"] = []any{map[string]any{"key": s.keyID, "sig": s.sigID(t, input)}}

	pts := signaturePointsFor(t, marshalDoc(t, base), []string{s.keyID})
	if len(pts) != 1 || !pts[0].ok || pts[0].reason != "" {
		t.Fatalf("piggy-ids string-match not accepted: %+v", pts)
	}
}

func TestSignaturesMultiAllValid(t *testing.T) {
	a, b := newMarklSigner(t), newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{a.sshLine, b.sshLine}},
	}
	input := marklInput(t, base)
	base["signatures"] = []any{
		map[string]any{"key": a.keyID, "sig": a.sigID(t, input)},
		map[string]any{"key": b.keyID, "sig": b.sigID(t, input)},
	}

	pts := signaturePointsFor(t, marshalDoc(t, base), nil)
	if len(pts) != 2 {
		t.Fatalf("want 2 verdicts, got %d: %+v", len(pts), pts)
	}
	for i, p := range pts {
		if !p.ok || p.reason != "" {
			t.Errorf("entry %d not signed-and-valid: %+v", i, p)
		}
	}
}

func TestSignaturesOneInvalidFailsConjunctive(t *testing.T) {
	a, b := newMarklSigner(t), newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{a.sshLine, b.sshLine}},
	}
	input := marklInput(t, base)
	base["signatures"] = []any{
		map[string]any{"key": a.keyID, "sig": a.sigID(t, input)},
		// b signs the wrong bytes: a well-formed markl-id that fails to verify.
		map[string]any{"key": b.keyID, "sig": b.sigID(t, []byte("not the signing input"))},
	}

	pts := signaturePointsFor(t, marshalDoc(t, base), nil)
	if len(pts) != 2 {
		t.Fatalf("want 2 verdicts, got %d: %+v", len(pts), pts)
	}
	if !pts[0].ok {
		t.Errorf("entry 0 should be valid: %+v", pts[0])
	}
	if pts[1].ok || !pts[1].must {
		t.Errorf("entry 1 should be a signed-but-invalid MUST failure: %+v", pts[1])
	}
}

func TestSignaturesUnknownFormatSkipped(t *testing.T) {
	s := newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"piggy":   map[string]any{"ssh_authorized_keys": []any{s.sshLine}},
	}
	base["signatures"] = []any{
		// sig is a well-formed markl-id but not papi-doc-sig-v1@ecdsa_p256_sig.
		map[string]any{"key": s.keyID, "sig": s.keyID},
	}
	pts := signaturePointsFor(t, marshalDoc(t, base), nil)
	if len(pts) != 1 || pts[0].reason == "" {
		t.Fatalf("entry with a non-doc-sig markl-id should be a skip: %+v", pts)
	}
}

func TestSignaturesTamperedFails(t *testing.T) {
	s := newMarklSigner(t)
	base := map[string]any{
		"version": "papi/v0",
		"person":  map[string]any{"handle": "tester"},
		"piggy":   map[string]any{"ssh_authorized_keys": []any{s.sshLine}},
	}
	input := marklInput(t, base)
	base["signatures"] = []any{map[string]any{"key": s.keyID, "sig": s.sigID(t, input)}}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(marshalDoc(t, base), &m); err != nil {
		t.Fatal(err)
	}
	m["person"] = json.RawMessage(`{"handle":"attacker"}`) // mutate a signed field
	pts := signaturePointsFor(t, marshalDoc(t, m), nil)
	if len(pts) != 1 || pts[0].ok || !pts[0].must {
		t.Fatalf("tampered doc should be signed-but-invalid: %+v", pts)
	}
}
