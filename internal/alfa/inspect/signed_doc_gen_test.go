package inspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/gowebpki/jcs"
)

// detReader is a deterministic byte stream (a SHA-256 keystream over a counter),
// so the generated fixture — key, signature, and all — is reproducible:
// regenerating is a no-op unless the document shape changes. A real card is not
// available (and not wanted) for a committed test fixture.
type detReader struct {
	buf []byte
	ctr uint64
}

func (r *detReader) Read(p []byte) (int, error) {
	for i := range p {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			h := sha256.Sum256(append([]byte("papi-signed-doc-fixture/v1"), c[:]...))
			r.buf = h[:]
		}
		p[i] = r.buf[0]
		r.buf = r.buf[1:]
	}
	return len(p), nil
}

// TestGenerateSignedDocFixture writes a §10-signed /papi document (Amendment 9
// signatures[]) and its published slot-9A markl-id into clients/ts/testdata/, the
// fixture the bun §10-verify test (FDR-0007) consumes to prove the wasm client
// verifies a REAL signed document — the promotion-to-experimental bar. The signing
// key is published ONLY as a markl-id (piggy.ssh_authorized_keys is empty), so
// trust comes solely from the published id passed to the verifier — the canonical
// §10.1 path the TS Client.verifyDocument exercises (it fetches /papi/piggy-ids
// and passes them in). Gated by PAPI_GEN_SIGNED_DOC=1 (like the enroll
// sample-receipt generator); a normal `go test` skips it. Run `just debug-signed-doc`.
func TestGenerateSignedDocFixture(t *testing.T) {
	if os.Getenv("PAPI_GEN_SIGNED_DOC") == "" {
		t.Skip("set PAPI_GEN_SIGNED_DOC=1 to regenerate clients/ts/testdata/signed-papi.*")
	}

	rng := &detReader{}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rng)
	if err != nil {
		t.Fatal(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	keyID, err := markl.Build(markl.PurposePIVAuth, markl.FormatSSHEcdsaNistp256Pub, compressed)
	if err != nil {
		t.Fatal(err)
	}

	// The document to sign — no signatures member yet (that IS the §10.2 input).
	// ssh_authorized_keys is empty: the key is trusted only via the published id.
	doc := map[string]any{
		"version": "papi/v0",
		"person":  map[string]any{"handle": "fixture", "name": "PAPI Fixture"},
		"piggy":   map[string]any{"ssh_authorized_keys": []any{}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	input, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rng, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	sigID, err := markl.Build(markl.PurposeDocSig, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		t.Fatal(err)
	}
	doc["signatures"] = []any{map[string]any{"key": keyID, "sig": sigID}}

	// Self-check: the fixture MUST verify against keyID before we commit it.
	docBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyDocumentWithPublishedIDs(docBytes, []string{keyID})
	if err != nil || !res.Authentic {
		t.Fatalf("generated fixture does not self-verify: authentic=%v err=%v checks=%+v", res.Authentic, err, res.Checks)
	}

	// Commit the /papi envelope (what the client fetches) + the published id.
	envelope := map[string]any{
		"data": doc,
		"meta": map[string]any{"type": "papi", "version": "papi/v0", "visibility": "public"},
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	dir := signedDocFixtureDir(t)
	writeSignedDocFixture(t, filepath.Join(dir, "signed-papi.json"), append(body, '\n'))
	writeSignedDocFixture(t, filepath.Join(dir, "signed-papi.pubid.txt"), []byte(keyID+"\n"))
	t.Logf("wrote signed-papi.json + signed-papi.pubid.txt to %s", dir)
}

// signedDocFixtureDir locates clients/ts/testdata/ relative to this source file
// (robust to the test's CWD, which is the package dir).
func signedDocFixtureDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/alfa/inspect/<file> → repo root is three levels up.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(root, "clients", "ts", "testdata")
}

func writeSignedDocFixture(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
