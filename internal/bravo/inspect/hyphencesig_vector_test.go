//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"code.linenisgreat.com/papi/internal/0/markl"
)

// hyphenceSigVector is the cross-implementation conformance vector for RFC-0001
// §15.1/§15.2, consumed verbatim by non-papi verifiers (conformist).
type hyphenceSigVector struct {
	Description                  string `json:"description"`
	Spec                         string `json:"spec"`
	Purpose                      string `json:"purpose"`
	PublicKey                    string `json:"public_key"`
	UnsignedDocument             string `json:"unsigned_document"`
	UnsignedDocumentNonCanonical string `json:"unsigned_document_noncanonical_order"`
	SignedInputHex               string `json:"signed_input_hex"`
	SignedDocument               string `json:"signed_document"`
}

const hyphenceSigVectorFile = "rfc0001-s15-hyphence-sig-v1.json"

const vectorUnsignedDocument = "---\n" +
	"# house lint profile\n" +
	"% pins reviewed by the operator\n" +
	"- lint-profile-example\n" +
	"! toml-conformist_profile-v1\n" +
	"---\n" +
	"\n" +
	"[meta]\n" +
	"description = \"the house's lint profile\"\n" +
	"\n" +
	"[linters.shellcheck]\n" +
	"enabled = true\n"

const vectorUnsignedDocumentNonCanonical = "---\n" +
	"! toml-conformist_profile-v1\n" +
	"% pins reviewed by the operator\n" +
	"- lint-profile-example\n" +
	"# house lint profile\n" +
	"---\n" +
	"\n" +
	"[meta]\n" +
	"description = \"the house's lint profile\"\n" +
	"\n" +
	"[linters.shellcheck]\n" +
	"enabled = true\n"

type detHyphenceSigner struct {
	priv *ecdsa.PrivateKey
	rng  *detReader
}

func (s detHyphenceSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(s.rng, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	return raw, nil
}

func hyphenceSigVectorPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "docs", "rfcs", "vectors", hyphenceSigVectorFile)
}

func signedInputFor(t *testing.T, doc []byte, purpose string) []byte {
	t.Helper()
	lines, body, err := parseHyphenceDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	input, err := HyphenceStripSelfBytes(lines, body, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// TestGenerateHyphenceSigVector regenerates the committed vector. Gated by
// PAPI_GEN_HYPHENCE_SIG_VECTOR=1; run `just debug-hyphence-sig-vector`.
func TestGenerateHyphenceSigVector(t *testing.T) {
	if os.Getenv("PAPI_GEN_HYPHENCE_SIG_VECTOR") == "" {
		t.Skip("set PAPI_GEN_HYPHENCE_SIG_VECTOR=1 to regenerate docs/rfcs/vectors/" + hyphenceSigVectorFile)
	}

	rng := &detReader{}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rng)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := markl.Build(markl.PurposePIVAuth, markl.FormatSSHEcdsaNistp256Pub,
		elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))
	if err != nil {
		t.Fatal(err)
	}

	const purpose = "conformist-profile-sig-v1"
	signed, err := SignHyphence(context.Background(), detHyphenceSigner{priv, rng}, "", purpose, []byte(vectorUnsignedDocument))
	if err != nil {
		t.Fatal(err)
	}

	v := hyphenceSigVector{
		Description: "Test vector for RFC-0001 §15 signed hyphence documents. The key is a deterministic TEST key; " +
			"never trust it. signed_input_hex is the §15.1 signed input of unsigned_document; " +
			"unsigned_document_noncanonical_order and signed_document MUST yield the same signed input; " +
			"signed_document MUST verify against public_key under purpose.",
		Spec:                         "papi RFC-0001 §15.1-§15.2 (Amendment 26)",
		Purpose:                      purpose,
		PublicKey:                    keyID,
		UnsignedDocument:             vectorUnsignedDocument,
		UnsignedDocumentNonCanonical: vectorUnsignedDocumentNonCanonical,
		SignedInputHex:               hex.EncodeToString(signedInputFor(t, []byte(vectorUnsignedDocument), purpose)),
		SignedDocument:               string(signed),
	}
	checkHyphenceSigVector(t, v)

	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := hyphenceSigVectorPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

func TestHyphenceSigVectorConformance(t *testing.T) {
	raw, err := os.ReadFile(hyphenceSigVectorPath(t))
	if err != nil {
		t.Fatalf("read committed vector (regenerate with `just debug-hyphence-sig-vector`): %v", err)
	}
	var v hyphenceSigVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	checkHyphenceSigVector(t, v)
}

func checkHyphenceSigVector(t *testing.T, v hyphenceSigVector) {
	t.Helper()
	want, err := hex.DecodeString(v.SignedInputHex)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unsigned_document":                    v.UnsignedDocument,
		"unsigned_document_noncanonical_order": v.UnsignedDocumentNonCanonical,
		"signed_document":                      v.SignedDocument,
	} {
		if got := signedInputFor(t, []byte(doc), v.Purpose); !bytes.Equal(got, want) {
			t.Errorf("%s: signed input\n%q\nwant\n%q", name, got, want)
		}
	}
	if !bytes.Equal(want, []byte(v.UnsignedDocument)) {
		t.Errorf("unsigned_document is not already canonical; its signed input differs from its bytes")
	}
	if keyID, err := VerifyHyphenceSignature([]byte(v.SignedDocument), v.Purpose, []string{v.PublicKey}); err != nil || keyID != v.PublicKey {
		t.Errorf("signed_document does not verify against public_key: key=%q err=%v", keyID, err)
	}
}
