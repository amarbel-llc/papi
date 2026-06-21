package markl

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vector mirrors one entry in madder's RFC-0002 conformance fixture
// (testdata/0002-markl-id-format-vectors.json), vendored byte-for-byte from
// amarbel-llc/madder so papi's port stays cross-implementation compatible.
type vector struct {
	Name       string `json:"name"`
	Purpose    string `json:"purpose"`
	Format     string `json:"format"`
	PayloadHex string `json:"payload_hex"`
	Encoded    string `json:"encoded"`
	Error      string `json:"error"`
}

type vectorFile struct {
	Vectors []vector `json:"vectors"`
	Invalid []vector `json:"invalid"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "0002-markl-id-format-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vf.Vectors) == 0 || len(vf.Invalid) == 0 {
		t.Fatalf("empty vector file: %d valid, %d invalid", len(vf.Vectors), len(vf.Invalid))
	}
	return vf
}

// TestVectorsRoundTrip is the cross-impl gate: every valid madder vector must
// Parse to the same purpose/format/payload, and Build back to the same string.
func TestVectorsRoundTrip(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			wantPayload, err := hex.DecodeString(v.PayloadHex)
			if err != nil {
				t.Fatalf("bad payload_hex: %v", err)
			}

			id, err := Parse(v.Encoded)
			if err != nil {
				t.Fatalf("Parse(%q): %v", v.Encoded, err)
			}
			if id.Purpose != v.Purpose || id.Format != v.Format {
				t.Errorf("Parse purpose/format = %q/%q, want %q/%q", id.Purpose, id.Format, v.Purpose, v.Format)
			}
			if hex.EncodeToString(id.Payload) != v.PayloadHex {
				t.Errorf("Parse payload = %x, want %s", id.Payload, v.PayloadHex)
			}

			got, err := Build(v.Purpose, v.Format, wantPayload)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got != v.Encoded {
				t.Errorf("Build = %q, want %q", got, v.Encoded)
			}
		})
	}
}

// TestPapiVectorsTyped pins the exact markl-ids the §10 Amendment 9 verifier
// reads, with size validation engaged (these formats are in formatSizes).
func TestPapiVectorsTyped(t *testing.T) {
	want := map[string]struct{ purpose, format string }{
		"papi-doc-sig-v1@ecdsa_p256_sig":           {PurposeDocSig, FormatEcdsaP256Sig},
		"piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub": {PurposePIVAuth, FormatSSHEcdsaNistp256Pub},
	}
	seen := map[string]bool{}
	for _, v := range loadVectors(t).Vectors {
		key := v.Purpose + "@" + v.Format
		exp, ok := want[key]
		if !ok {
			continue
		}
		seen[key] = true
		id, err := Parse(v.Encoded)
		if err != nil {
			t.Fatalf("%s: Parse: %v", v.Name, err)
		}
		if id.Purpose != exp.purpose || id.Format != exp.format {
			t.Errorf("%s: got %q/%q", v.Name, id.Purpose, id.Format)
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("vector for %q not found in fixture", key)
		}
	}
}

// TestInvalidVectorsCodec asserts the codec-level invalid vectors are rejected.
// The registry-level errors (WrongSize on sha256, IncompatiblePurposeAndFormat
// on dodder purposes) exercise madder's full registry, which papi does not
// replicate — purpose/format policy is the §10 verifier's job — so they are
// covered by TestWrongSizeKnownFormat instead.
func TestInvalidVectorsCodec(t *testing.T) {
	codec := map[string]error{
		"MixedCase":        ErrMixedCase,
		"SeparatorMissing": ErrSeparatorMissing,
		"InvalidChecksum":  ErrInvalidChecksum,
		"InvalidCharacter": ErrInvalidCharacter,
	}
	for _, v := range loadVectors(t).Invalid {
		want, ok := codec[v.Error]
		if !ok {
			t.Logf("skipping registry-level invalid vector %q (%s)", v.Name, v.Error)
			continue
		}
		if _, err := Parse(v.Encoded); !errors.Is(err, want) {
			t.Errorf("%s: Parse error = %v, want %v", v.Name, err, want)
		}
	}
}

// TestWrongSizeKnownFormat: a payload of the wrong length for a known format is
// rejected even though its blech32 envelope is valid.
func TestWrongSizeKnownFormat(t *testing.T) {
	// 33 bytes under ecdsa_p256_sig (which RFC-0002 §5 fixes at 64).
	bad, err := blech32Encode(FormatEcdsaP256Sig, make([]byte, 33))
	if err != nil {
		t.Fatalf("blech32Encode: %v", err)
	}
	if _, err := Parse(bad); !errors.Is(err, ErrWrongSize) {
		t.Fatalf("Parse(wrong-size) error = %v, want ErrWrongSize", err)
	}
}

// ecdsaP256Body returns the blech32 body of an ...@ecdsa_p256_sig markl-id (the
// part after the format prefix), independent of the purpose decoration.
func ecdsaP256Body(t *testing.T, encoded string) string {
	t.Helper()
	const marker = FormatEcdsaP256Sig + "-"
	i := strings.LastIndex(encoded, marker)
	if i < 0 {
		t.Fatalf("no %s body in %q", FormatEcdsaP256Sig, encoded)
	}
	return encoded[i+len(marker):]
}

// TestPapiOwnedVectors validates the papi-owned conformance vectors
// (testdata/papi-sig-vectors.json) — the purposes papi registers itself under
// ADR-0006 (papi-doc-sig-v1, papi-proof-sig-v1, papi-enroll-att-v1). Each round-trips through
// Parse/Build, and its ecdsa_p256_sig body is cross-checked against the vendored
// RFC-0002 framework vector: the blech32 checksum binds to the format, so the
// body is purpose-independent and must equal the framework's canonical encoding.
// This anchors papi's vectors to the shared framework rather than to themselves.
func TestPapiOwnedVectors(t *testing.T) {
	var frameworkBody string
	for _, v := range loadVectors(t).Vectors {
		if v.Format == FormatEcdsaP256Sig && v.Purpose == "" {
			frameworkBody = ecdsaP256Body(t, v.Encoded)
		}
	}
	if frameworkBody == "" {
		t.Fatal("no framework ecdsa_p256_sig vector in the vendored fixture")
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "papi-sig-vectors.json"))
	if err != nil {
		t.Fatalf("read papi vectors: %v", err)
	}
	var pf struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &pf); err != nil {
		t.Fatalf("parse papi vectors: %v", err)
	}

	want := map[string]bool{PurposeDocSig: false, PurposeProofSig: false, PurposeEnrollAtt: false}
	for _, v := range pf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			payload, err := hex.DecodeString(v.PayloadHex)
			if err != nil {
				t.Fatalf("bad payload_hex: %v", err)
			}
			id, err := Parse(v.Encoded)
			if err != nil {
				t.Fatalf("Parse(%q): %v", v.Encoded, err)
			}
			if id.Purpose != v.Purpose || id.Format != FormatEcdsaP256Sig {
				t.Errorf("Parse purpose/format = %q/%q, want %q/%s", id.Purpose, id.Format, v.Purpose, FormatEcdsaP256Sig)
			}
			if hex.EncodeToString(id.Payload) != v.PayloadHex {
				t.Errorf("Parse payload = %x, want %s", id.Payload, v.PayloadHex)
			}
			got, err := Build(v.Purpose, v.Format, payload)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got != v.Encoded {
				t.Errorf("Build = %q, want %q", got, v.Encoded)
			}
			if body := ecdsaP256Body(t, v.Encoded); body != frameworkBody {
				t.Errorf("ecdsa_p256_sig body %q != framework %q", body, frameworkBody)
			}
		})
		if _, ok := want[v.Purpose]; ok {
			want[v.Purpose] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("missing papi-owned vector for purpose %q", p)
		}
	}
}
