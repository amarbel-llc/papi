//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/hyphence/go/hyphence"
	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

func TestExtractPigpenTypeLock(t *testing.T) {
	lines := []hyphence.MetadataLine{
		{Prefix: '-', Value: "piggy-recipient-v1@pivy_ecdh_p256_pub-qqq..."},
		{Prefix: '!', Value: "pigpen-v1@papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>"},
	}
	lock, ok := extractPigpenTypeLock(lines)
	if !ok {
		t.Fatal("want a lock on the type line, got none")
	}
	if lock != "papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>" {
		t.Errorf("unexpected lock value: %q", lock)
	}

	noLock := []hyphence.MetadataLine{{Prefix: '!', Value: "pigpen-v1"}}
	if _, ok := extractPigpenTypeLock(noLock); ok {
		t.Error("bare type line (no @lock) must report ok=false")
	}
}

func TestParsePigpenMetadataLines(t *testing.T) {
	const doc = "---\n" +
		"- piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqqquk3lm\n" +
		"! pigpen-v1\n" +
		"---\n"
	lines, err := parsePigpenMetadataLines([]byte(doc))
	if err != nil {
		t.Fatalf("parsePigpenMetadataLines: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 metadata lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Prefix != '-' || lines[1].Prefix != '!' {
		t.Errorf("unexpected prefixes: %+v", lines)
	}
	if lines[1].Value != "pigpen-v1" {
		t.Errorf("want type line value %q, got %q", "pigpen-v1", lines[1].Value)
	}
}

// --- pigpenSignaturePoints (§14.2, provisional/experimental) ---

// pigpenSigner is an ephemeral slot-9A-style P-256 signer expressed as the
// markl-id a pigpen `-` line publishes, mirroring marklSigner in
// signature_test.go.
type pigpenSigner struct {
	priv  *ecdsa.PrivateKey
	keyID string // piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…
}

func newPigpenSigner(t *testing.T) pigpenSigner {
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
	return pigpenSigner{priv: priv, keyID: keyID}
}

// renderPigpenDoc canonicalizes and serializes lines into hyphence document
// bytes via FormatBodyEmitter, the same encoder pigpenStripSelfBytes uses.
func renderPigpenDoc(t *testing.T, lines []hyphence.MetadataLine) []byte {
	t.Helper()
	doc := &hyphence.Document{Metadata: append([]hyphence.MetadataLine(nil), lines...)}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildPigpenDoc assembles a payload-less pigpen document publishing s's
// piv_auth key on a `-` line. When sign is true, it self-signs (strip-self,
// §14.2): signs pigpenStripSelfBytes of the unsigned lines, then embeds the
// resulting papi-pigpen-self-sig-v1@ecdsa_p256_sig lock on the `!` line.
// corrupt flips a signature byte after signing, producing a well-formed but
// invalid lock.
func buildPigpenDoc(t *testing.T, s pigpenSigner, sign, corrupt bool) []byte {
	t.Helper()
	lines := []hyphence.MetadataLine{
		{Prefix: '-', Value: s.keyID},
		{Prefix: '!', Value: "pigpen-v1"},
	}
	if !sign {
		return renderPigpenDoc(t, lines)
	}

	input, err := pigpenStripSelfBytes(lines)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	if corrupt {
		raw[0] ^= 0xFF
	}
	sigID, err := markl.Build(purposePigpenSelfSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	lines[1].Value = "pigpen-v1@" + sigID
	return renderPigpenDoc(t, lines)
}

// pigpenPointsFor runs pigpenSignaturePoints against a test server serving
// data at /papi/pigpen (or a 404 when notFound) and, when authIDs is
// non-nil, those ids at /papi/piggy-ids.
func pigpenPointsFor(t *testing.T, data []byte, notFound bool, authIDs []string) []point {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/pigpen", func(w http.ResponseWriter, _ *http.Request) {
		if notFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/vnd.pigpen")
		_, _ = w.Write(data)
	})
	if authIDs != nil {
		mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("# piggy-ids\n" + strings.Join(authIDs, "\n") + "\n"))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return pigpenSignaturePoints(context.Background(), c)
}

func TestPigpenSignatureVerification(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, true, false)
		pts := pigpenPointsFor(t, doc, false, []string{s.keyID})
		if len(pts) != 1 || !pts[0].ok || pts[0].reason != "" {
			t.Fatalf("valid pigpen self-signature not accepted: %+v", pts)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, true, true) // corrupt=true flips a sig byte
		pts := pigpenPointsFor(t, doc, false, []string{s.keyID})
		if len(pts) != 1 || pts[0].ok || !pts[0].must {
			t.Fatalf("tampered pigpen self-signature not flagged signed-but-invalid: %+v", pts)
		}
	})

	t.Run("unpublished", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, true, false)
		// The signing key is never advertised on /papi/piggy-ids.
		pts := pigpenPointsFor(t, doc, false, []string{})
		if len(pts) != 1 || pts[0].reason == "" {
			t.Fatalf("unpublished pigpen key should be a skip (unverifiable): %+v", pts)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		lines := []hyphence.MetadataLine{{Prefix: '!', Value: "pigpen-v1@not-a-valid-markl-lock"}}
		doc := renderPigpenDoc(t, lines)
		pts := pigpenPointsFor(t, doc, false, nil)
		if len(pts) != 1 || pts[0].reason == "" {
			t.Fatalf("malformed lock should be a skip (unverifiable): %+v", pts)
		}
	})

	t.Run("absent endpoint", func(t *testing.T) {
		pts := pigpenPointsFor(t, nil, true, nil)
		if len(pts) != 1 || pts[0].reason == "" {
			t.Fatalf("404 /papi/pigpen should be a skip, never a fail: %+v", pts)
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, false, false)
		pts := pigpenPointsFor(t, doc, false, []string{s.keyID})
		if len(pts) != 1 || pts[0].reason == "" {
			t.Fatalf("bare (unsigned) pigpen doc should be a skip, never a fail: %+v", pts)
		}
	})
}
