//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/hyphence/go/hyphence"
	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/alfa/papi"
)

const testProfilePurpose = "conformist-profile-sig-v1"

const testProfileDoc = "---\n" +
	"# house lint profile\n" +
	"! toml-conformist_profile-v1\n" +
	"---\n" +
	"\n" +
	"[linters.shellcheck]\n" +
	"enabled = true\n"

type ecdsaTestSigner struct{ priv *ecdsa.PrivateKey }

func (s ecdsaTestSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	return raw, nil
}

func signTestProfile(t *testing.T, s pigpenSigner) []byte {
	t.Helper()
	signed, err := SignHyphence(context.Background(), ecdsaTestSigner{s.priv}, "", testProfilePurpose, []byte(testProfileDoc))
	if err != nil {
		t.Fatalf("SignHyphence: %v", err)
	}
	return signed
}

func TestHyphenceStripSelfBytesDefinition(t *testing.T) {
	lines, body, err := parseHyphenceDocument([]byte(testProfileDoc))
	if err != nil {
		t.Fatal(err)
	}
	lines = append([]hyphence.MetadataLine{{Prefix: '-', Value: testProfilePurpose + "@ignored"}}, lines...)
	got, err := HyphenceStripSelfBytes(lines, body, testProfilePurpose)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testProfileDoc {
		t.Errorf("signed input:\n%q\nwant:\n%q", got, testProfileDoc)
	}
}

func TestHyphenceStripSelfBytesMatchesPigpenForPayloadless(t *testing.T) {
	s := newPigpenSigner(t)
	lines, body, err := parseHyphenceDocument(buildPigpenDoc(t, s, true, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Fatalf("payload-less pigpen doc parsed a body: %q", body)
	}
	generic, err := HyphenceStripSelfBytes(lines, body, markl.PurposePigpenSelfSig)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := pigpenStripSelfBytes(lines)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generic, legacy) {
		t.Errorf("generic %q != pigpen %q", generic, legacy)
	}
}

func TestVerifyHyphenceAcceptsExistingPigpenSignature(t *testing.T) {
	s := newPigpenSigner(t)
	doc := buildPigpenDoc(t, s, true, false)
	keyID, err := VerifyHyphenceSignature(doc, markl.PurposePigpenSelfSig, []string{s.keyID})
	if err != nil {
		t.Fatalf("VerifyHyphenceSignature: %v", err)
	}
	if keyID != s.keyID {
		t.Errorf("verified with %q, want %q", keyID, s.keyID)
	}
}

func TestSignHyphenceRoundTripWithBody(t *testing.T) {
	s := newPigpenSigner(t)
	other := newPigpenSigner(t)
	signed := signTestProfile(t, s)

	if !bytes.HasSuffix(signed, []byte("\n\n[linters.shellcheck]\nenabled = true\n")) {
		t.Errorf("signed document lost its body:\n%s", signed)
	}
	if !strings.Contains(string(signed), "- "+testProfilePurpose+"@ecdsa_p256_sig-") {
		t.Errorf("signed document has no signature line:\n%s", signed)
	}

	keyID, err := VerifyHyphenceSignature(signed, testProfilePurpose, []string{"# comment-free ids only", other.keyID, s.keyID})
	if err != nil {
		t.Fatalf("VerifyHyphenceSignature: %v", err)
	}
	if keyID != s.keyID {
		t.Errorf("verified with %q, want %q", keyID, s.keyID)
	}
}

func TestVerifyHyphenceRejections(t *testing.T) {
	s := newPigpenSigner(t)
	signed := signTestProfile(t, s)
	published := []string{s.keyID}

	cases := []struct {
		name      string
		doc       []byte
		purpose   string
		published []string
		want      error
	}{
		{"tampered body", bytes.Replace(signed, []byte("enabled = true"), []byte("enabled = false"), 1), testProfilePurpose, published, ErrHyphenceSigInvalid},
		{"tampered metadata", bytes.Replace(signed, []byte("# house lint profile"), []byte("# other profile"), 1), testProfilePurpose, published, ErrHyphenceSigInvalid},
		{"body appended", append(append([]byte(nil), signed...), []byte("extra = 1\n")...), testProfilePurpose, published, ErrHyphenceSigInvalid},
		{"unpublished key", signed, testProfilePurpose, []string{newPigpenSigner(t).keyID}, ErrHyphenceSigInvalid},
		{"no published keys", signed, testProfilePurpose, nil, ErrHyphenceNoPublishedKey},
		{"other purpose", signed, markl.PurposePigpenSelfSig, published, ErrHyphenceUnsigned},
		{"unsigned", []byte(testProfileDoc), testProfilePurpose, published, ErrHyphenceUnsigned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyHyphenceSignature(tc.doc, tc.purpose, tc.published)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSignHyphenceRefusals(t *testing.T) {
	s := newPigpenSigner(t)
	signer := ecdsaTestSigner{s.priv}
	ctx := context.Background()

	if _, err := SignHyphence(ctx, signer, "", testProfilePurpose, signTestProfile(t, s)); !errors.Is(err, ErrHyphenceAlreadySigned) {
		t.Errorf("re-sign: got %v, want ErrHyphenceAlreadySigned", err)
	}
	noType := "---\n# no type\n---\n\nbody\n"
	if _, err := SignHyphence(ctx, signer, "", testProfilePurpose, []byte(noType)); !errors.Is(err, ErrHyphenceNoTypeLine) {
		t.Errorf("no type line: got %v, want ErrHyphenceNoTypeLine", err)
	}
	if _, err := SignHyphence(ctx, signer, "", "bad@purpose", []byte(testProfileDoc)); err == nil {
		t.Error("purpose containing @ must be rejected")
	}
	failing := failingHyphenceSigner{}
	if _, err := SignHyphence(ctx, failing, "", testProfilePurpose, []byte(testProfileDoc)); !errors.Is(err, errFailingSigner) {
		t.Errorf("signer failure: got %v, want wrapped errFailingSigner", err)
	}
}

var errFailingSigner = errors.New("card unavailable")

type failingHyphenceSigner struct{}

func (failingHyphenceSigner) SignSlot9A(context.Context, string, []byte) ([]byte, error) {
	return nil, errFailingSigner
}

func TestResolveHyphence(t *testing.T) {
	s := newPigpenSigner(t)
	signed := signTestProfile(t, s)

	mux := http.NewServeMux()
	mux.HandleFunc("/papi/conformist-profile", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(signed)
	})
	mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# ids\n" + s.keyID + "  # 9A\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolveHyphence(context.Background(), c, "/papi/conformist-profile", testProfilePurpose)
	if err != nil {
		t.Fatalf("ResolveHyphence: %v", err)
	}
	if !bytes.Equal(got, signed) {
		t.Error("ResolveHyphence must pass the fetched bytes through unmodified")
	}
	if _, err := ResolveHyphence(context.Background(), c, "/papi/missing", testProfilePurpose); err == nil {
		t.Error("a 404 must be an error")
	}
}
