package main

import (
	"bytes"
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
)

// purposePigpenSelfSig mirrors the unexported constant of the same name in
// internal/alfa/inspect (pigpen.go) — papi's provisional, piggy-unratified
// self-signature purpose token (RFC-0001 §14.2). Package main can't import
// it directly, and duplicating the literal here (rather than exporting it
// just for a test) keeps inspect's provisional-scheme warning contained to
// one package. If that constant is ever renamed, this test fixture's
// signature will simply stop verifying (fail loud, not silently pass).
const purposePigpenSelfSig = "papi-pigpen-self-sig-v1"

// renderPigpenLines canonicalizes and serializes lines into hyphence
// document bytes via FormatBodyEmitter — mirrors
// internal/alfa/inspect/pigpen_test.go's renderPigpenDoc, reimplemented here
// since that helper is unexported in a different package.
func renderPigpenLines(t *testing.T, lines []hyphence.MetadataLine) []byte {
	t.Helper()
	doc := &hyphence.Document{Metadata: append([]hyphence.MetadataLine(nil), lines...)}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newSignedPigpenFixture starts an httptest.Server that serves a genuinely
// self-signed /papi/pigpen document (RFC-0001 §14.2) plus the matching
// /papi/piggy-ids publication, and returns the server and the exact document
// bytes a successful resolve should echo to stdout unmodified.
//
// This duplicates the signing recipe from
// internal/alfa/inspect/pigpen_test.go's buildPigpenDoc (strip-self bytes via
// a bare `! pigpen-v1` line, sign, re-embed the lock) because that package's
// crypto-critical core (verifyPigpenSelfSignature, pigpenStripSelfBytes) is
// unexported and this is a different package (main). The crypto verification
// logic itself is already exhaustively covered by
// internal/alfa/inspect/pigpen_test.go (TestResolvePigpen and friends); this
// fixture exists only to prove run()'s argv/stdout/stderr/exit-code plumbing
// carries a real success end to end, not to re-prove the crypto.
func newSignedPigpenFixture(t *testing.T) (srv *httptest.Server, doc []byte) {
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

	lines := []hyphence.MetadataLine{
		{Prefix: '-', Value: keyID},
		{Prefix: '!', Value: "pigpen-v1"},
	}
	stripped := renderPigpenLines(t, lines) // strip-self signing input (§14.2)

	digest := sha256.Sum256(stripped)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sigID, err := markl.Build(purposePigpenSelfSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	lines[1].Value = "pigpen-v1@" + sigID
	doc = renderPigpenLines(t, lines)

	mux := http.NewServeMux()
	mux.HandleFunc("/papi/pigpen", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/vnd.pigpen")
		_, _ = w.Write(doc)
	})
	mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("# piggy-ids\n" + keyID + "\n"))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, doc
}

func TestRunArgvValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"empty args", []string{}},
		{"resolve with no locator", []string{"resolve"}},
		{"resolve with extra arg", []string{"resolve", "http://example.com", "extra"}},
		{"wrong verb", []string{"wrong", "http://example.com"}},
		{"locator only, no verb", []string{"http://example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout must be empty on a usage error, got %q", stdout.String())
			}
			if !strings.Contains(strings.ToLower(stderr.String()), "usage") {
				t.Errorf("stderr must contain a usage diagnostic, got %q", stderr.String())
			}
			if strings.HasPrefix(stderr.String(), "pigpen-resolver-papi-http:") {
				t.Errorf("stderr must not carry a self-prefix, got %q", stderr.String())
			}
		})
	}
}

// TestRunClientConstructionFailure covers the papi.NewClient(args[1]) error
// path: a locator that fails to normalize into a base URL at all (distinct
// from a locator that normalizes fine but fails to resolve over HTTP,
// covered by TestRunResolveFailure below).
func TestRunClientConstructionFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", ""}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr must contain the underlying failure reason, got empty stderr")
	}
	if strings.HasPrefix(stderr.String(), "pigpen-resolver-papi-http:") {
		t.Errorf("stderr must not carry a self-prefix, got %q", stderr.String())
	}
}

// TestRunResolveFailure covers inspect.ResolvePigpen's own error path: a
// reachable server that simply doesn't implement /papi/pigpen (404) — the
// simplest, cheapest failure fixture that doesn't require building any
// signed-document bytes. ResolvePigpen's full range of failure classes
// (unsigned, invalid signature, malformed lock, unpublished key, etc.) is
// already exhaustively covered by internal/alfa/inspect/pigpen_test.go; this
// test only needs to prove run() correctly surfaces *a* ResolvePigpen error
// to stderr with exit 1.
func TestRunResolveFailure(t *testing.T) {
	srv := httptest.NewServer(http.NewServeMux()) // no routes registered -> 404 on everything
	t.Cleanup(srv.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", srv.URL}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "404") {
		t.Errorf("stderr must contain the underlying failure reason (HTTP 404), got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), srv.URL) {
		t.Errorf("stderr should embed the locator %q (from ResolvePigpen's own error), got %q", srv.URL, stderr.String())
	}
	if strings.HasPrefix(stderr.String(), "pigpen-resolver-papi-http:") {
		t.Errorf("stderr must not carry a self-prefix, got %q", stderr.String())
	}
}

// TestRunSuccess is the end-to-end happy path: correct argv against a
// fixture serving a genuinely self-signed pigpen document -> exit 0, stdout
// equal to the exact document bytes, stderr empty.
func TestRunSuccess(t *testing.T) {
	srv, doc := newSignedPigpenFixture(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", srv.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr must be empty on success, got %q", stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), doc) {
		t.Errorf("stdout must equal the resolved document bytes exactly:\ngot:  %q\nwant: %q", stdout.Bytes(), doc)
	}
}
