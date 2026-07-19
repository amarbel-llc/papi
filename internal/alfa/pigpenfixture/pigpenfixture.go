//go:build !wasip1 && !(js && wasm)

// Package pigpenfixture builds a genuinely self-signed RFC-0001 §14.2 pigpen
// document plus a matching /papi/piggy-ids publication, for tests that need
// to exercise a pigpen resolver end-to-end without duplicating the
// ECDSA/hyphence signing recipe. It exists to de-duplicate what was
// previously TWO byte-for-byte-identical copies of this fixture: one in
// cmd/pigpen-resolver-papi-http/main_test.go (Task C3) and one in the root
// main_test.go (Task C4, papi#54). Both are `package main` binaries, so a
// shared helper must live in a regular (non-_test.go) file somewhere either
// package can import — hence this package.
//
// internal/alfa/inspect/pigpen_test.go has its OWN, necessarily separate
// fixture (buildPigpenDoc et al.): it reuses that package's unexported
// crypto-critical core (pigpenStripSelfBytes, verifyPigpenSelfSignature)
// directly, which this package — sitting outside inspect — cannot do. That
// duplication is genuinely constrained by package boundaries and is left
// as-is; this package only removes the OTHER, unconstrained duplication
// between the two `package main` test suites.
//
// Same wasm-isolation note as internal/alfa/inspect/pigpen.go: hyphence
// pulls in purse-first/libs/dewey transitively, which has no wasip1/js-wasm
// implementation, so this package must stay out of both wasm builds too.
// In practice it's only ever imported from _test.go files in package main
// (never from production code reachable by cmd/papi-verify-wasm or
// cmd/papi-client-wasm), so this tag is a defensive backstop rather than a
// load-bearing constraint today.
package pigpenfixture

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

	"code.linenisgreat.com/hyphence/go/hyphence"
	"github.com/amarbel-llc/papi/internal/0/markl"
)

// SelfSigPurpose and SelfSigFormat mirror internal/alfa/inspect's unexported
// self-signature scheme (RFC-0001 §14.2, papi#54): an ordinary
// papi-pigpen-self-sig-v1@ecdsa_p256_sig markl-id placed as its own bare `-`
// line, verified against piggy's real recipient-set parser (which tolerates
// an unrecognized-purpose `-` line by design — linenisgreat/hyphence#6).
// Exported here since this package IS the shared fixture; if inspect's
// constants are ever renamed, a fixture built with these will simply stop
// verifying against a real resolver (fail loud, not silently pass).
const (
	SelfSigPurpose = markl.PurposePigpenSelfSig
	SelfSigFormat  = markl.FormatEcdsaP256Sig
)

// RenderLines canonicalizes and serializes lines into hyphence document
// bytes via FormatBodyEmitter — the same encode path a resolver's own parse
// step expects.
func RenderLines(t testing.TB, lines []hyphence.MetadataLine) []byte {
	t.Helper()
	doc := &hyphence.Document{Metadata: append([]hyphence.MetadataLine(nil), lines...)}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// NewServer starts an httptest.Server serving a genuinely self-signed
// /papi/pigpen document (RFC-0001 §14.2) plus the matching /papi/piggy-ids
// publication, and returns the server and the exact document bytes a
// successful resolve should return/print unmodified (verify-then-passthrough
// — the same bytes the resolver's own fetch received). The server is closed
// automatically via t.Cleanup.
func NewServer(t testing.TB) (srv *httptest.Server, doc []byte) {
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
	stripped := RenderLines(t, lines) // strip-self signing input (§14.2)

	digest := sha256.Sum256(stripped)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sigID, err := markl.Build(SelfSigPurpose, SelfSigFormat, raw)
	if err != nil {
		t.Fatal(err)
	}
	doc = RenderLines(t, []hyphence.MetadataLine{
		lines[0],
		{Prefix: '-', Value: sigID},
		lines[1],
	})

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
