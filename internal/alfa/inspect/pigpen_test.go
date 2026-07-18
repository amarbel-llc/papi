//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		{Prefix: '!', Value: "pigpen-v1@papi_pigpen_self_sig_ecdsa_p256_v1-<blech32>"},
	}
	lock, ok := extractPigpenTypeLock(lines)
	if !ok {
		t.Fatal("want a lock on the type line, got none")
	}
	if lock != "papi_pigpen_self_sig_ecdsa_p256_v1-<blech32>" {
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
// resulting bare pigpenSelfSigFormat lock on the `!` line. corrupt flips a
// signature byte after signing, producing a well-formed but invalid lock.
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
	sigID, err := markl.Build("", pigpenSelfSigFormat, raw)
	if err != nil {
		t.Fatal(err)
	}
	lines[1].Value = "pigpen-v1@" + sigID
	return renderPigpenDoc(t, lines)
}

// newPigpenFixtureServer builds a test server serving data at /papi/pigpen
// (or a 404 when notFound) and, when authIDs is non-nil, those ids at
// /papi/piggy-ids. Shared by pigpenPointsFor (pigpenSignaturePoints, the
// `papi validate` check) and pigpenResolveFor (ResolvePigpen, the resolver,
// papi#54 Task C2) so both exercise the identical fixture shape.
func newPigpenFixtureServer(t *testing.T, data []byte, notFound bool, authIDs []string) *httptest.Server {
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
	return srv
}

// pigpenPointsFor runs pigpenSignaturePoints against a fixture server built
// by newPigpenFixtureServer.
func pigpenPointsFor(t *testing.T, data []byte, notFound bool, authIDs []string) []point {
	t.Helper()
	srv := newPigpenFixtureServer(t, data, notFound, authIDs)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return pigpenSignaturePoints(context.Background(), c)
}

// pigpenResolveFor runs ResolvePigpen against a fixture server built by
// newPigpenFixtureServer — the resolver-side counterpart to pigpenPointsFor
// (papi#54 Task C2).
func pigpenResolveFor(t *testing.T, data []byte, notFound bool, authIDs []string) ([]byte, error) {
	t.Helper()
	srv := newPigpenFixtureServer(t, data, notFound, authIDs)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return ResolvePigpen(context.Background(), c)
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

// --- ResolvePigpen (§14.2, papi#54 Task C2) ---
//
// Mirrors TestPigpenSignatureVerification's structure (same fixtures via
// pigpenResolveFor/newPigpenFixtureServer), but asserts on (bytes, error)
// instead of a validator point. Two outcomes the validator treats as a
// graceful skip are hard errors here: the resolver has no skip concept.
func TestResolvePigpen(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, true, false)
		got, err := pigpenResolveFor(t, doc, false, []string{s.keyID})
		if err != nil {
			t.Fatalf("ResolvePigpen on a validly-signed doc: unexpected error: %v", err)
		}
		// Pins passthrough, not just verification success: the returned
		// bytes must be the ORIGINAL fetched bytes, not a re-encode.
		if !bytes.Equal(got, doc) {
			t.Fatalf("ResolvePigpen must return the original fetched bytes unmodified:\ngot:  %q\nwant: %q", got, doc)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, true, true) // corrupt=true flips a sig byte
		srv := newPigpenFixtureServer(t, doc, false, []string{s.keyID})
		c, cerr := papi.NewClient(srv.URL)
		if cerr != nil {
			t.Fatal(cerr)
		}
		got, err := ResolvePigpen(context.Background(), c)
		if err == nil {
			t.Fatalf("ResolvePigpen on a tampered signature must fail, got bytes: %q", got)
		}
		if !errors.Is(err, errPigpenSigInvalid) {
			t.Errorf("want errors.Is(err, errPigpenSigInvalid), got: %v", err)
		}
		// Pins the non-doubled message format: ResolvePigpen's own
		// "pigpen: resolve <locator>/papi/pigpen: ..." prefix must appear
		// exactly once — errPigpen* sentinels must not carry their own
		// leading "pigpen: " (that duplicated when wrapped here, and again
		// when piggy wraps ResolvePigpen's stderr with its own
		// kind="papi-http"/locator="..." context).
		want := "pigpen: resolve " + c.BaseURL + "/papi/pigpen: signature invalid"
		if err.Error() != want {
			t.Errorf("unexpected error message:\ngot:  %q\nwant: %q", err.Error(), want)
		}
	})

	t.Run("unpublished key", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, true, false)
		// The signing key is never advertised on /papi/piggy-ids.
		got, err := pigpenResolveFor(t, doc, false, []string{})
		if err == nil {
			t.Fatalf("ResolvePigpen with an unpublished signing key must fail, got bytes: %q", got)
		}
		if !errors.Is(err, errPigpenKeyNotPublished) {
			t.Errorf("want errors.Is(err, errPigpenKeyNotPublished), got: %v", err)
		}
	})

	t.Run("malformed lock", func(t *testing.T) {
		lines := []hyphence.MetadataLine{{Prefix: '!', Value: "pigpen-v1@not-a-valid-markl-lock"}}
		doc := renderPigpenDoc(t, lines)
		got, err := pigpenResolveFor(t, doc, false, nil)
		if err == nil {
			t.Fatalf("ResolvePigpen on a malformed lock must fail, got bytes: %q", got)
		}
		if !errors.Is(err, errPigpenLockMalformed) {
			t.Errorf("want errors.Is(err, errPigpenLockMalformed), got: %v", err)
		}
	})

	t.Run("404/absent endpoint", func(t *testing.T) {
		got, err := pigpenResolveFor(t, nil, true, nil)
		if err == nil {
			t.Fatalf("ResolvePigpen against a 404 /papi/pigpen must fail (a resolver has no skip concept), got bytes: %q", got)
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("want the error to mention HTTP 404, got: %v", err)
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		s := newPigpenSigner(t)
		doc := buildPigpenDoc(t, s, false, false)
		got, err := pigpenResolveFor(t, doc, false, []string{s.keyID})
		// Unlike the validator (which skips an unsigned document as
		// SHOULD-not-MUST), the resolver hard-requires a signature.
		if err == nil {
			t.Fatalf("ResolvePigpen on an unsigned doc must fail (resolver policy, unlike the validator's skip), got bytes: %q", got)
		}
		if !errors.Is(err, errPigpenUnsigned) {
			t.Errorf("want errors.Is(err, errPigpenUnsigned), got: %v", err)
		}
	})
}

// TestResolvePigpenErrorsEmbedLocator pins that every ResolvePigpen error
// embeds the origin's locator (c.BaseURL), so a bare human-run invocation of
// the resolver binary is self-sufficient without piggy's own
// kind="papi-http"/locator="..." wrapping context (papi#54 Task C2 design).
func TestResolvePigpenErrorsEmbedLocator(t *testing.T) {
	srv := newPigpenFixtureServer(t, nil, true, nil)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, rerr := ResolvePigpen(context.Background(), c)
	if rerr == nil {
		t.Fatal("want an error against a 404 /papi/pigpen")
	}
	if !strings.Contains(rerr.Error(), srv.URL) {
		t.Errorf("error must embed the locator %q, got: %v", srv.URL, rerr)
	}
}

// TestPigpenSignatureVerificationLazyAuthFetch pins that pigpenSignaturePoints
// (via verifyPigpenSelfSignature) never touches /papi/piggy-ids for the three
// outcomes that are decided before a signing key is ever looked up for
// publication: no lock (unsigned), a lock that doesn't parse (malformed), and
// a parseable lock with no auth-key line to check. This is the common,
// §14.2-expected-to-be-fast "document is simply unsigned" path, and it must
// resolve without any network I/O beyond the initial /papi/pigpen fetch. A
// prior version of this refactor fetched piggy-ids unconditionally,
// regressing this — see papi#54.
func TestPigpenSignatureVerificationLazyAuthFetch(t *testing.T) {
	unsignedDoc := buildPigpenDoc(t, newPigpenSigner(t), false, false)

	malformedLockDoc := renderPigpenDoc(t, []hyphence.MetadataLine{
		{Prefix: '!', Value: "pigpen-v1@not-a-valid-markl-lock"},
	})

	wellFormedSig, err := markl.Build("", pigpenSelfSigFormat, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	noAuthKeyDoc := renderPigpenDoc(t, []hyphence.MetadataLine{
		{Prefix: '!', Value: "pigpen-v1@" + wellFormedSig},
	})

	cases := []struct {
		name string
		doc  []byte
	}{
		{"unsigned", unsignedDoc},
		{"malformed lock", malformedLockDoc},
		{"well-formed lock, no auth key", noAuthKeyDoc},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var piggyIDsHits int
			mux := http.NewServeMux()
			mux.HandleFunc("/papi/pigpen", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/vnd.pigpen")
				_, _ = w.Write(tc.doc)
			})
			mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
				piggyIDsHits++
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write([]byte("# piggy-ids\n"))
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			c, err := papi.NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}

			pts := pigpenSignaturePoints(context.Background(), c)
			if len(pts) != 1 || pts[0].reason == "" {
				t.Fatalf("expected a skip verdict for %q, got: %+v", tc.name, pts)
			}
			if piggyIDsHits != 0 {
				t.Fatalf("%q: /papi/piggy-ids fetched %d time(s); want 0 (lazy fetch, only after lock+key found)",
					tc.name, piggyIDsHits)
			}
		})
	}
}

// pigpenConformantServer mirrors conformantServer (inspect_test.go) route for
// route — a domain that already passes every RFC-0001 MUST — and additionally
// publishes s's slot-9A key on /papi/piggy-ids and serves a signed pigpen doc
// at /papi/pigpen, so a Run-level test can assert the pigpen verdict appears
// alongside the rest of `papi validate`'s checklist without tripping any
// unrelated MUST failure.
func pigpenConformantServer(t *testing.T, s pigpenSigner, doc []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"version":"papi/v0","handle":"tester",
			"resources":{"document":%q,"piggy_ids":%q,"ssh_authorized_keys":%q},
			"auth":{"scheme":"piggy-challenge-response"}},"meta":{"type":"papi-discovery","count":3}}`,
			base+"/papi", base+"/papi/piggy-ids", base+"/papi/ssh-authorized-keys")
	})
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"version":"papi/v0",
			"person":{"handle":"tester","name":"Test User"},
			"piggy":{"encryption_recipients":[{"id":"r1"}],"ssh_authorized_keys":[{"key":"k1"},{"key":"k2"}]},
			"forges":[{"id":"gh","kind":"github","repos":[{},{}]}],
			"sitemap":{"domains":{"visibility":"public"},"visibility":"public"},
			"templates":[{"id":"eng","flakeref":"github:x/y#eng"}],
			"caches":[{"id":"krone","url":"http://krone:8080","trusted_public_keys":["krone:AAAApub"]}]},
			"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`)
	})
	mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "# piggy-ids\npiggy-recipient-v1@pivy_ecdh_p256_pub-aaa\n"+s.keyID+"\n")
	})
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ecdsa-sha2-nistp256 AAAAfake tester\n")
	})
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if v, _ := m["recipient"].(string); v != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("/papi/pigpen", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/vnd.pigpen")
		_, _ = w.Write(doc)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// --- SignPigpen (§14.2, papi#54 Task D1) ---

// pigpenTestSigner adapts a pigpenSigner test fixture's private key to the
// PigpenSigner interface, doing REAL ECDSA signing exactly like a production
// PiggySignBytesSigner would: msg is the bare preimage, hashed SHA-256
// internally before signing (see PigpenSigner's doc comment and
// enroll.PiggySignBytesSigner.SignSlot9A's).
type pigpenTestSigner struct {
	priv *ecdsa.PrivateKey
}

func (s pigpenTestSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
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

// erroringPigpenSigner is a PigpenSigner whose SignSlot9A always fails,
// pinning that SignPigpen propagates a signer error rather than swallowing
// or wrapping it unrecognizably.
type erroringPigpenSigner struct{ err error }

func (s erroringPigpenSigner) SignSlot9A(context.Context, string, []byte) ([]byte, error) {
	return nil, s.err
}

func TestSignPigpen(t *testing.T) {
	t.Run("round-trip", func(t *testing.T) {
		s := newPigpenSigner(t)
		unsigned := buildPigpenDoc(t, s, false, false)

		signed, err := SignPigpen(context.Background(), pigpenTestSigner{priv: s.priv}, "test-guid", unsigned)
		if err != nil {
			t.Fatalf("SignPigpen: %v", err)
		}

		// The proof: run the signed output through the EXISTING verification
		// path (pigpenSignaturePoints -> verifyPigpenSelfSignature), not a
		// second, parallel verification path written just for this test.
		pts := pigpenPointsFor(t, signed, false, []string{s.keyID})
		if len(pts) != 1 || !pts[0].ok || pts[0].reason != "" {
			t.Fatalf("SignPigpen output failed EXISTING verification (pigpenSignaturePoints): %+v", pts)
		}
	})

	t.Run("already signed is rejected", func(t *testing.T) {
		s := newPigpenSigner(t)
		signed := buildPigpenDoc(t, s, true, false)

		_, err := SignPigpen(context.Background(), pigpenTestSigner{priv: s.priv}, "test-guid", signed)
		if err == nil {
			t.Fatal("SignPigpen on an already-signed document must fail, not silently clobber the existing lock")
		}
		if !errors.Is(err, errPigpenAlreadySigned) {
			t.Errorf("want errors.Is(err, errPigpenAlreadySigned), got: %v", err)
		}
	})

	t.Run("no auth-key line is rejected", func(t *testing.T) {
		lines := []hyphence.MetadataLine{{Prefix: '!', Value: "pigpen-v1"}}
		doc := renderPigpenDoc(t, lines)

		s := newPigpenSigner(t)
		_, err := SignPigpen(context.Background(), pigpenTestSigner{priv: s.priv}, "test-guid", doc)
		if err == nil {
			t.Fatal("SignPigpen on a document with no auth-key line must fail (nothing for a verifier to check against)")
		}
		if !errors.Is(err, errPigpenNoAuthKey) {
			t.Errorf("want errors.Is(err, errPigpenNoAuthKey), got: %v", err)
		}
	})

	t.Run("signer failure propagates", func(t *testing.T) {
		s := newPigpenSigner(t)
		unsigned := buildPigpenDoc(t, s, false, false)

		wantErr := errors.New("piv card removed")
		_, err := SignPigpen(context.Background(), erroringPigpenSigner{err: wantErr}, "test-guid", unsigned)
		if err == nil {
			t.Fatal("SignPigpen must propagate a signer error")
		}
		if !errors.Is(err, wantErr) {
			t.Errorf("want errors.Is(err, wantErr), got: %v", err)
		}
	})

	// errPigpenNoTypeLine pins a genuinely reachable (not merely defensive)
	// case: a document with a well-formed auth-key `-` line but NO `!` line
	// anywhere at all — malformed/truncated input distinct from "unsigned"
	// (a bare `! pigpen-v1` line, which is what "no auth-key line is
	// rejected" above and extractPigpenTypeLock's hasLock==false actually
	// cover). findPigpenAuthKey succeeding says nothing about whether a `!`
	// line exists elsewhere in the document, so SignPigpen must check for
	// this independently.
	t.Run("no type line at all is rejected", func(t *testing.T) {
		s := newPigpenSigner(t)
		lines := []hyphence.MetadataLine{{Prefix: '-', Value: s.keyID}}
		doc := renderPigpenDoc(t, lines)

		_, err := SignPigpen(context.Background(), pigpenTestSigner{priv: s.priv}, "test-guid", doc)
		if err == nil {
			t.Fatal("SignPigpen on a document with no `!` type line at all must fail")
		}
		if !errors.Is(err, errPigpenNoTypeLine) {
			t.Errorf("want errors.Is(err, errPigpenNoTypeLine), got: %v", err)
		}
	})
}

// TestRunIncludesPigpenCheck (papi#54, Task B4) pins that Run's checklist
// actually calls pigpenSignaturePoints: a conformant domain serving a signed,
// verifiable /papi/pigpen document must surface the pigpen "signed-and-valid"
// verdict in `papi validate`'s ndjson-crap stream, end to end (a real
// httptest.Server, a real HTTP fetch, real ECDSA verification) — not just via
// the pigpenSignaturePoints unit tests above, which never go through Run.
func TestRunIncludesPigpenCheck(t *testing.T) {
	s := newPigpenSigner(t)
	doc := buildPigpenDoc(t, s, true, false)
	srv := pigpenConformantServer(t, s, doc)

	var buf bytes.Buffer
	if err := Run(context.Background(), &buf, srv.URL, Options{}); err != nil {
		t.Fatalf("Run against a pigpen-signed conformant fixture: %v", err)
	}

	var descriptions []string
	for i, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i, err, line)
		}
		if rec["type"] != "test" {
			continue
		}
		if d, ok := rec["description"].(string); ok {
			descriptions = append(descriptions, d)
		}
	}

	joined := strings.Join(descriptions, "\n")
	if !strings.Contains(joined, "pigpen") || !strings.Contains(joined, "signed-and-valid") {
		t.Fatalf("Run's ndjson-crap stream is missing the pigpen signed-and-valid verdict:\n%s", joined)
	}
}
