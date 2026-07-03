package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/signchallenge"
)

const (
	mockRecipient = "piggy-recipient-v1@pivy_ecdh_p256_pub-known"
	mockNonce     = "test-nonce-abc123"
)

// mockBoxServer is a hermetic §5 handshake fixture: challenge mints a one-time
// nonce "encrypted" as base64 (recovered by a `base64 -d` decrypt-cmd), response
// validates it once, and /papi returns a scoped projection (no acl) when the
// minted session is presented, public otherwise.
func mockBoxServer() *httptest.Server {
	consumed := false
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["recipient"] != mockRecipient {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ebox := base64.StdEncoding.EncodeToString([]byte(mockNonce))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"challenge_id":"ch1","ebox_b64":%q,"expires_at":9999999999}`, ebox)
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if consumed || m["challenge_id"] != "ch1" || m["nonce"] != mockNonce {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		consumed = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"session":"sess1","principal":"tester","groups":["authenticated"],"expires_at":9999999999}`)
	})
	mux.HandleFunc("/papi", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"tester","contact":{"email":"x@y"}}},"meta":{"type":"papi","version":"papi/v0","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"tester"}},"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

func descs(pts []point) string {
	var b strings.Builder
	for _, p := range pts {
		b.WriteString(p.desc)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestAuthenticatedHandshake(t *testing.T) {
	srv := mockBoxServer()
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := authenticatedChecks(context.Background(), c, Options{
		Recipient:  mockRecipient,
		DecryptCmd: "base64 -d",
	})
	if hasMustFail(pts) {
		t.Fatalf("conformant mock-box handshake produced a MUST failure:\n%s", descs(pts))
	}
	joined := descs(pts)
	for _, want := range []string{
		"handshake -> session",
		"meta.visibility==scoped",
		"strips acl even under auth",
		"replayed challenge -> 401",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestUnknownSessionResolvesPublic(t *testing.T) {
	srv := mockBoxServer()
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := unknownSessionPoint(context.Background(), c)
	if !p.ok || p.reason != "" {
		t.Fatalf("unknown session not resolved to public: %+v", p)
	}
}

const mockAuthKeyID = "piggy-auth-v1@ecdsa_p256_pub-known"

// fakeSigner signs as a slot-9A card would: SHA-256 over the bare preimage, ECDSA
// P-256, returned as raw r‖s — exactly what `piggy sign-bytes --slot 9a --format
// raw` produces (mirrors signchallenge's own test signer).
type fakeSigner struct{ priv *ecdsa.PrivateKey }

func (f fakeSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, f.priv, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	return rs, nil
}

// mockSignServer is a hermetic §5.2 sign-challenge fixture: discovery advertises
// piggy-sign-challenge, the challenge mints a nonce for a known auth_key_id, the
// response ECDSA-verifies the slot-9A signature over the §5.2 preimage (bound to
// the request host, as the reference verifier does), and /papi returns a scoped
// projection when the minted session is presented. It is the mirror of the live
// linenisgreat.com auth tier the retired decrypt path 400s against.
func mockSignServer(pub *ecdsa.PublicKey) *httptest.Server {
	consumed := false
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No resources[] → the serving base stays the identity base, so the auth
		// POSTs (and thus r.Host) match the domain the client signs.
		io.WriteString(w, `{"version":"papi/v0","auth":{"scheme":"piggy-sign-challenge"}}`)
	})
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["auth_key_id"] != mockAuthKeyID {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"challenge_id":"ch1","nonce":%q,"expires_at":9999999999}`, mockNonce)
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if consumed || m["challenge_id"] != "ch1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := signchallenge.Verify(pub, r.Host, mockNonce, m["signature"]); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		consumed = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"session":"sess1","principal":"tester","expires_at":9999999999}`)
	})
	mux.HandleFunc("/papi", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "PiggySession sess1" {
			io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"tester","contact":{"email":"x@y"}}},"meta":{"type":"papi","version":"papi/v0","visibility":"scoped"}}`)
			return
		}
		io.WriteString(w, `{"data":{"version":"papi/v0","person":{"handle":"tester"}},"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

// TestSignChallengeHandshake is the §5.2 regression for amarbel-llc/papi#46: a
// server advertising piggy-sign-challenge must be answered by signing the nonce
// with slot-9A, not by POSTing a slot-9D recipient (which the live server 400s).
func TestSignChallengeHandshake(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockSignServer(&priv.PublicKey)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := authenticatedChecks(context.Background(), c, Options{
		AuthKeyID: mockAuthKeyID,
		Signer:    fakeSigner{priv},
	})
	if hasMustFail(pts) {
		t.Fatalf("conformant sign-challenge handshake produced a MUST failure:\n%s", descs(pts))
	}
	joined := descs(pts)
	for _, want := range []string{
		"handshake -> session",
		"meta.visibility==scoped",
		"strips acl even under auth",
		"replayed challenge -> 401",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

// TestSignChallengeNoSignerSkips: a sign-challenge server presented with no
// --auth-key-id/signer yields a single skip (wrong-flags), not a MUST failure.
func TestSignChallengeNoSignerSkips(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockSignServer(&priv.PublicKey)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Only decrypt-challenge creds supplied, but the server advertises
	// sign-challenge: resolveScheme honors the advertised scheme → ErrNoSigner skip.
	pts := authenticatedChecks(context.Background(), c, Options{
		Recipient:  mockRecipient,
		DecryptCmd: "base64 -d",
	})
	if len(pts) != 1 || pts[0].reason == "" {
		t.Fatalf("sign-challenge server with no signer should yield a single skip, got:\n%s", descs(pts))
	}
}

func TestAuthUnknownRecipientSkips(t *testing.T) {
	srv := mockBoxServer()
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := authenticatedChecks(context.Background(), c, Options{
		Recipient:  "piggy-recipient-v1@pivy_ecdh_p256_pub-nope",
		DecryptCmd: "cat",
	})
	if len(pts) != 1 || pts[0].reason == "" {
		t.Fatalf("unknown recipient (403) should yield a single skip, got:\n%s", descs(pts))
	}
}
