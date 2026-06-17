package inspect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/papi"
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
