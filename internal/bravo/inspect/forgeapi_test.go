package inspect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// forgesServer serves /papi/forges, optionally returning a DIFFERENT body once a
// §5 session is presented — the shape a server takes when api_base_url is published
// only on the gated projection because the API plane's hostname is not for
// anonymous eyes. It also carries the handshake endpoints so the authed retry can
// actually run, and counts handshakes so a test can prove the anonymous path costs
// none.
type forgesServer struct {
	anon       string // JSON array for the anonymous projection
	authed     string // JSON array once a session is presented; "" = same as anon
	handshakes int
}

func (s *forgesServer) start(t *testing.T) *httptest.Server {
	t.Helper()
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
		fmt.Fprintf(w, `{"data":{"challenge_id":"ch1","ebox_b64":%q,"expires_at":9999999999},"meta":{"type":"papi-auth-challenge"}}`, ebox)
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["challenge_id"] != "ch1" || m["nonce"] != mockNonce {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.handshakes++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"session":"sess1","principal":"tester","groups":[],"expires_at":9999999999},"meta":{"type":"papi-auth-session"}}`)
	})
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, r *http.Request) {
		body := s.anon
		if s.authed != "" && r.Header.Get("Authorization") == "PiggySession sess1" {
			body = s.authed
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s,"meta":{"type":"forges"}}`, body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// authedOpts drives the legacy decrypt-challenge scheme, which needs no card — the
// point here is the RETRY happening at all, not which §5 scheme carries it.
func authedOpts() Options {
	return Options{Recipient: mockRecipient, DecryptCmd: "base64 -d"}
}

const (
	gitOnlyForge = `{"id":"forgejo-vanity","kind":"forgejo","base_url":"https://code.example.com"}`
	splitForge   = `{"id":"forgejo-vanity","kind":"forgejo","base_url":"https://code.example.com","api_base_url":"https://api-plane.example.com"}`
	githubForge  = `{"id":"github-primary","kind":"github","base_url":"https://github.com"}`
)

func TestResolveForgeAPIBaseFromAnonymousProjection(t *testing.T) {
	s := &forgesServer{anon: `[` + githubForge + `,` + splitForge + `]`}
	srv := s.start(t)

	got, err := ResolveForgeAPIBase(context.Background(), srv.URL, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://api-plane.example.com" {
		t.Fatalf("got %q, want the declared api_base_url — not base_url", got)
	}
	if s.handshakes != 0 {
		t.Fatalf("anonymous resolution must cost no handshake, ran %d", s.handshakes)
	}
}

// The whole reason the member exists: base_url names the plane you clone from, which
// on a split deployment is NOT the plane you call.
func TestResolveForgeAPIBaseDoesNotFallBackToBaseURL(t *testing.T) {
	s := &forgesServer{anon: `[` + gitOnlyForge + `]`}
	srv := s.start(t)

	_, err := ResolveForgeAPIBase(context.Background(), srv.URL, "", Options{})
	if !errors.Is(err, ErrNoForgeAPIBase) {
		t.Fatalf("err = %v, want ErrNoForgeAPIBase rather than a silent base_url", err)
	}
	// The error should name what was there, so the operator can see what to fix.
	if !strings.Contains(err.Error(), "forgejo-vanity") {
		t.Errorf("error should list the forges it saw, got %v", err)
	}
}

// §1.1 permits publishing the member only on the gated projection. An anonymous miss
// is therefore not conclusive, and the retry is what makes that legal shape usable.
func TestResolveForgeAPIBaseRetriesAuthenticated(t *testing.T) {
	s := &forgesServer{
		anon:   `[` + gitOnlyForge + `]`,
		authed: `[` + splitForge + `]`,
	}
	srv := s.start(t)

	got, err := ResolveForgeAPIBase(context.Background(), srv.URL, "", authedOpts())
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://api-plane.example.com" {
		t.Fatalf("got %q, want the gated api_base_url", got)
	}
	if s.handshakes != 1 {
		t.Fatalf("expected exactly one handshake, got %d", s.handshakes)
	}
}

// Without credentials the same server must fail rather than appear to have no API
// plane for a reason the caller cannot act on.
func TestResolveForgeAPIBaseGatedWithoutCredentials(t *testing.T) {
	s := &forgesServer{anon: `[` + gitOnlyForge + `]`, authed: `[` + splitForge + `]`}
	srv := s.start(t)

	if _, err := ResolveForgeAPIBase(context.Background(), srv.URL, "", Options{}); !errors.Is(err, ErrNoForgeAPIBase) {
		t.Fatalf("err = %v, want ErrNoForgeAPIBase", err)
	}
}

// Guessing between two declared API planes would silently aim mint and revoke at the
// wrong forge, so ambiguity is an error naming the candidates.
func TestResolveForgeAPIBaseAmbiguous(t *testing.T) {
	second := `{"id":"forgejo-other","kind":"forgejo","base_url":"https://other.example.com","api_base_url":"https://api-other.example.com"}`
	s := &forgesServer{anon: `[` + splitForge + `,` + second + `]`}
	srv := s.start(t)

	_, err := ResolveForgeAPIBase(context.Background(), srv.URL, "", Options{})
	if err == nil {
		t.Fatal("two declared API bases must not resolve to a guess")
	}
	for _, want := range []string{"forgejo-vanity", "forgejo-other"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got %v", want, err)
		}
	}

	// Naming one resolves it.
	got, err := ResolveForgeAPIBase(context.Background(), srv.URL, "forgejo-other", Options{})
	if err != nil || got != "https://api-other.example.com" {
		t.Fatalf("--forge selection: got %q, %v", got, err)
	}
}

func TestResolveForgeAPIBaseByID(t *testing.T) {
	s := &forgesServer{anon: `[` + githubForge + `,` + splitForge + `]`}
	srv := s.start(t)
	ctx := context.Background()

	// A named forge with no api_base_url falls back to base_url: §1.1 says absent
	// means the API, if any, is served there, and the caller was explicit.
	got, err := ResolveForgeAPIBase(ctx, srv.URL, "github-primary", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://github.com" {
		t.Fatalf("got %q, want base_url for a named forge declaring no api_base_url", got)
	}

	if _, err := ResolveForgeAPIBase(ctx, srv.URL, "nope", Options{}); err == nil {
		t.Fatal("an unknown forge id must error")
	} else if !strings.Contains(err.Error(), "github-primary") {
		t.Errorf("error should list the available ids, got %v", err)
	}
}
