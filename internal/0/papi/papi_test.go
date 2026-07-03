package papi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeBase(t *testing.T) {
	cases := map[string]string{
		"linenisgreat.com":                 "https://linenisgreat.com",
		"api.linenisgreat.com":             "https://api.linenisgreat.com",
		"https://api.linenisgreat.com/":    "https://api.linenisgreat.com",
		"http://localhost:8080/papi":       "http://localhost:8080",
		"https://example.test:443/x/y?z=1": "https://example.test:443",
	}
	for in, want := range cases {
		got, err := normalizeBase(in)
		if err != nil {
			t.Errorf("normalizeBase(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeBase(%q) = %q, want %q", in, got, want)
		}
	}

	if _, err := normalizeBase("   "); err == nil {
		t.Error("normalizeBase(blank): want error, got nil")
	}
}

func TestDecodeDiscoveryEnveloped(t *testing.T) {
	// The reference impl wraps discovery in the {data, meta} envelope.
	body := []byte(`{"data":{"version":"papi/v0","handle":"linenisgreat",
		"resources":{"document":"http://x/papi"},
		"auth":{"scheme":"piggy-challenge-response"}},"meta":{"type":"papi-discovery"}}`)
	d, err := decodeDiscovery(body)
	if err != nil {
		t.Fatalf("decodeDiscovery: %v", err)
	}
	if d.Version != "papi/v0" || d.Handle != "linenisgreat" {
		t.Errorf("version/handle = %q/%q", d.Version, d.Handle)
	}
	if d.Resources["document"] != "http://x/papi" {
		t.Errorf("resources = %v", d.Resources)
	}
	if d.Auth == nil || d.Auth.Scheme != "piggy-challenge-response" {
		t.Errorf("auth = %+v", d.Auth)
	}
}

func TestDecodeDiscoveryBare(t *testing.T) {
	// A spec-literal discovery doc (fields at top level, no envelope).
	body := []byte(`{"version":"papi/v0","handle":"bare","resources":{"document":"https://x/papi"}}`)
	d, err := decodeDiscovery(body)
	if err != nil {
		t.Fatalf("decodeDiscovery: %v", err)
	}
	if d.Handle != "bare" || d.Resources["document"] != "https://x/papi" {
		t.Errorf("decoded = %+v", d)
	}
}

// TestServingDiscoveryPrefersServingHost is the split-host regression for
// amarbel-llc/papi#46: the identity domain hosts a static discovery stub that
// advertises a stale auth.scheme while the canonical serving host advertises the
// current one. ServingDiscovery MUST read the serving host's auth block (it
// implements the auth endpoints), while Discovery still reads the identity stub.
func TestServingDiscoveryPrefersServingHost(t *testing.T) {
	serving := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"papi/v0","handle":"linenisgreat","auth":{"scheme":"piggy-sign-challenge"}}`)
	}))
	defer serving.Close()

	// The identity stub points its resources at the serving host (so the client
	// resolves the serving base there) but advertises the RETIRED scheme.
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"papi/v0","handle":"linenisgreat","resources":{"document":%q},"auth":{"scheme":"piggy-challenge-response"}}`,
			serving.URL+"/papi")
	}))
	defer identity.Close()

	c, err := NewClient(identity.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	sd, _, err := c.ServingDiscovery(ctx)
	if err != nil {
		t.Fatalf("ServingDiscovery: %v", err)
	}
	if sd.Auth == nil || sd.Auth.Scheme != "piggy-sign-challenge" {
		t.Errorf("ServingDiscovery auth.scheme = %+v, want piggy-sign-challenge (serving host is authoritative)", sd.Auth)
	}

	id, _, err := c.Discovery(ctx)
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}
	if id.Auth == nil || id.Auth.Scheme != "piggy-challenge-response" {
		t.Errorf("Discovery auth.scheme = %+v, want the identity stub's piggy-challenge-response", id.Auth)
	}
}

func TestServingBaseFromResources(t *testing.T) {
	cases := []struct {
		res  map[string]string
		want string
	}{
		{map[string]string{"document": "https://api.example.com/papi"}, "https://api.example.com"},
		{map[string]string{"piggy-ids": "https://api.example.com/papi/piggy-ids"}, "https://api.example.com"},
		{map[string]string{"repos": "https://h.example.com/v0/papi/repos"}, "https://h.example.com/v0"},
		{map[string]string{"x": "/papi"}, ""},       // relative URL: no host → no base
		{map[string]string{"y": "https://h/x"}, ""}, // no known suffix
		{map[string]string{}, ""},
	}
	for _, tc := range cases {
		if got := servingBaseFromResources(tc.res); got != tc.want {
			t.Errorf("servingBaseFromResources(%v) = %q, want %q", tc.res, got, tc.want)
		}
	}
}

// TestClientFollowsDiscovery proves the §8.1 split-host fix: the identity host
// only serves /.well-known/papi (and 404s /papi), while a different serving host
// holds the document — the client must follow discovery to reach it.
func TestClientFollowsDiscovery(t *testing.T) {
	servingMux := http.NewServeMux()
	servingMux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"version":"papi/v0","person":{"handle":"split"}},"meta":{"visibility":"public"}}`))
	})
	servingMux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("# ids\npiggy-recipient-v1@pivy_ecdh_p256_pub-aaa\n"))
	})
	serving := httptest.NewServer(servingMux)
	defer serving.Close()

	identityMux := http.NewServeMux()
	identityMux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"papi/v0","handle":"split","resources":{"document":%q,"piggy-ids":%q}}`,
			serving.URL+"/papi", serving.URL+"/papi/piggy-ids")
	})
	// identity host deliberately has no /papi route → 404 if the client fails to
	// follow discovery.
	identity := httptest.NewServer(identityMux)
	defer identity.Close()

	c, err := NewClient(identity.URL)
	if err != nil {
		t.Fatal(err)
	}
	doc, _, _, err := c.Document(context.Background())
	if err != nil {
		t.Fatalf("Document via discovery: %v", err)
	}
	if doc.Person == nil || doc.Person.Handle != "split" {
		t.Errorf("document not fetched from the serving host: %+v", doc)
	}
	body, status, err := c.PiggyIDs(context.Background())
	if err != nil || status != http.StatusOK {
		t.Fatalf("PiggyIDs: %v status %d", err, status)
	}
	if !strings.Contains(string(body), "pivy_ecdh_p256_pub-aaa") {
		t.Errorf("piggy-ids not fetched from the serving host: %q", body)
	}
}

// TestClientFallsBackWithoutDiscovery keeps the same-host / pre-discovery path
// working: no /.well-known/papi → the client hits <base>/papi directly.
func TestClientFallsBackWithoutDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"version":"papi/v0","person":{"handle":"direct"}},"meta":{"visibility":"public"}}`))
	})
	srv := httptest.NewServer(mux) // no /.well-known/papi route → 404 → fallback
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	doc, _, _, err := c.Document(context.Background())
	if err != nil {
		t.Fatalf("fallback Document: %v", err)
	}
	if doc.Person == nil || doc.Person.Handle != "direct" {
		t.Errorf("fallback did not fetch /papi directly: %+v", doc)
	}
}

func TestFilterRecipients(t *testing.T) {
	body := []byte("# papi piggy-ids for tester\n" +
		"# slot-9D encryption recipients\n" +
		"piggy-recipient-v1@pivy_ecdh_p256_pub-aaa  # laptop\n" +
		"piggy-recipient-v1@pivy_ecdh_p256_pub-bbb\n" +
		"# slot-9A ssh auth ids\n" +
		"piggy-piv_auth-v1@pivy_p256_pub-ccc  # yubikey\n" +
		"\n")
	got := FilterRecipients(body)
	want := []string{
		"piggy-recipient-v1@pivy_ecdh_p256_pub-aaa",
		"piggy-recipient-v1@pivy_ecdh_p256_pub-bbb",
	}
	if len(got) != len(want) {
		t.Fatalf("FilterRecipients returned %d line(s), want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}
