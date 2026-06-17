package papi

import "testing"

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
