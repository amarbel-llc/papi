package forgetoken

import "testing"

// This package's normalizeBase is a second implementation of the one in
// internal/alfa/papi (papi#77) — it exists only because that one is unexported and
// a tier up, out of reach of a tier-0 leaf. The table below is deliberately COPIED
// VERBATIM from internal/alfa/papi's TestNormalizeBase, and that is the whole
// point: it is the evidence that the two agree today, so consolidating them onto
// one implementation is provably behaviour-preserving rather than merely plausible.
//
// If this test and its twin ever disagree, do not "fix" one to match the other
// without deciding which behaviour is correct — a divergence here means `papi
// validate <target>` and `papi forge token --host <target>` have been resolving the
// same string to different servers.
//
// Only the ERROR TEXT differs between the two, deliberately: this copy says "forge
// host", which is what the flag is called. Consolidation should keep a caller-supplied
// noun rather than flattening both to one message.
func TestNormalizeBaseAgreesWithTheClientNormalizer(t *testing.T) {
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

// The cases the twin does NOT cover, pinned here because they are the ones a
// consolidation is most likely to change silently: a scheme-less host:port (the
// shape `--host` actually receives is bare, so this is the common path), and a
// target that parses but carries no host.
func TestNormalizeBaseEdges(t *testing.T) {
	got, err := normalizeBase("forge.example.com:2222")
	if err != nil {
		t.Fatalf("scheme-less host:port: %v", err)
	}
	// Note: url.Parse reads "forge.example.com:2222" as scheme "forge.example.com"
	// when it is NOT prefixed — the "://" guard is what stops that, so this asserts
	// the guard, not just the happy path.
	if got != "https://forge.example.com:2222" {
		t.Errorf("normalizeBase(host:port) = %q", got)
	}
	if _, err := normalizeBase("https:///nohost"); err == nil {
		t.Error("a target with no host must error")
	}
}
