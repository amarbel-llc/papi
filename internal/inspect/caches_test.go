package inspect

import (
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/papi"
)

func wellFormedCache() papi.Cache {
	return papi.Cache{
		ID:                "krone",
		URL:               "http://krone:8080",
		TrustedPublicKeys: []string{"krone:AAAAbase64ed25519"},
	}
}

func TestVerifyCacheWellFormed(t *testing.T) {
	// An explicit kind="nix-binary-cache" and an empty kind (the §11.1 default)
	// are both recognized.
	for _, kind := range []string{"", cacheKind} {
		ch := wellFormedCache()
		ch.Kind = kind
		p := verifyCache(ch, 0, map[string]bool{})
		if !p.ok || p.reason != "" {
			t.Fatalf("kind=%q: well-formed cache rejected: %+v", kind, p)
		}
	}
}

func TestVerifyCacheSchemaViolationsHardFail(t *testing.T) {
	cases := map[string]papi.Cache{
		"empty id":           {URL: "http://x", TrustedPublicKeys: []string{"k:v"}},
		"empty url":          {ID: "c", TrustedPublicKeys: []string{"k:v"}},
		"no trusted keys":    {ID: "c", URL: "http://x"},
		"blank trusted keys": {ID: "c", URL: "http://x", TrustedPublicKeys: []string{"", ""}},
	}
	for name, ch := range cases {
		p := verifyCache(ch, 0, map[string]bool{})
		if p.ok || p.reason != "" || !p.must {
			t.Errorf("%s: expected a hard MUST fail, got %+v", name, p)
		}
	}
}

func TestVerifyCacheDuplicateIDHardFails(t *testing.T) {
	seen := map[string]bool{}
	ch := wellFormedCache()
	if p := verifyCache(ch, 0, seen); !p.ok {
		t.Fatalf("first entry should be ok: %+v", p)
	}
	p := verifyCache(ch, 1, seen)
	if p.ok || !p.must || !strings.Contains(p.desc, "unique id") {
		t.Fatalf("duplicate id not hard-failed: %+v", p)
	}
}

// TestVerifyCacheUnknownKindSkipped pins §11.1: an entry whose kind the client
// does not understand is skipped (mirroring §7.1), not failed — and it must not
// reserve its id for the uniqueness check, so a later well-formed entry reusing
// that id still passes.
func TestVerifyCacheUnknownKindSkipped(t *testing.T) {
	seen := map[string]bool{}
	exotic := papi.Cache{ID: "krone", Kind: "ipfs-cluster"}
	p := verifyCache(exotic, 0, seen)
	if p.reason == "" || !strings.Contains(p.reason, "unrecognized kind") {
		t.Fatalf("unknown kind not skipped: %+v", p)
	}
	if seen["krone"] {
		t.Error("a skipped entry must not reserve its id")
	}
	if p := verifyCache(wellFormedCache(), 1, seen); !p.ok {
		t.Fatalf("well-formed entry reusing a skipped id should pass: %+v", p)
	}
}

func TestCacheChecksNoCaches(t *testing.T) {
	pts := cacheChecks(&papi.Document{})
	if len(pts) != 1 || pts[0].reason == "" {
		t.Fatalf("empty caches[] should yield a single skip: %+v", pts)
	}
}
