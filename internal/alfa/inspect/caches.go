package inspect

import (
	"fmt"

	"code.linenisgreat.com/papi/internal/0/papi"
)

// cacheKind is the only nix-binary-cache mechanism defined in papi/v0 (§11.1).
const cacheKind = "nix-binary-cache"

// cacheChecks validates the document's advertised nix binary caches against the
// RFC-0001 §11.1 entry schema: each entry's id is non-empty and unique within
// the array, url is non-empty, and trusted_public_keys carries at least one
// non-empty key. An entry whose kind is set but unrecognized is skipped (§11.1,
// mirroring §7.1), not failed. These are the server's own document-structure
// MUSTs — like the §4.2 envelope and §2.6 acl-strip verdicts — so a violation is
// a hard fail that trips the conformance exit code.
func cacheChecks(d *papi.Document) []point {
	if len(d.Caches) == 0 {
		return []point{skip("caches: §11.1 entry schema", "no caches[] advertised")}
	}
	pts := make([]point, 0, len(d.Caches))
	seen := map[string]bool{}
	for i, ch := range d.Caches {
		pts = append(pts, verifyCache(ch, i, seen))
	}
	return pts
}

// verifyCache evaluates one cache entry against the §11.1 schema. An entry with
// an unrecognized kind is skipped before any id/url checks so it neither fails
// the list nor reserves its id for the uniqueness check.
func verifyCache(ch papi.Cache, i int, seen map[string]bool) point {
	if ch.Kind != "" && ch.Kind != cacheKind {
		return skip(fmt.Sprintf("caches: cache[%d] skipped", i),
			fmt.Sprintf("unrecognized kind %q (§11.1)", ch.Kind))
	}

	label := fmt.Sprintf("cache[%d] %q", i, ch.ID)
	switch {
	case ch.ID == "":
		return mustFail(fmt.Sprintf("caches: cache[%d] has a non-empty id (§11.1)", i), nil)
	case seen[ch.ID]:
		return mustFail("caches: "+label+" has a unique id (§11.1)", map[string]any{"id": ch.ID})
	}
	seen[ch.ID] = true

	switch {
	case ch.URL == "":
		return mustFail("caches: "+label+" has a non-empty url (§11.1)", nil)
	case !anyNonEmpty(ch.TrustedPublicKeys):
		return mustFail("caches: "+label+" has ≥1 non-empty trusted_public_keys (§11.1)", nil)
	}
	return ok(fmt.Sprintf("caches: %s well-formed — url %q, %d trusted key(s) (§11.1)",
		label, ch.URL, len(ch.TrustedPublicKeys)))
}

// anyNonEmpty reports whether ss contains at least one non-empty string.
func anyNonEmpty(ss []string) bool {
	for _, s := range ss {
		if s != "" {
			return true
		}
	}
	return false
}
