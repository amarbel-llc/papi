package inspect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

const forgePathLabel = "conformance: forge path_includes_identity is truthful (§1.1, Amendment 27)"

// forgePathIdentityChecks checks that each forge's declared clone-path layout
// (§1.1 path_includes_identity) matches what its HTTPS plane serves, probing one
// public repo per forge with the git smart-HTTP discovery request. Only HTTPS is
// probed: it is anonymous and unambiguous, while the SSH plane needs a key and
// local url rewrites can redirect a probe (papi#86). A network failure degrades
// to a skip.
//
//   - Declared false: the identity-free path <base_url>/<name>.git must serve.
//   - Absent or true: if the identity-bearing path does not serve but the
//     identity-free one does, the forge is identity-free without declaring it.
func forgePathIdentityChecks(ctx context.Context, c *papi.Client, repos []papi.Repo) []point {
	resp, err := c.Fetch(ctx, "/papi/forges")
	if err != nil {
		return []point{skip(forgePathLabel, "GET /papi/forges failed: "+err.Error())}
	}
	if resp.Status != http.StatusOK {
		return []point{skip(forgePathLabel, fmt.Sprintf("GET /papi/forges returned HTTP %d", resp.Status))}
	}
	forges, err := decodeForgeEntries(resp.Body)
	if err != nil {
		return []point{skip(forgePathLabel, "decode /papi/forges: "+err.Error())}
	}

	var pts []point
	for _, f := range forges {
		if p, ok := forgePathPoint(ctx, c, f, repos); ok {
			pts = append(pts, p)
		}
	}
	if len(pts) == 0 {
		return []point{skip(forgePathLabel, "no forge has an https base_url, an identity and a public repo to probe")}
	}
	return pts
}

// forgePathPoint probes one forge. ok is false when the forge cannot be probed
// (no https base_url, no identity, or no public repo on it).
func forgePathPoint(ctx context.Context, c *papi.Client, f forgeEntry, repos []papi.Repo) (point, bool) {
	base, err := url.Parse(f.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || f.Identity == "" {
		return point{}, false
	}
	name := ""
	for _, r := range repos {
		if r.Forge == f.ID && r.Name != "" {
			name = r.Name
			break
		}
	}
	if name == "" {
		return point{}, false
	}
	root := strings.TrimSuffix(f.BaseURL, "/")
	identityFree := root + "/" + name + ".git"
	identityBearing := root + "/" + f.Identity + "/" + name + ".git"
	label := fmt.Sprintf("%s: forge %q", forgePathLabel, f.ID)

	declaredFree := f.PathIncludesIdentity != nil && !*f.PathIncludesIdentity
	if declaredFree {
		served, reason := gitHTTPServes(ctx, c, identityFree)
		switch {
		case reason != "":
			return skip(label, reason), true
		case !served:
			return shouldFail(label+": declares path_includes_identity:false but the identity-free path does not serve",
				map[string]any{"probed": identityFree}), true
		}
		return ok(fmt.Sprintf("%s: identity-free path %s serves", label, identityFree)), true
	}

	served, reason := gitHTTPServes(ctx, c, identityBearing)
	switch {
	case reason != "":
		return skip(label, reason), true
	case served:
		return ok(fmt.Sprintf("%s: identity-bearing path %s serves", label, identityBearing)), true
	}
	freeServed, freeReason := gitHTTPServes(ctx, c, identityFree)
	switch {
	case freeReason != "":
		return skip(label, freeReason), true
	case freeServed:
		return shouldFail(label+": serves identity-free paths but does not declare path_includes_identity:false",
			map[string]any{"identity_bearing": identityBearing, "identity_free": identityFree}), true
	}
	return skip(label, "neither clone path serves over HTTPS for "+name+"; cannot tell the layout"), true
}

// gitHTTPServes reports whether repoURL answers the git smart-HTTP discovery
// request (what `git ls-remote` sends first) with HTTP 200. A non-empty reason
// means the probe could not be made.
func gitHTTPServes(ctx context.Context, c *papi.Client, repoURL string) (served bool, reason string) {
	status, _, skipReason := fetchExternalURL(ctx, c, repoURL+"/info/refs?service=git-upload-pack")
	if skipReason != "" {
		return false, skipReason
	}
	return status == http.StatusOK, ""
}
