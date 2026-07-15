package inspect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/amarbel-llc/papi/internal/0/papi"
)

// projectionChecks reconciles a domain's projected views of its repository set
// (FDR-0011) and validates the RFC-0001 Amendment 22 canonical-marker invariant.
// The FDR-0011 assertions (dangling provenance, unreachable clone channel) are SHOULD
// verdicts pending an RFC amendment. The canonical-marker check is a MUST. Both share
// the repos fetch so /papi/repos is only called once per validate run.
func projectionChecks(ctx context.Context, c *papi.Client) []point {
	const label = "projections: /papi/repos ⟷ /papi/forges (FDR-0011)"

	repos, _, err := c.Repos(ctx)
	if err != nil {
		return []point{
			skip(label, "GET /papi/repos failed: "+err.Error()),
			skip("conformance: /papi/repos canonical marker (§1.1, Amendment 22)", "GET /papi/repos failed: "+err.Error()),
		}
	}

	canonicalPts := repoCanonicalChecks(repos)

	if len(repos) == 0 {
		return append([]point{skip(label, "no repositories to reconcile")}, canonicalPts...)
	}

	forgesResp, err := c.Fetch(ctx, "/papi/forges")
	if err != nil {
		return append([]point{skip(label, "GET /papi/forges failed: "+err.Error())}, canonicalPts...)
	}
	if forgesResp.Status != http.StatusOK {
		return append([]point{skip(label, fmt.Sprintf("GET /papi/forges returned HTTP %d", forgesResp.Status))}, canonicalPts...)
	}
	forges, err := decodeForgeEntries(forgesResp.Body)
	if err != nil {
		return append([]point{skip(label, "decode /papi/forges: "+err.Error())}, canonicalPts...)
	}

	byID := make(map[string]forgeEntry, len(forges))
	for _, f := range forges {
		byID[f.ID] = f
	}

	var dangling, unreachable []string
	for _, r := range repos {
		key := r.Owner + "/" + r.Name
		if r.Forge != "" {
			if _, ok := byID[r.Forge]; !ok {
				dangling = append(dangling, fmt.Sprintf("%s → forge %q", key, r.Forge))
			}
		}
		if !cloneChannelReachable(r, byID) {
			unreachable = append(unreachable, key)
		}
	}

	var pts []point
	if len(dangling) > 0 {
		pts = append(pts, shouldFail("projections: every /papi/repos.forge resolves to a /papi/forges id (FDR-0011)",
			map[string]any{"dangling": dangling}))
	} else {
		pts = append(pts, ok(fmt.Sprintf("projections: all %d /papi/repos entries resolve their forge to a /papi/forges id (FDR-0011)", len(repos))))
	}
	if len(unreachable) > 0 {
		pts = append(pts, shouldFail("projections: every /papi/repos entry joins a clone channel (FDR-0011, papi#50)",
			map[string]any{"unreachable": unreachable}))
	} else {
		pts = append(pts, ok("projections: every /papi/repos entry joins a clone channel (FDR-0011, papi#50)"))
	}
	return append(pts, canonicalPts...)
}

// cloneChannelReachable reports whether a flattened repo can be joined to a git clone
// url: its forge's ssh_clone or base_url host, else the repo's own url host. A repo
// with no reachable channel is one `papi repos --url` would silently omit (papi#50).
func cloneChannelReachable(r papi.Repo, byID map[string]forgeEntry) bool {
	if f, ok := byID[r.Forge]; ok {
		if f.SSHClone != "" {
			return true
		}
		if u, err := url.Parse(f.BaseURL); err == nil && u.Host != "" {
			return true
		}
	}
	if u, err := url.Parse(r.URL); err == nil && u.Host != "" {
		return true
	}
	return false
}
