package inspect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/amarbel-llc/papi/internal/0/papi"
)

// projectionChecks reconciles a domain's projected views of its repository set
// (FDR-0011): the authoritative flattened /papi/repos against the /papi/forges clone
// channels it joins to. It asserts every /papi/repos entry's `forge` resolves to a
// /papi/forges id (no dangling provenance) and every repo is joinable to a clone
// channel (no repo silently unreachable — the papi#50 class of drift). These are
// reported as SHOULD verdicts: the invariants become normative MUSTs only once pinned
// in an RFC-0001 amendment (FDR-0011), so a violation is surfaced here without tripping
// the conformance exit code.
func projectionChecks(ctx context.Context, c *papi.Client) []point {
	const label = "projections: /papi/repos ⟷ /papi/forges (FDR-0011)"

	forgesResp, err := c.Fetch(ctx, "/papi/forges")
	if err != nil {
		return []point{skip(label, "GET /papi/forges failed: "+err.Error())}
	}
	if forgesResp.Status != http.StatusOK {
		return []point{skip(label, fmt.Sprintf("GET /papi/forges returned HTTP %d", forgesResp.Status))}
	}
	forges, err := decodeForgeEntries(forgesResp.Body)
	if err != nil {
		return []point{skip(label, "decode /papi/forges: "+err.Error())}
	}
	repos, _, err := c.Repos(ctx)
	if err != nil {
		return []point{skip(label, "GET /papi/repos failed: "+err.Error())}
	}
	if len(repos) == 0 {
		return []point{skip(label, "no repositories to reconcile")}
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
	return pts
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
