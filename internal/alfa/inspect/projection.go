package inspect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/amarbel-llc/papi/internal/0/papi"
)

// projectionChecks reconciles a domain's projected views of its repository set
// (FDR-0011) and validates the RFC-0001 Amendment 22 canonical-marker invariant
// and the Amendment 24 flake_url fetchability check. The FDR-0011 assertions
// (dangling provenance, unreachable clone channel) are SHOULD verdicts pending an
// RFC amendment. The canonical-marker check is a MUST. All checks share the repos
// fetch so /papi/repos is only called once per validate run.
func projectionChecks(ctx context.Context, c *papi.Client) []point {
	const label = "projections: /papi/repos ⟷ /papi/forges (FDR-0011)"

	repos, _, err := c.Repos(ctx)
	if err != nil {
		return []point{
			skip(label, "GET /papi/repos failed: "+err.Error()),
			skip("conformance: /papi/repos canonical marker (§1.1, Amendment 22)", "GET /papi/repos failed: "+err.Error()),
			skip("conformance: /papi/repos flake_url fetchability (Amendment 24)", "GET /papi/repos failed: "+err.Error()),
		}
	}

	canonicalPts := repoCanonicalChecks(repos)
	flakePts := flakeURLChecks(ctx, c, repos)

	if len(repos) == 0 {
		return append(append([]point{skip(label, "no repositories to reconcile")}, canonicalPts...), flakePts...)
	}

	forgesResp, err := c.Fetch(ctx, "/papi/forges")
	if err != nil {
		return append(append([]point{skip(label, "GET /papi/forges failed: "+err.Error())}, canonicalPts...), flakePts...)
	}
	if forgesResp.Status != http.StatusOK {
		return append(append([]point{skip(label, fmt.Sprintf("GET /papi/forges returned HTTP %d", forgesResp.Status))}, canonicalPts...), flakePts...)
	}
	forges, err := decodeForgeEntries(forgesResp.Body)
	if err != nil {
		return append(append([]point{skip(label, "decode /papi/forges: "+err.Error())}, canonicalPts...), flakePts...)
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
	return append(append(pts, canonicalPts...), flakePts...)
}

// flakeURLChecks validates the Amendment 24 flake_url fetchability contract on
// canonical /papi/repos entries (canonical:true, or single-entry by bare name).
// A declared flake_url MUST return HTTP 200 anonymously; it SHOULD also return a
// Link rel="immutable" header whose target is itself anonymously fetchable. This
// check makes outbound HTTP requests; on network failure it degrades to a skip.
func flakeURLChecks(ctx context.Context, c *papi.Client, repos []papi.Repo) []point {
	const skipLabel = "conformance: /papi/repos flake_url fetchability (Amendment 24)"

	entries := canonicalRepoEntries(repos)
	var pts []point
	for _, r := range entries {
		if r.FlakeURL == "" {
			continue
		}
		pts = append(pts, checkFlakeURL(ctx, c, r)...)
	}
	if len(pts) == 0 {
		return []point{skip(skipLabel, "no canonical entries declare flake_url")}
	}
	return pts
}

// canonicalRepoEntries returns the repos that should carry flake_url: entries
// with canonical:true, plus all entries for repos that appear only once by bare
// name (single-entry repos are implicitly canonical per Amendment 22).
func canonicalRepoEntries(repos []papi.Repo) []papi.Repo {
	nameCount := make(map[string]int, len(repos))
	for _, r := range repos {
		nameCount[r.Name]++
	}
	out := make([]papi.Repo, 0, len(repos))
	for _, r := range repos {
		if nameCount[r.Name] == 1 || r.Canonical {
			out = append(out, r)
		}
	}
	return out
}

// checkFlakeURL validates one flake_url entry: HTTP 200 (MUST), Link
// rel="immutable" (SHOULD), and the immutable target's HTTP 200 (SHOULD).
func checkFlakeURL(ctx context.Context, c *papi.Client, r papi.Repo) []point {
	label := fmt.Sprintf("conformance: %s flake_url %q (Amendment 24)", r.Name, r.FlakeURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.FlakeURL, nil)
	if err != nil {
		return []point{skip(label, "invalid URL: "+err.Error())}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return []point{skip(label, "network unavailable: "+err.Error())}
	}
	// Drain enough to release the connection; we only need status and headers.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []point{mustFail(
			label+": MUST be anonymously fetchable (HTTP 200)",
			map[string]any{"flake_url": r.FlakeURL, "status": resp.StatusCode},
		)}
	}

	pts := []point{ok(label + ": anonymously fetchable (HTTP 200)")}

	immURL := parseLinkImmutable(resp.Header["Link"])
	if immURL == "" {
		pts = append(pts, shouldFail(
			label+`: SHOULD carry Link rel="immutable" header`,
			map[string]any{"flake_url": r.FlakeURL},
		))
		return pts
	}
	pts = append(pts, ok(fmt.Sprintf("%s: carries Link rel=%q → %q", label, "immutable", immURL)))

	pts = append(pts, checkImmutableTarget(ctx, c, label, immURL))
	return pts
}

// checkImmutableTarget verifies that the Link rel="immutable" target URL is
// itself anonymously fetchable (HTTP 200). A SHOULD verdict — the immutable
// pin is optional but when present the fixed-revision archive must exist.
func checkImmutableTarget(ctx context.Context, c *papi.Client, label, immURL string) point {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, immURL, nil)
	if err != nil {
		return skip(label+": Link immutable target fetchable", "invalid URL: "+err.Error())
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return skip(label+": Link immutable target fetchable", "network unavailable: "+err.Error())
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return shouldFail(
			label+": Link immutable target SHOULD be anonymously fetchable (HTTP 200)",
			map[string]any{"immutable": immURL, "status": resp.StatusCode},
		)
	}
	return ok(fmt.Sprintf("%s: Link immutable target %q fetchable (HTTP 200)", label, immURL))
}

// parseLinkImmutable extracts the first target URL from Link header values
// where rel contains "immutable". Handles both `rel="immutable"` and
// `rel=immutable`. Returns "" when no such link is present.
func parseLinkImmutable(linkHeaders []string) string {
	for _, h := range linkHeaders {
		for _, entry := range strings.Split(h, ",") {
			entry = strings.TrimSpace(entry)
			end := strings.Index(entry, ">")
			if !strings.HasPrefix(entry, "<") || end < 0 {
				continue
			}
			target := entry[1:end]
			rest := strings.ToLower(entry[end+1:])
			if strings.Contains(rest, `rel="immutable"`) || strings.Contains(rest, "rel=immutable") {
				return target
			}
		}
	}
	return ""
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
