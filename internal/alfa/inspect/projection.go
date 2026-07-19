package inspect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"code.linenisgreat.com/papi/internal/0/papi"
)

// projectionChecks reconciles a domain's projected views of its repository set.
// Three independent concerns share a single /papi/repos fetch: the FDR-0011
// dangling-provenance / clone-channel check, the Amendment 22 canonical-marker
// invariant, and the Amendment 24 flake_url fetchability check. Each concern
// handles its own early-exit; all three are merged at the end.
func projectionChecks(ctx context.Context, c *papi.Client) []point {
	repos, _, err := c.Repos(ctx)
	if err != nil {
		reason := "GET /papi/repos failed: " + err.Error()
		return []point{
			skip("projections: /papi/repos ⟷ /papi/forges (FDR-0011)", reason),
			skip("conformance: /papi/repos canonical marker (§1.1, Amendment 22)", reason),
			skip("conformance: /papi/repos flake_url fetchability (Amendment 24)", reason),
		}
	}
	fdrPts := fdr0011Points(ctx, c, repos)
	canonicalPts := repoCanonicalChecks(repos)
	flakePts := flakeURLChecks(ctx, c, repos)
	return append(append(fdrPts, canonicalPts...), flakePts...)
}

// fdr0011Points checks that every /papi/repos entry's forge resolves to a
// /papi/forges id and that every entry joins a clone channel (FDR-0011). Returns
// a single skip when repos is empty or forges cannot be fetched.
func fdr0011Points(ctx context.Context, c *papi.Client, repos []papi.Repo) []point {
	const label = "projections: /papi/repos ⟷ /papi/forges (FDR-0011)"

	if len(repos) == 0 {
		return []point{skip(label, "no repositories to reconcile")}
	}

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

// flakeURLChecks validates the Amendment 24 flake_url fetchability contract on
// canonical /papi/repos entries (canonical:true, or single-entry by bare name).
// A declared flake_url MUST return HTTP 200 anonymously; it SHOULD also return a
// Link rel="immutable" header whose target is itself anonymously fetchable. This
// check makes outbound HTTP requests; on network failure it degrades to a skip.
func flakeURLChecks(ctx context.Context, c *papi.Client, repos []papi.Repo) []point {
	entries := canonicalRepoEntries(repos)
	var pts []point
	for _, r := range entries {
		if r.FlakeURL == "" {
			continue
		}
		pts = append(pts, checkFlakeURL(ctx, c, r)...)
	}
	if len(pts) == 0 {
		return []point{skip("conformance: /papi/repos flake_url fetchability (Amendment 24)", "no canonical entries declare flake_url")}
	}
	return pts
}

// canonicalRepoEntries returns the repos that should carry flake_url: entries
// with canonical:true, plus all entries for repos that appear only once by bare
// name (single-entry repos are implicitly canonical per Amendment 22). The
// bare-name grouping mirrors repoCanonicalChecks in check.go — keep them in sync.
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

	status, linkHeaders, skipReason := fetchExternalURL(ctx, c, r.FlakeURL)
	if skipReason != "" {
		return []point{skip(label, skipReason)}
	}
	if status != http.StatusOK {
		return []point{mustFail(
			label+": MUST be anonymously fetchable (HTTP 200)",
			map[string]any{"flake_url": r.FlakeURL, "status": status},
		)}
	}

	pts := []point{ok(label + ": anonymously fetchable (HTTP 200)")}

	immURL := parseLinkImmutable(linkHeaders)
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
	status, _, skipReason := fetchExternalURL(ctx, c, immURL)
	if skipReason != "" {
		return skip(label+": Link immutable target fetchable", skipReason)
	}
	if status != http.StatusOK {
		return shouldFail(
			label+": Link immutable target SHOULD be anonymously fetchable (HTTP 200)",
			map[string]any{"immutable": immURL, "status": status},
		)
	}
	return ok(fmt.Sprintf("%s: Link immutable target %q fetchable (HTTP 200)", label, immURL))
}

// fetchExternalURL GETs an arbitrary URL using the papi client's HTTP transport,
// drains the body (to release the connection), and returns the status code and
// Link response headers. On an invalid URL or network error, returns a non-empty
// skipReason for the caller to emit a skip point instead of a verdict.
func fetchExternalURL(ctx context.Context, c *papi.Client, rawURL string) (status int, linkHeaders []string, skipReason string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, "invalid URL: " + err.Error()
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, "network unavailable: " + err.Error()
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header["Link"], ""
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
			if strings.Contains(rest, `rel="immutable"`) {
				return target
			}
			// Unquoted form: rel=immutable must not be followed by more word characters
			// (e.g. rel=immutable-archive must not match).
			if idx := strings.Index(rest, "rel=immutable"); idx >= 0 {
				after := rest[idx+len("rel=immutable"):]
				if after == "" || after[0] == ';' || after[0] == ' ' || after[0] == '\t' {
					return target
				}
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
