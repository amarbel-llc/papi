package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

// forgeEntry is the slice of a /papi/forges entry the access asserter reads: its id
// and the OPTIONAL `canary` — the `<owner>/<name>` of a repo the forge publishes
// visibility:"private", named on the PUBLIC forge entry so a card-free checker can
// assert it stays out of the anonymous projection (RFC-0001 §1.1, FDR-0010).
type forgeEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	BaseURL  string `json:"base_url"`
	SSHClone string `json:"ssh_clone"`
	Canary   string `json:"canary"`
}

func decodeForgeEntries(body []byte) ([]forgeEntry, error) {
	data, _, err := papi.DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var forges []forgeEntry
	if err := json.Unmarshal(data, &forges); err != nil {
		return nil, err
	}
	return forges, nil
}

// RunForgeCheck reconciles a domain's DECLARED forge/repo visibility against the
// VERIFIED anonymous /papi projection (papi#48, FDR-0010 option (a)), writing an
// ndjson-crap stream to w. The card-free floor asserts each forge's declared canary
// is absent from the anonymous /papi/repos; with §5 credentials it additionally
// reconciles the full declared set — every declared-public repo anonymously visible,
// every declared-private/scoped repo hidden. forgeID scopes the check to one forge
// entry when non-empty. Deployment/topology (DNS, firewall, nginx) is out of scope —
// that is circus's plane, which delegates the visibility half here. Returns
// ErrNonConformant on a MUST violation.
func RunForgeCheck(ctx context.Context, w io.Writer, target, forgeID string, opts Options) error {
	c, err := papi.NewClient(target)
	if err != nil {
		return err
	}
	rep := crap.NewReporter(w, crap.ReporterOptions{
		Title:  "papi forge check " + c.BaseURL,
		Source: "papi",
	})

	fail := func(desc string, err error) error {
		emit(rep, []point{mustFail(desc, map[string]any{"error": err.Error()})})
		if rep.Err() != nil {
			return rep.Err()
		}
		return err
	}

	anonForges, err := c.Fetch(ctx, "/papi/forges")
	if err != nil {
		return fail("forge: GET /papi/forges (anonymous)", err)
	}
	if anonForges.Status != http.StatusOK {
		return fail("forge: GET /papi/forges (anonymous)", fmt.Errorf("HTTP %d", anonForges.Status))
	}
	forges, err := decodeForgeEntries(anonForges.Body)
	if err != nil {
		return fail("forge: decode anonymous /papi/forges", err)
	}
	anonRepos, _, err := c.Repos(ctx)
	if err != nil {
		return fail("forge: GET /papi/repos (anonymous)", err)
	}

	pts := forgeCanaryPoints(forges, anonRepos, forgeID)
	if opts.authed() {
		pts = append(pts, forgeReconcilePoints(ctx, c, opts, forgeID, anonRepos)...)
	} else {
		pts = append(pts, skip("forge: declared-vs-verified reconciliation (§2.5, §4.2)",
			"anonymous canary floor only; pass --auth-key-id/--recipient to reconcile the full declared set"))
	}

	emit(rep, pts)
	if rep.Err() != nil {
		return rep.Err()
	}
	if anyMustFail(pts) {
		return ErrNonConformant
	}
	return nil
}

// forgeCanaryPoints is the card-free floor: for each anonymously-visible forge with a
// declared canary (optionally filtered to forgeID), the canary repo MUST NOT appear in
// the anonymous /papi/repos — a private-repo leak (RFC-0001 §2.5).
func forgeCanaryPoints(forges []forgeEntry, anonRepos []papi.Repo, forgeID string) []point {
	var pts []point
	checked := 0
	for _, f := range forges {
		if forgeID != "" && f.ID != forgeID {
			continue
		}
		if f.Canary == "" {
			continue
		}
		checked++
		label := fmt.Sprintf("forge %s: declared canary %q", f.ID, f.Canary)
		if repoAnonymouslyVisible(f.Canary, anonRepos) {
			pts = append(pts, mustFail(label+" LEAKED into anonymous /papi/repos (§2.5)",
				map[string]any{"forge": f.ID, "canary": f.Canary}))
		} else {
			pts = append(pts, ok(label+" absent from anonymous /papi/repos (§2.5)"))
		}
	}
	if checked == 0 {
		reason := "no anonymously-visible forge declares a canary member"
		if forgeID != "" {
			reason = fmt.Sprintf("forge %q declares no canary member (or is not anonymously visible)", forgeID)
		}
		pts = append(pts, skip("forge: anonymous canary floor", reason))
	}
	return pts
}

// forgeReconcilePoints is the authenticated tier: fetch the full declared set (authed
// /papi/repos) and assert every declared-public repo is anonymously visible and every
// declared-private/scoped repo is anonymously hidden — the full declared-vs-verified
// projection reconciliation (RFC-0001 §2.5, §4.2). Runs the §5 handshake once.
func forgeReconcilePoints(ctx context.Context, c *papi.Client, opts Options, forgeID string, anonRepos []papi.Repo) []point {
	sess, err := Handshake(ctx, c, opts)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoBoxBackend), errors.Is(err, ErrRecipientUnregistered),
			errors.Is(err, ErrNoDecryptCmd), errors.Is(err, ErrNoSigner):
			return []point{skip("forge: declared-vs-verified reconciliation (§5)", err.Error())}
		default:
			return []point{mustFail("forge: §5 handshake for reconciliation", map[string]any{"error": err.Error()})}
		}
	}
	resp, err := c.FetchAuthed(ctx, "/papi/repos", sess.ID)
	if err != nil {
		return []point{mustFail("forge: GET /papi/repos (authed)", map[string]any{"error": err.Error()})}
	}
	if resp.Status != http.StatusOK {
		return []point{mustFail("forge: GET /papi/repos (authed)", map[string]any{"status": resp.Status})}
	}
	declared, err := papi.DecodeRepos(resp.Body)
	if err != nil {
		return []point{mustFail("forge: decode authed /papi/repos", map[string]any{"error": err.Error()})}
	}

	anon := make(map[string]bool, len(anonRepos))
	for _, r := range anonRepos {
		anon[r.Owner+"/"+r.Name] = true
	}
	var leaked, hidden []string
	for _, r := range declared {
		if forgeID != "" && r.Forge != forgeID {
			continue
		}
		key := r.Owner + "/" + r.Name
		if r.Visibility == "public" || r.Visibility == "" {
			if !anon[key] {
				hidden = append(hidden, key)
			}
		} else if anon[key] {
			leaked = append(leaked, key)
		}
	}

	var pts []point
	if len(leaked) > 0 {
		pts = append(pts, mustFail("forge: declared-private/scoped repo(s) LEAKED into anonymous /papi/repos (§2.5)",
			map[string]any{"repos": leaked}))
	} else {
		pts = append(pts, ok("forge: every declared-private/scoped repo hidden anonymously (§2.5)"))
	}
	if len(hidden) > 0 {
		pts = append(pts, mustFail("forge: declared-public repo(s) NOT anonymously visible (§4.2)",
			map[string]any{"repos": hidden}))
	} else {
		pts = append(pts, ok("forge: every declared-public repo anonymously visible (§4.2)"))
	}
	return pts
}

// repoAnonymouslyVisible reports whether the canary (`owner/name`, or a bare name)
// matches a repo in the anonymous set.
func repoAnonymouslyVisible(canary string, repos []papi.Repo) bool {
	for _, r := range repos {
		if r.Owner+"/"+r.Name == canary || r.Name == canary {
			return true
		}
	}
	return false
}
