// Package inspect drives `papi validate`: it discovers a domain's PAPI, reports
// what it publishes (introspection facts), and checks it against the RFC-0001
// public-tier conformance contract (discovery, envelope, acl-strip, projection,
// text endpoints, auth status codes — see check.go). Each entry is an
// ndjson-crap point: an informational fact, a MUST/SHOULD verdict, or a skip.
// The scoped projection and the full challenge/response handshake (a card) are
// out of this cut.
package inspect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/papi/internal/papi"
)

// ErrNonConformant is returned by Run when the domain violates a MUST. The
// ndjson-crap stream has already been written; the error only signals the
// process exit code.
var ErrNonConformant = errors.New("domain is not RFC-0001 conformant")

// Run discovers and introspects target's PAPI, writing an ndjson-crap stream to
// w. It returns an error only on an operational failure (the domain's discovery
// could not be fetched); per-resource facts are reported as stream points.
func Run(ctx context.Context, w io.Writer, target string) error {
	c, err := papi.NewClient(target)
	if err != nil {
		return err
	}

	rep := crap.NewReporter(w, crap.ReporterOptions{
		Title:  "papi validate " + c.BaseURL,
		Source: "papi",
	})

	var pts []point

	disc, _, derr := c.Discovery(ctx)
	if derr != nil {
		emit(rep, []point{mustFail("discovery: GET /.well-known/papi", map[string]any{"error": derr.Error()})})
		if rep.Err() != nil {
			return rep.Err()
		}
		return fmt.Errorf("discovery: %w", derr)
	}
	pts = append(pts, ok(fmt.Sprintf("discovery: reachable — version %q, handle %q", disc.Version, disc.Handle)))
	pts = append(pts, discoveryPoints(disc)...)
	pts = append(pts, discoveryVerdicts(disc)...)

	if doc, _, _, docErr := c.Document(ctx); docErr != nil {
		pts = append(pts, mustFail("introspect: GET /papi", map[string]any{"error": docErr.Error()}))
	} else {
		pts = append(pts, documentPoints(doc)...)
	}

	pts = append(pts, conformanceChecks(ctx, c, disc)...)
	pts = append(pts, signaturePoint(ctx, c))

	emit(rep, pts)
	if rep.Err() != nil {
		return rep.Err()
	}
	if anyMustFail(pts) {
		return ErrNonConformant
	}
	return nil
}

// point is a pending stream entry; emit turns it into the right crap record. A
// point with reason != "" is a skip; otherwise ok toggles pass/fail, and must
// marks a failing point as a MUST violation (which sets the process exit code).
type point struct {
	desc   string
	ok     bool
	diag   map[string]any
	reason string // non-empty => skip
	must   bool   // a failing MUST (vs a SHOULD)
}

func ok(desc string) point           { return point{desc: desc, ok: true} }
func skip(desc, reason string) point { return point{desc: desc, ok: true, reason: reason} }

// mustFail is a failing MUST verdict (trips the exit code); shouldFail is a
// failing SHOULD verdict (reported, but does not trip the exit code).
func mustFail(desc string, d map[string]any) point {
	return point{desc: desc, diag: d, must: true}
}

func shouldFail(desc string, d map[string]any) point {
	return point{desc: desc, diag: withSeverity(d, "should")}
}

func withSeverity(d map[string]any, sev string) map[string]any {
	if d == nil {
		d = map[string]any{}
	}
	d["severity"] = sev
	return d
}

func anyMustFail(pts []point) bool {
	for _, p := range pts {
		if !p.ok && p.reason == "" && p.must {
			return true
		}
	}
	return false
}

func emit(rep *crap.Reporter, pts []point) {
	ts := rep.TestStream(len(pts))
	for _, p := range pts {
		switch {
		case p.reason != "":
			ts.Skip(p.desc, p.reason)
		case p.ok:
			ts.Ok(p.desc)
		default:
			ts.NotOk(p.desc, p.diag)
		}
	}
	ts.Finish()
}

func discoveryPoints(d *papi.Discovery) []point {
	var pts []point

	keys := sortedKeys(d.Resources)
	pts = append(pts, ok(fmt.Sprintf("discovery: %d resource link(s): %s", len(keys), strings.Join(keys, ", "))))

	// Surface the scheme of each link as a fact. http:// is a SHOULD violation
	// (RFC-0001 §4.1, linenisgreat#26); flagging it as a verdict is part of the
	// conformance cut, but reporting the scheme here is plain introspection.
	var insecure []string
	for _, k := range keys {
		if strings.HasPrefix(d.Resources[k], "http://") {
			insecure = append(insecure, k)
		}
	}
	if len(insecure) > 0 {
		pts = append(pts, ok(fmt.Sprintf("discovery: %d resource link(s) use http:// (%s)",
			len(insecure), strings.Join(insecure, ", "))))
	}

	if d.Auth != nil {
		pts = append(pts, ok(fmt.Sprintf("discovery: auth scheme %q", d.Auth.Scheme)))
	} else {
		pts = append(pts, skip("discovery: auth block", "no auth block advertised"))
	}
	return pts
}

func documentPoints(d *papi.Document) []point {
	var pts []point

	if d.Person != nil {
		label := d.Person.Handle
		if d.Person.Name != "" {
			label = fmt.Sprintf("%s (%s)", d.Person.Name, d.Person.Handle)
		}
		pts = append(pts, ok("person: "+label))
	}

	if d.Piggy != nil {
		pts = append(pts, ok(fmt.Sprintf("piggy: %d encryption recipient(s), %d ssh key(s)",
			len(d.Piggy.EncryptionRecipients), len(d.Piggy.SSHAuthorizedKeys))))
	}

	if len(d.Forges) > 0 {
		repos := 0
		kinds := make([]string, 0, len(d.Forges))
		for _, f := range d.Forges {
			repos += len(f.Repos)
			kinds = append(kinds, forgeLabel(f))
		}
		pts = append(pts, ok(fmt.Sprintf("forges: %d (%s) with %d repo(s)",
			len(d.Forges), strings.Join(kinds, ", "), repos)))
	}

	if len(d.Organizations) > 0 {
		pts = append(pts, ok(fmt.Sprintf("organizations: %d", len(d.Organizations))))
	}

	if len(d.Sitemap) > 0 {
		pts = append(pts, ok(fmt.Sprintf("sitemap: %d domain(s): %s",
			len(d.Sitemap), strings.Join(sortedRawKeys(d.Sitemap), ", "))))
	}

	if len(d.Templates) > 0 {
		ids := make([]string, 0, len(d.Templates))
		for _, t := range d.Templates {
			ids = append(ids, t.ID)
		}
		pts = append(pts, ok(fmt.Sprintf("templates: %d (%s)", len(d.Templates), strings.Join(ids, ", "))))
	} else {
		pts = append(pts, skip("templates (RFC-0001 §7)", "no templates[] advertised"))
	}

	return pts
}

func forgeLabel(f papi.Forge) string {
	if f.ID != "" {
		return fmt.Sprintf("%s/%s", f.Kind, f.ID)
	}
	return f.Kind
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedRawKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
