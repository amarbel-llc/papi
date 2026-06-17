// Package inspect drives the first-cut PAPI introspection: discover a domain's
// PAPI and report what it publishes as an ndjson-crap result stream. Every
// point is informational (a fact about the document); conformance verdicts
// (RFC-0001 §2, §4, §5) are layered on in a later cut.
package inspect

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/papi/internal/papi"
)

// Run discovers and introspects target's PAPI, writing an ndjson-crap stream to
// w. It returns an error only on an operational failure (the domain's discovery
// could not be fetched); per-resource facts are reported as stream points.
func Run(ctx context.Context, w io.Writer, target string) error {
	c, err := papi.NewClient(target)
	if err != nil {
		return err
	}

	rep := crap.NewReporter(w, crap.ReporterOptions{
		Title:  "papi introspect " + c.BaseURL,
		Source: "papi",
	})

	var pts []point

	disc, _, derr := c.Discovery(ctx)
	if derr != nil {
		emit(rep, []point{notOk("discovery: GET /.well-known/papi", map[string]any{"error": derr.Error()})})
		if rep.Err() != nil {
			return rep.Err()
		}
		return fmt.Errorf("discovery: %w", derr)
	}
	pts = append(pts, ok(fmt.Sprintf("discovery: reachable — version %q, handle %q", disc.Version, disc.Handle)))
	pts = append(pts, discoveryPoints(disc)...)

	if doc, _, _, docErr := c.Document(ctx); docErr != nil {
		pts = append(pts, notOk("introspect: GET /papi", map[string]any{"error": docErr.Error()}))
	} else {
		pts = append(pts, documentPoints(doc)...)
	}

	emit(rep, pts)
	return rep.Err()
}

// point is a pending stream entry; emit turns it into the right crap record.
type point struct {
	desc   string
	ok     bool
	diag   map[string]any
	reason string // non-empty => skip
}

func ok(desc string) point                      { return point{desc: desc, ok: true} }
func notOk(desc string, d map[string]any) point { return point{desc: desc, diag: d} }
func skip(desc, reason string) point            { return point{desc: desc, ok: true, reason: reason} }

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
