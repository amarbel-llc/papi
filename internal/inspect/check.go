package inspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/amarbel-llc/papi/internal/papi"
)

// conformanceChecks runs the RFC-0001 public-tier conformance verdicts against
// the domain as the anonymous principal: every advertised resource's envelope /
// acl-strip / projection, the text endpoints, and the auth error codes. The
// scoped projection and the full challenge/response handshake need a card and
// are reported as a skip.
func conformanceChecks(ctx context.Context, c *papi.Client, disc *papi.Discovery) []point {
	var pts []point

	for _, k := range sortedKeys(disc.Resources) {
		path := resourcePath(disc.Resources[k])
		if path == "" {
			pts = append(pts, shouldFail("conformance: discovery resource "+k+" has no usable path",
				map[string]any{"url": disc.Resources[k]}))
			continue
		}
		resp, err := c.Fetch(ctx, path)
		if err != nil {
			pts = append(pts, mustFail("conformance: GET "+path, map[string]any{"error": err.Error()}))
			continue
		}
		if isTextEndpoint(path) {
			pts = append(pts, textEndpointPoint(resp))
			continue
		}
		pts = append(pts, envelopePoints(resp)...)
		pts = append(pts, aclLeakPoint(resp))
		pts = append(pts, privateHuskPoint(resp))
	}

	pts = append(pts, authProbes(ctx, c)...)
	return pts
}

// resourcePath returns the path of an absolute or relative resource URL, so a
// probe runs against the validated base rather than following the advertised
// link's scheme/host (which §Security warns may be attacker-chosen).
func resourcePath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return ""
	}
	return u.Path
}

func isTextEndpoint(path string) bool {
	return strings.HasSuffix(path, "/piggy-ids") || strings.HasSuffix(path, "/ssh-authorized-keys")
}

// discoveryVerdicts checks the discovery document's required fields (§4.1) and
// that its resource links are absolute (MUST) and https (SHOULD; http:// is
// linenisgreat#26).
func discoveryVerdicts(d *papi.Discovery) []point {
	var pts []point
	if d.Version == "" {
		pts = append(pts, mustFail("conformance: discovery has version (§4.1)", nil))
	}
	if d.Handle == "" {
		pts = append(pts, mustFail("conformance: discovery has handle (§4.1)", nil))
	}
	if len(d.Resources) == 0 {
		pts = append(pts, mustFail("conformance: discovery has resources (§4.1)", nil))
	}
	if d.Auth == nil {
		pts = append(pts, mustFail("conformance: discovery has auth (§4.1)", nil))
	}
	for _, k := range sortedKeys(d.Resources) {
		u := d.Resources[k]
		switch {
		case strings.HasPrefix(u, "https://"):
		case strings.HasPrefix(u, "http://"):
			pts = append(pts, shouldFail("conformance: discovery resource "+k+" is http:// — SHOULD be https (§4.1, linenisgreat#26)",
				map[string]any{"url": u}))
		default:
			pts = append(pts, mustFail("conformance: discovery resource "+k+" is not an absolute URL (§4.1)",
				map[string]any{"url": u}))
		}
	}
	if len(pts) == 0 {
		pts = append(pts, ok("conformance: discovery required fields + absolute https resource links (§4.1)"))
	}
	return pts
}

// envelopePoints checks a JSON endpoint's {data, meta} envelope (§4.2) and that
// meta.visibility is "public" for the anonymous principal.
func envelopePoints(resp *papi.Response) []point {
	label := "conformance: " + resp.Path
	if resp.Status != http.StatusOK {
		return []point{mustFail(label+" status 200", map[string]any{"got": resp.Status})}
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return []point{mustFail(label+" is JSON", map[string]any{"error": err.Error()})}
	}
	var pts []point
	if !hasKey(env, "data") {
		pts = append(pts, mustFail(label+" has data (§4.2)", nil))
	}
	meta, hasMeta := env["meta"]
	if !hasMeta {
		pts = append(pts, mustFail(label+" has meta (§4.2)", nil))
		return pts
	}
	var m map[string]any
	_ = json.Unmarshal(meta, &m)
	if _, has := m["type"]; !has {
		pts = append(pts, shouldFail(label+" meta.type (§4.2)", nil))
	}
	switch v, present := m["visibility"]; {
	case !present:
		pts = append(pts, mustFail(label+" meta.visibility (§4.2)", nil))
	case v != "public":
		pts = append(pts, mustFail(label+" meta.visibility==public for anon (§4.2)", map[string]any{"got": v}))
	}
	if resp.Path == "/papi" {
		if _, has := m["version"]; !has {
			pts = append(pts, mustFail(label+" meta.version (§4.2)", nil))
		}
	}
	if len(pts) == 0 {
		pts = append(pts, ok(label+" {data,meta}, meta.visibility=public (§4.2)"))
	}
	return pts
}

// aclLeakPoint scans a JSON response for any serialized "acl" key — a HARD FAIL
// (§2.6: acl MUST NOT appear in any response, on any path).
func aclLeakPoint(resp *papi.Response) point {
	var v any
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return ok("conformance: " + resp.Path + " acl-strip (non-JSON, skipped)")
	}
	if at := findACL(v); at != "" {
		return mustFail("conformance: "+resp.Path+" leaks an acl key — HARD FAIL (§2.6)",
			map[string]any{"at": at})
	}
	return ok("conformance: " + resp.Path + " strips acl (§2.6)")
}

func findACL(v any) string {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["acl"]; ok {
			return "acl"
		}
		for k, val := range t {
			if sub := findACL(val); sub != "" {
				return k + "." + sub
			}
		}
	case []any:
		for i, val := range t {
			if sub := findACL(val); sub != "" {
				return fmt.Sprintf("[%d].%s", i, sub)
			}
		}
	}
	return ""
}

// privateHuskPoint flags a visibility:"private" node present in an anonymous
// response — a projection leak (§2.5: private nodes MUST be dropped for the
// anonymous principal, not emitted).
func privateHuskPoint(resp *papi.Response) point {
	var v any
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return ok("conformance: " + resp.Path + " private-drop (non-JSON, skipped)")
	}
	if hasPrivateVisibility(v) {
		return mustFail("conformance: "+resp.Path+" exposes a visibility:private node to anon (§2.5)", nil)
	}
	return ok("conformance: " + resp.Path + " drops private nodes for anon (§2.5)")
}

func hasPrivateVisibility(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if vis, _ := t["visibility"].(string); vis == "private" {
			return true
		}
		for _, val := range t {
			if hasPrivateVisibility(val) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if hasPrivateVisibility(val) {
				return true
			}
		}
	}
	return false
}

// textEndpointPoint checks a text/plain endpoint: 200, a raw body that is NOT the
// JSON envelope (§4.2), and (SHOULD) a text/plain Content-Type.
func textEndpointPoint(resp *papi.Response) point {
	if resp.Status != http.StatusOK {
		return mustFail("conformance: "+resp.Path+" status 200", map[string]any{"got": resp.Status})
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(resp.Body, &env) == nil && hasKey(env, "data") && hasKey(env, "meta") {
		return mustFail("conformance: "+resp.Path+" MUST NOT use the {data,meta} envelope (§4.2)",
			map[string]any{"content_type": resp.ContentType})
	}
	if !strings.HasPrefix(resp.ContentType, "text/plain") {
		return shouldFail("conformance: "+resp.Path+" Content-Type text/plain (§4.2)",
			map[string]any{"got": resp.ContentType})
	}
	return ok("conformance: " + resp.Path + " raw text/plain, not enveloped (§4.2)")
}

// authProbes checks the auth endpoints' error codes (§5.1, §5.2) without a card:
// malformed requests MUST yield 400, and an unknown recipient 403 — or 503 when
// no box backend is available (auth tier unavailable, not a failure).
func authProbes(ctx context.Context, c *papi.Client) []point {
	var pts []point

	// The challenge tier: a 503 means no box backend (§5.1), and the server MUST
	// answer 503 before validating the request — so it short-circuits the
	// recipient checks. Treat it as "auth tier unavailable" (a skip), not a
	// failure, and skip the dependent error-code probes.
	noRecip, err := c.Post(ctx, "/papi/auth/challenge", []byte(`{}`))
	switch {
	case err != nil:
		pts = append(pts, mustFail("conformance: POST /papi/auth/challenge", map[string]any{"error": err.Error()}))
	case noRecip.Status == http.StatusServiceUnavailable:
		pts = append(pts, skip("conformance: /papi/auth/challenge error codes (§5.1)",
			"503 — auth tier unavailable (no box backend); challenge checks skipped"))
	default:
		pts = append(pts, statusPoint("challenge with no recipient -> 400 (§5.1)", noRecip.Status, http.StatusBadRequest))
		unknown := []byte(`{"recipient":"piggy-recipient-v1@pivy_ecdh_p256_pub-zzznonexistentprobe"}`)
		if resp, uerr := c.Post(ctx, "/papi/auth/challenge", unknown); uerr == nil {
			pts = append(pts, authUnknownPoint(resp.Status))
		}
	}

	if resp, err := c.Post(ctx, "/papi/auth/response", []byte(`{}`)); err != nil {
		pts = append(pts, mustFail("conformance: POST /papi/auth/response", map[string]any{"error": err.Error()}))
	} else {
		pts = append(pts, statusPoint("response with no fields -> 400 (§5.2)", resp.Status, http.StatusBadRequest))
	}

	return pts
}

func statusPoint(label string, got, want int) point {
	if got == want {
		return ok("conformance: " + label)
	}
	return mustFail("conformance: "+label, map[string]any{"got": got, "want": want})
}

func authUnknownPoint(status int) point {
	switch status {
	case http.StatusForbidden:
		return ok("conformance: challenge with unknown recipient -> 403 (§5.1)")
	case http.StatusServiceUnavailable:
		return skip("conformance: challenge with unknown recipient (§5.1)",
			"503 — auth tier unavailable (no box backend); not a conformance failure")
	default:
		return mustFail("conformance: challenge with unknown recipient -> 403 or 503 (§5.1)",
			map[string]any{"got": status})
	}
}

func hasKey(m map[string]json.RawMessage, k string) bool {
	_, ok := m[k]
	return ok
}
