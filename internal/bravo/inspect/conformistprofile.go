//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"code.linenisgreat.com/hyphence/go/hyphence"
	"code.linenisgreat.com/papi/internal/alfa/papi"
)

const (
	conformistProfileResourceKey = "conformist_profile"
	conformistProfileType        = "toml-conformist_profile-v1"
	PurposeConformistProfileSig  = "conformist-profile-sig-v1"
)

// conformistProfilePoints validates the OPTIONAL GET /papi/conformist-profile
// (RFC-0001 §15.3): discovery advertises it iff it is served, the body is a
// toml-conformist_profile-v1 hyphence document, and its §15 signature verifies.
func conformistProfilePoints(ctx context.Context, c *papi.Client, disc *papi.Discovery) []point {
	const label = "conformist-profile (§15.3)"
	advertisedURL, advertised := disc.Resources[conformistProfileResourceKey]

	resp, err := c.Fetch(ctx, conformistProfilePath)
	if err != nil {
		return []point{skip(label, "GET "+conformistProfilePath+" failed: "+err.Error())}
	}
	if resp.Status == http.StatusNotFound {
		if advertised {
			return []point{mustFail(label+": discovery lists "+conformistProfileResourceKey+" but the endpoint is 404 (§4.1)",
				map[string]any{"url": advertisedURL})}
		}
		return []point{skip(label, conformistProfilePath+" not implemented (OPTIONAL, §15.3)")}
	}
	if resp.Status != http.StatusOK {
		return []point{skip(label, fmt.Sprintf("%s returned HTTP %d", conformistProfilePath, resp.Status))}
	}

	var pts []point
	if !advertised {
		// The conformance loop only probes advertised resources, so check the raw body here.
		pts = append(pts,
			mustFail(label+": served but discovery does not list resources."+conformistProfileResourceKey+" (§4.1)", nil),
			textEndpointPoint(resp))
	}

	lines, _, perr := parseHyphenceDocument(resp.Body)
	if perr != nil {
		return append(pts, mustFail(label+": body is a hyphence document", map[string]any{"error": perr.Error()}))
	}
	if got := hyphenceTypeName(lines); got != conformistProfileType {
		pts = append(pts, mustFail(label+": type line is `! "+conformistProfileType+"`", map[string]any{"got": got}))
	}

	keyID, verr := verifyHyphence(resp.Body, PurposeConformistProfileSig, func() []string {
		return fetchPiggyAuthIDs(ctx, c)
	})
	switch {
	case verr == nil:
		pts = append(pts, ok(label+": signed-and-valid (§15.2) by "+keyID))
	case errors.Is(verr, ErrHyphenceUnsigned):
		pts = append(pts, shouldFail(label+": SHOULD be signed under "+PurposeConformistProfileSig, nil))
	case errors.Is(verr, ErrHyphenceSigMalformed), errors.Is(verr, ErrHyphenceNoPublishedKey):
		pts = append(pts, skip(label+": signature unverifiable (§15.2)", verr.Error()))
	default:
		pts = append(pts, mustFail(label+": signed-but-invalid (§15.2)", map[string]any{"error": verr.Error()}))
	}
	return pts
}

// hyphenceTypeName returns the first `!` line's type, without any `@lock` suffix.
func hyphenceTypeName(lines []hyphence.MetadataLine) string {
	for _, l := range lines {
		if l.Prefix == '!' {
			name, _, _ := strings.Cut(l.Value, "@")
			return name
		}
	}
	return ""
}
