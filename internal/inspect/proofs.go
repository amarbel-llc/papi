package inspect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/amarbel-llc/papi/internal/papi"
)

// txtLookup resolves a hostname's DNS TXT records. It is a package var so the
// hermetic test suite can substitute a fake resolver (§9.4 DNS proofs); in
// production it is the system resolver.
var txtLookup = func(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// proofDNSTimeout bounds a single TXT lookup (§9.4 "SHOULD bound the response"),
// mirroring the proofHTTPClient timeout.
const proofDNSTimeout = 10 * time.Second

// recipientGrammar is the §5.1 published-recipient id grammar.
var recipientGrammar = regexp.MustCompile(`^piggy-recipient-v1@pivy_ecdh_p256_pub-[0-9a-z-]+$`)

// proofMaxBody bounds a single proof_uri fetch (§9.4 "SHOULD bound the response").
const proofMaxBody = 1 << 20

// proofsChecks verifies the document's identity-ownership proofs (RFC-0001 §9.4)
// over the anonymous /papi document. Each proof yields verified (ok),
// unverified (a flag — the claim is not proven), or unverifiable (a skip — a
// malformed/unsupported entry). It is a third-party check over public inputs;
// proof verdicts are not server-conformance MUSTs, so none trips the exit code.
func proofsChecks(ctx context.Context, c *papi.Client) []point {
	doc, _, _, err := c.Document(ctx)
	if err != nil {
		return []point{skip("proofs: §9 verification", "GET /papi failed: "+err.Error())}
	}
	if len(doc.Proofs) == 0 {
		return []point{skip("proofs: §9 verification", "no proofs[] advertised")}
	}

	var recipients []json.RawMessage
	if doc.Piggy != nil {
		recipients = doc.Piggy.EncryptionRecipients
	}
	published := recipientIDSet(recipients)
	hc := proofHTTPClient()
	seen := map[string]bool{}

	pts := make([]point, 0, len(doc.Proofs))
	for i, pr := range doc.Proofs {
		pts = append(pts, verifyProof(ctx, hc, pr, i, published, seen))
	}
	return pts
}

// verifyProof evaluates one proof entry to the §9.4 outcome.
func verifyProof(ctx context.Context, hc *http.Client, pr papi.Proof, i int, published, seen map[string]bool) point {
	label := fmt.Sprintf("proof[%d] %q", i, pr.ID)

	switch {
	case pr.ID == "":
		return skip(fmt.Sprintf("proofs: proof[%d] unverifiable", i), "missing id (§9.1)")
	case seen[pr.ID]:
		return skip("proofs: "+label+" unverifiable", "duplicate id (§9.1)")
	}
	seen[pr.ID] = true

	switch {
	case !recipientGrammar.MatchString(pr.Recipient):
		return skip("proofs: "+label+" unverifiable", "recipient does not match the §5.1 grammar")
	case !published[pr.Recipient]:
		return skip("proofs: "+label+" unverifiable", "recipient not in piggy.encryption_recipients (§9.1)")
	case pr.Claim == "" || pr.ProofURI == "":
		return skip("proofs: "+label+" unverifiable", "missing claim or proof_uri (§9.1)")
	}

	format := pr.Fmt
	if format == "" {
		format = "recipient"
	}
	switch format {
	case "recipient":
		return verifyRecipientProof(ctx, hc, pr, label)
	case "signature":
		return skip("proofs: "+label+" unverifiable",
			`fmt "signature" not yet implemented — awaits markl-id proof signatures (§9.3)`)
	default:
		return skip("proofs: "+label+" unverifiable", fmt.Sprintf("unknown fmt %q (§9.3)", format))
	}
}

// verifyRecipientProof handles fmt="recipient": the resource at proof_uri MUST
// contain the recipient id (§9.3). It dispatches on the proof_uri scheme — the
// "scheme the service matcher defines" (§9.4) — to the https or dns backlink
// reader; an unsupported scheme is unverifiable, not a failure.
func verifyRecipientProof(ctx context.Context, hc *http.Client, pr papi.Proof, label string) point {
	u, err := url.Parse(pr.ProofURI)
	if err != nil {
		return skip("proofs: "+label+" unverifiable", "bad proof_uri: "+err.Error())
	}
	switch u.Scheme {
	case "https":
		return verifyRecipientProofHTTPS(ctx, hc, pr, label)
	case "dns":
		return verifyRecipientProofDNS(ctx, pr, label, dnsName(u))
	default:
		return skip("proofs: "+label+" unverifiable",
			fmt.Sprintf("proof_uri scheme %q unsupported — https or dns (§9.4)", u.Scheme))
	}
}

// verifyRecipientProofHTTPS reads the backlink from an https document: it MUST
// contain the recipient id as a substring (§9.3). The fetch is same-host-
// redirect-only and bounded (§9.4).
func verifyRecipientProofHTTPS(ctx context.Context, hc *http.Client, pr papi.Proof, label string) point {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pr.ProofURI, nil)
	if err != nil {
		return skip("proofs: "+label+" unverifiable", "bad proof_uri: "+err.Error())
	}
	resp, err := hc.Do(req)
	if err != nil {
		return shouldFail("proofs: "+label+" unverified — proof_uri fetch failed (§9.4)",
			map[string]any{"claim": pr.Claim, "error": err.Error()})
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return shouldFail("proofs: "+label+" unverified — proof_uri non-success (§9.4)",
			map[string]any{"claim": pr.Claim, "status": resp.StatusCode})
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, proofMaxBody))
	if strings.Contains(string(body), pr.Recipient) {
		return ok(fmt.Sprintf("proofs: %s verified — %s backlinks the recipient (§9.4)", label, pr.Claim))
	}
	return shouldFail("proofs: "+label+" unverified — backlink (recipient id) not found at proof_uri (§9.4)",
		map[string]any{"claim": pr.Claim})
}

// verifyRecipientProofDNS reads the backlink from a dns: proof_uri: one of the
// name's TXT records MUST contain the recipient id (§9.3) — the recipient id
// pasted into a DNS TXT record. The lookup is bounded (§9.4).
func verifyRecipientProofDNS(ctx context.Context, pr papi.Proof, label, name string) point {
	if name == "" {
		return skip("proofs: "+label+" unverifiable", "dns: proof_uri has no hostname (§9.4)")
	}
	ctx, cancel := context.WithTimeout(ctx, proofDNSTimeout)
	defer cancel()
	records, err := txtLookup(ctx, name)
	if err != nil {
		return shouldFail("proofs: "+label+" unverified — TXT lookup failed (§9.4)",
			map[string]any{"claim": pr.Claim, "name": name, "error": err.Error()})
	}
	for _, rec := range records {
		if strings.Contains(rec, pr.Recipient) {
			return ok(fmt.Sprintf("proofs: %s verified — %s TXT record backlinks the recipient (§9.4)", label, pr.Claim))
		}
	}
	return shouldFail("proofs: "+label+" unverified — recipient id not found in TXT records (§9.4)",
		map[string]any{"claim": pr.Claim, "name": name, "records": len(records)})
}

// dnsName extracts the hostname from a parsed dns: proof_uri. RFC-0001 uses the
// opaque form (dns:example.com), which url.Parse exposes as Opaque; the //-host
// form is tolerated for robustness.
func dnsName(u *url.URL) string {
	if u.Opaque != "" {
		return u.Opaque
	}
	return u.Host
}

// proofHTTPClient is the §9.4 fetch client: bounded time, and redirects only to
// the same host (a redirect to a foreign host MUST NOT be treated as verified).
func proofHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing redirect to foreign host %q (§9.4)", req.URL.Host)
			}
			return nil
		},
	}
}

// recipientIDSet collects the recipient ids from piggy.encryption_recipients[],
// tolerating string entries and objects carrying the id under "id".
func recipientIDSet(entries []json.RawMessage) map[string]bool {
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		var s string
		if json.Unmarshal(e, &s) == nil && s != "" {
			set[s] = true
			continue
		}
		var m map[string]any
		if json.Unmarshal(e, &m) == nil {
			if id, ok := m["id"].(string); ok && id != "" {
				set[id] = true
			}
		}
	}
	return set
}
