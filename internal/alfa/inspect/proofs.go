package inspect

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/0/papi"
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
	signingKeys := publishedSigningKeys(ctx, c, doc)
	hc := proofHTTPClient()
	seen := map[string]bool{}

	pts := make([]point, 0, len(doc.Proofs))
	for i, pr := range doc.Proofs {
		pts = append(pts, verifyProof(ctx, hc, pr, i, published, seen, signingKeys))
	}
	return pts
}

// publishedSigningKeys collects the P-256 public keys a §9.3 fmt="signature"
// proof may verify against: the subject's slot-9A keys, sourced from both
// ssh_authorized_keys[] (OpenSSH lines) and the piggy-piv_auth-v1 ids on
// /papi/piggy-ids (the canonical markl-id representation).
func publishedSigningKeys(ctx context.Context, c *papi.Client, doc *papi.Document) []*ecdsa.PublicKey {
	var keys []*ecdsa.PublicKey
	if doc.Piggy != nil {
		for _, entry := range doc.Piggy.SSHAuthorizedKeys {
			for _, cand := range candidateKeyLines(entry) {
				if cp, ok := sshKeyCompressedPoint(cand); ok {
					if pub, err := p256FromCompressed(cp); err == nil {
						keys = append(keys, pub)
					}
				}
			}
		}
	}
	for _, id := range fetchPiggyAuthIDs(ctx, c) {
		mid, err := markl.Parse(id)
		if err != nil || mid.Purpose != markl.PurposePIVAuth || mid.Format != markl.FormatSSHEcdsaNistp256Pub {
			continue
		}
		if pub, err := p256FromCompressed(mid.Payload); err == nil {
			keys = append(keys, pub)
		}
	}
	return keys
}

// verifyProof evaluates one proof entry to the §9.4 outcome. signingKeys are the
// subject's published slot-9A keys, used by the fmt="signature" path.
func verifyProof(ctx context.Context, hc *http.Client, pr papi.Proof, i int, published, seen map[string]bool, signingKeys []*ecdsa.PublicKey) point {
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
		return verifySignatureProof(ctx, hc, pr, label, signingKeys)
	default:
		return skip("proofs: "+label+" unverifiable", fmt.Sprintf("unknown fmt %q (§9.3)", format))
	}
}

// verifyRecipientProof handles fmt="recipient": the resource at proof_uri MUST
// contain the recipient id as a substring (§9.3). It reads the backlink material
// via proofBody (https body or dns TXT) and searches it for the recipient id.
func verifyRecipientProof(ctx context.Context, hc *http.Client, pr papi.Proof, label string) point {
	body, source, bad, fetched := proofBody(ctx, hc, pr, label)
	if !fetched {
		return bad
	}
	if strings.Contains(body, pr.Recipient) {
		return ok(fmt.Sprintf("proofs: %s verified — %s %sbacklinks the recipient (§9.4)", label, pr.Claim, source))
	}
	return shouldFail("proofs: "+label+" unverified — recipient id not found at proof_uri (§9.4)",
		map[string]any{"claim": pr.Claim})
}

// proofSigGrammar matches a papi-proof-sig-v1@ecdsa_p256_sig markl-id embedded in
// a proof_uri body (§9.3); markl.Parse then validates its blech32 checksum.
var proofSigGrammar = regexp.MustCompile(`papi-proof-sig-v1@ecdsa_p256_sig-[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+`)

// verifySignatureProof handles fmt="signature" (§9.3, Amendment 9 sibling of
// §10): the resource at proof_uri MUST contain a `papi-proof-sig-v1@ecdsa_p256_sig`
// markl-id — a slot-9A signature over the exact `claim` string — that verifies
// against one of the subject's published slot-9A keys. The signature alone proves
// "the holder of a published slot-9A key signed this claim"; co-publication of
// the proof's recipient binds it to the asserted identity.
func verifySignatureProof(ctx context.Context, hc *http.Client, pr papi.Proof, label string, signingKeys []*ecdsa.PublicKey) point {
	body, _, bad, fetched := proofBody(ctx, hc, pr, label)
	if !fetched {
		return bad
	}
	id, found := findProofSigMarklID(body)
	if !found {
		return shouldFail("proofs: "+label+" unverified — no papi-proof-sig-v1 markl-id at proof_uri (§9.3)",
			map[string]any{"claim": pr.Claim})
	}
	if len(signingKeys) == 0 {
		return skip("proofs: "+label+" unverifiable",
			"no published slot-9A key to verify the signature against (§9.3)")
	}
	for _, k := range signingKeys {
		if ecdsaVerifyRaw(k, []byte(pr.Claim), id.Payload) {
			return ok(fmt.Sprintf("proofs: %s verified — papi-proof-sig-v1 signs the claim %q (§9.3)", label, pr.Claim))
		}
	}
	return shouldFail("proofs: "+label+" unverified — signature verifies against no published slot-9A key (§9.3)",
		map[string]any{"claim": pr.Claim})
}

// findProofSigMarklID returns the first valid papi-proof-sig-v1@ecdsa_p256_sig
// markl-id embedded in body.
func findProofSigMarklID(body string) (markl.ID, bool) {
	for _, m := range proofSigGrammar.FindAllString(body, -1) {
		id, err := markl.Parse(m)
		if err == nil && id.Purpose == markl.PurposeProofSig && id.Format == markl.FormatEcdsaP256Sig {
			return id, true
		}
	}
	return markl.ID{}, false
}

// proofBody fetches the verification material at pr.ProofURI, dispatching on the
// scheme (§9.4): the https response body, or the joined dns TXT records. source
// is a noun for the verified message ("" for https, "TXT record " for dns). On a
// fetch problem it returns a verdict point and ok=false.
func proofBody(ctx context.Context, hc *http.Client, pr papi.Proof, label string) (body, source string, bad point, ok bool) {
	u, err := url.Parse(pr.ProofURI)
	if err != nil {
		return "", "", skip("proofs: "+label+" unverifiable", "bad proof_uri: "+err.Error()), false
	}
	switch u.Scheme {
	case "https":
		return proofBodyHTTPS(ctx, hc, pr, label)
	case "dns":
		return proofBodyDNS(ctx, pr, label, dnsName(u))
	default:
		return "", "", skip("proofs: "+label+" unverifiable",
			fmt.Sprintf("proof_uri scheme %q unsupported — https or dns (§9.4)", u.Scheme)), false
	}
}

// proofBodyHTTPS reads the https proof_uri document, same-host-redirect-only and
// bounded (§9.4).
func proofBodyHTTPS(ctx context.Context, hc *http.Client, pr papi.Proof, label string) (string, string, point, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pr.ProofURI, nil)
	if err != nil {
		return "", "", skip("proofs: "+label+" unverifiable", "bad proof_uri: "+err.Error()), false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", shouldFail("proofs: "+label+" unverified — proof_uri fetch failed (§9.4)",
			map[string]any{"claim": pr.Claim, "error": err.Error()}), false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", shouldFail("proofs: "+label+" unverified — proof_uri non-success (§9.4)",
			map[string]any{"claim": pr.Claim, "status": resp.StatusCode}), false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, proofMaxBody))
	return string(body), "", point{}, true
}

// proofBodyDNS reads the dns: proof_uri's TXT records, bounded (§9.4).
func proofBodyDNS(ctx context.Context, pr papi.Proof, label, name string) (string, string, point, bool) {
	if name == "" {
		return "", "", skip("proofs: "+label+" unverifiable", "dns: proof_uri has no hostname (§9.4)"), false
	}
	ctx, cancel := context.WithTimeout(ctx, proofDNSTimeout)
	defer cancel()
	records, err := txtLookup(ctx, name)
	if err != nil {
		return "", "", shouldFail("proofs: "+label+" unverified — TXT lookup failed (§9.4)",
			map[string]any{"claim": pr.Claim, "name": name, "error": err.Error()}), false
	}
	return strings.Join(records, "\n"), "TXT record ", point{}, true
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
