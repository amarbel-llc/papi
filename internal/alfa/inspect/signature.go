package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
)

// signaturePoints verifies the document signature(s) (RFC-0001 §10) over the
// anonymous /papi document. Amendment 9 made the signature a `signatures[]`
// array of markl-id entries verified conjunctively: each entry yields
// signed-and-valid (ok), signed-but-invalid (a MUST failure — a present-but-
// broken signature is a stronger negative than none, §10.3), or unverifiable (a
// skip). A document is authentic only if every evaluable entry verifies, so any
// invalid entry trips the exit code. The legacy singular `signature` (ssh-9a) is
// still verified when no `signatures[]` is present.
func signaturePoints(ctx context.Context, c *papi.Client) []point {
	resp, err := c.Fetch(ctx, "/papi")
	if err != nil {
		return []point{skip("signature: §10 verification", "GET /papi failed: "+err.Error())}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(resp.Body, &env) != nil || len(env.Data) == 0 {
		return []point{skip("signature: §10 verification", "no document data to verify")}
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(env.Data, &doc) != nil {
		return []point{skip("signature: §10 verification", "document data is not a JSON object")}
	}

	input, err := canonicalSigningInput(doc)
	if err != nil {
		return []point{mustFail("signature: signed-but-invalid (§10.3)",
			map[string]any{"error": "canonicalize: " + err.Error()})}
	}

	// Amendment 9: a `signatures[]` array (markl-id entries), verified
	// conjunctively. Takes precedence over the legacy singular form.
	if sigsRaw, ok := doc["signatures"]; ok {
		var entries []papi.Signature
		if json.Unmarshal(sigsRaw, &entries) == nil && len(entries) > 0 {
			authIDs := fetchPiggyAuthIDs(ctx, c)
			pts := make([]point, 0, len(entries))
			for i, e := range entries {
				pts = append(pts, verifyMarklSignature(i, e, input, doc, authIDs))
			}
			return pts
		}
	}

	// Legacy singular `signature` (ssh-9a, pre-Amendment 9).
	if sigRaw, present := doc["signature"]; present {
		return []point{verifyLegacySignature(sigRaw, input, doc)}
	}
	return []point{skip("signature: unsigned (§10.3)", "no signature or signatures member")}
}

// verifyMarklSignature evaluates one Amendment 9 `signatures[]` entry: `sig` is a
// papi-doc-sig-v1@ecdsa_p256_sig markl-id (raw 64-byte r‖s), `key` is a
// …@ssh_ecdsa_nistp256_pub markl-id (33-byte SEC1 point). The method is carried
// by the markl-ids, so there is no `alg` field.
func verifyMarklSignature(i int, entry papi.Signature, input []byte, doc map[string]json.RawMessage, authIDs []string) point {
	label := fmt.Sprintf("signatures[%d]", i)

	sigID, err := markl.Parse(entry.Sig)
	if err != nil || sigID.Purpose != markl.PurposeDocSig || sigID.Format != markl.FormatEcdsaP256Sig {
		return skip("signature: "+label+" unverifiable (§10.3)",
			"sig is not a papi-doc-sig-v1@ecdsa_p256_sig markl-id")
	}
	keyID, err := markl.Parse(entry.Key)
	if err != nil || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
		return skip("signature: "+label+" unverifiable (§10.3)",
			"key is not an …@ssh_ecdsa_nistp256_pub markl-id")
	}
	if !keyPublishedMarkl(entry.Key, keyID.Payload, doc, authIDs) {
		return skip("signature: "+label+" unverifiable -> unsigned (§10.1)",
			"signing key is not published (piggy-ids or ssh_authorized_keys)")
	}

	pub, err := p256FromCompressed(keyID.Payload)
	if err != nil {
		return mustFail("signature: "+label+" signed-but-invalid (§10.3)",
			map[string]any{"error": err.Error(), "key": entry.Key})
	}
	if !ecdsaVerifyRaw(pub, input, sigID.Payload) {
		return mustFail("signature: "+label+" signed-but-invalid (§10.3)",
			map[string]any{"key": entry.Key})
	}
	return ok(fmt.Sprintf("signature: %s signed-and-valid (§10, papi-doc-sig-v1)", label))
}

// verifyLegacySignature handles the pre-Amendment 9 singular `signature` object
// (alg "ssh-9a", an OpenSSH `key` line, a base64 SSH-wire `sig`).
func verifyLegacySignature(sigRaw json.RawMessage, input []byte, doc map[string]json.RawMessage) point {
	var sig papi.Signature
	if json.Unmarshal(sigRaw, &sig) != nil {
		return skip("signature: unsigned (§10.3)", "signature member is not an object")
	}
	if sig.Alg != "ssh-9a" {
		return skip("signature: unsigned (§10.3)", fmt.Sprintf("alg %q not understood", sig.Alg))
	}
	if !keyPublished(sig.Key, doc) {
		return skip("signature: unverifiable -> unsigned (§10.1)",
			"signing key is not published in ssh_authorized_keys")
	}
	if err := verifySSH9a(sig.Key, input, sig.Sig); err != nil {
		return mustFail("signature: signed-but-invalid (§10.3)",
			map[string]any{"error": err.Error(), "key": sig.Key})
	}
	return ok("signature: signed-and-valid (§10, ssh-9a legacy)")
}

// canonicalSigningInput reconstructs the §10.2 signing input: the document with
// both the `signature` and `signatures` members removed, serialized by RFC 8785
// JCS. Stripping both lets a producer/verifier reconstruct identical bytes
// regardless of which form a document carries (Amendment 9).
func canonicalSigningInput(doc map[string]json.RawMessage) ([]byte, error) {
	stripped := make(map[string]json.RawMessage, len(doc))
	for k, v := range doc {
		if k == "signature" || k == "signatures" {
			continue
		}
		stripped[k] = v
	}
	reser, err := json.Marshal(stripped)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(reser)
}

// fetchPiggyAuthIDs returns the bare ids advertised on /papi/piggy-ids (one per
// line, comments dropped) — the canonical markl-id representation of a subject's
// keys, against which an Amendment 9 signature's `key` is string-matched. Best
// effort: an unreachable endpoint yields no ids and verification falls back to
// the ssh_authorized_keys[] point-match.
func fetchPiggyAuthIDs(ctx context.Context, c *papi.Client) []string {
	body, status, err := c.PiggyIDs(ctx)
	if err != nil || status != 200 {
		return nil
	}
	var ids []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids = append(ids, line)
	}
	return ids
}

// keyPublishedMarkl reports whether an Amendment 9 signature's key is published,
// by either of two paths (the maintainer's union ruling, §10.1):
//   - canonical: string-equality of the key markl-id against the slot-9A ids
//     advertised on /papi/piggy-ids;
//   - fallback: the key's P-256 point matches an ssh_authorized_keys[] entry, so
//     instances publishing only OpenSSH keys still verify.
func keyPublishedMarkl(keyMarklID string, keyPoint []byte, doc map[string]json.RawMessage, authIDs []string) bool {
	for _, id := range authIDs {
		if id == keyMarklID {
			return true
		}
	}
	return pointPublished(keyPoint, doc)
}

// pointPublished reports whether a SEC1-compressed P-256 point matches the key
// of any ssh_authorized_keys[] entry (§10.1 fallback).
func pointPublished(compressed []byte, doc map[string]json.RawMessage) bool {
	piggyRaw, ok := doc["piggy"]
	if !ok {
		return false
	}
	var p struct {
		SSHAuthorizedKeys []json.RawMessage `json:"ssh_authorized_keys"`
	}
	if json.Unmarshal(piggyRaw, &p) != nil {
		return false
	}
	for _, entry := range p.SSHAuthorizedKeys {
		for _, cand := range candidateKeyLines(entry) {
			if cp, ok := sshKeyCompressedPoint(cand); ok && bytes.Equal(cp, compressed) {
				return true
			}
		}
	}
	return false
}

// sshKeyCompressedPoint parses an OpenSSH ecdsa-sha2-nistp256 key line and
// returns its SEC1-compressed P-256 point, matching the markl ssh_ecdsa_nistp256_pub
// payload encoding.
func sshKeyCompressedPoint(line string) ([]byte, bool) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || pub.Type() != ssh.KeyAlgoECDSA256 {
		return nil, false
	}
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, false
	}
	ec, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, false
	}
	return elliptic.MarshalCompressed(elliptic.P256(), ec.X, ec.Y), true
}

// p256FromCompressed decodes a 33-byte SEC1-compressed point into a P-256 key.
func p256FromCompressed(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	if x == nil {
		return nil, errors.New("invalid compressed P-256 point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// ecdsaVerifyRaw verifies a raw 64-byte r‖s ECDSA P-256 signature (the
// `ecdsa_p256_sig` markl format) over SHA-256(input).
func ecdsaVerifyRaw(pub *ecdsa.PublicKey, input, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// verifySSH9a verifies a legacy RFC-0001 §10.4 ssh-9a signature: sig is base64 of
// the SSH-wire ecdsa-sha2-nistp256 signature (string(alg) || string(r,s blob));
// verification is ECDSA-P256 + SHA-256 (handled by x/crypto/ssh) over input.
func verifySSH9a(keyLine string, input []byte, sigB64 string) error {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	if pub.Type() != ssh.KeyAlgoECDSA256 {
		return fmt.Errorf("key type %q, want ecdsa-sha2-nistp256", pub.Type())
	}
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("sig base64: %w", err)
	}
	format, rest, ok := parseSSHString(raw)
	if !ok {
		return fmt.Errorf("sig: missing algorithm-name string")
	}
	blob, _, ok := parseSSHString(rest)
	if !ok {
		return fmt.Errorf("sig: missing signature blob")
	}
	if string(format) != ssh.KeyAlgoECDSA256 {
		return fmt.Errorf("sig algorithm %q, want ecdsa-sha2-nistp256", format)
	}
	return pub.Verify(input, &ssh.Signature{Format: string(format), Blob: blob})
}

// parseSSHString peels one RFC 4251 §5 length-prefixed string off b.
func parseSSHString(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(len(b)-4) < uint64(n) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// keyPublished reports whether key (an authorized_keys line) appears in the
// document's piggy.ssh_authorized_keys[] (§10.1), matched by normalized key
// material. Entries may be plain strings or objects carrying the line.
func keyPublished(key string, doc map[string]json.RawMessage) bool {
	want := normalizeKey(key)
	if want == "" {
		return false
	}
	piggyRaw, ok := doc["piggy"]
	if !ok {
		return false
	}
	var p struct {
		SSHAuthorizedKeys []json.RawMessage `json:"ssh_authorized_keys"`
	}
	if json.Unmarshal(piggyRaw, &p) != nil {
		return false
	}
	for _, entry := range p.SSHAuthorizedKeys {
		for _, cand := range candidateKeyLines(entry) {
			if normalizeKey(cand) == want {
				return true
			}
		}
	}
	return false
}

func candidateKeyLines(entry json.RawMessage) []string {
	var s string
	if json.Unmarshal(entry, &s) == nil {
		return []string{s}
	}
	var m map[string]any
	if json.Unmarshal(entry, &m) != nil {
		return nil
	}
	var out []string
	for _, f := range []string{"key", "public_key", "line", "authorized_key"} {
		if v, ok := m[f].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}

// normalizeKey parses an authorized_keys line and returns "type base64" (comment
// dropped), or "" if it does not parse.
func normalizeKey(line string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal())
}
