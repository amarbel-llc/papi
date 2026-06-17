package inspect

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/amarbel-llc/papi/internal/papi"
	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
)

// signaturePoint verifies the document signature (RFC-0001 §10) over the
// anonymous /papi document. It yields one point: signed-and-valid (ok),
// signed-but-invalid (a MUST failure — a present-but-broken signature is a
// stronger negative than none, §10.3), or unsigned/unverifiable (a skip, since
// signatures are OPTIONAL).
func signaturePoint(ctx context.Context, c *papi.Client) point {
	resp, err := c.Fetch(ctx, "/papi")
	if err != nil {
		return skip("signature: §10 verification", "GET /papi failed: "+err.Error())
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(resp.Body, &env) != nil || len(env.Data) == 0 {
		return skip("signature: §10 verification", "no document data to verify")
	}

	var doc map[string]json.RawMessage
	if json.Unmarshal(env.Data, &doc) != nil {
		return skip("signature: §10 verification", "document data is not a JSON object")
	}
	sigRaw, present := doc["signature"]
	if !present {
		return skip("signature: unsigned (§10.3)", "no signature member")
	}
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

	input, err := canonicalSigningInput(doc)
	if err != nil {
		return mustFail("signature: signed-but-invalid (§10.3)",
			map[string]any{"error": "canonicalize: " + err.Error()})
	}
	if err := verifySSH9a(sig.Key, input, sig.Sig); err != nil {
		return mustFail("signature: signed-but-invalid (§10.3)",
			map[string]any{"error": err.Error(), "key": sig.Key})
	}
	return ok("signature: signed-and-valid (§10, ssh-9a)")
}

// canonicalSigningInput reconstructs the §10.2 signing input: the document with
// the signature member removed, serialized by RFC 8785 JCS.
func canonicalSigningInput(doc map[string]json.RawMessage) ([]byte, error) {
	stripped := make(map[string]json.RawMessage, len(doc))
	for k, v := range doc {
		if k == "signature" {
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

// verifySSH9a verifies an RFC-0001 §10.4 ssh-9a signature: sig is base64 of the
// SSH-wire ecdsa-sha2-nistp256 signature (string(alg) || string(r,s blob));
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
