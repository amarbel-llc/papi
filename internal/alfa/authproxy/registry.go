package authproxy

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/amarbel-llc/papi/internal/alfa/signchallenge"
)

// RegistryEntry is one registered slot-9A identity: its ECDSA public key and the
// principal (the cn= annotation, falling back to guid=).
type RegistryEntry struct {
	Principal string
	PubKey    *ecdsa.PublicKey
}

// Registry is the set of registered slot-9A keys the verifier accepts. It is parsed
// from a papi-ssh-sync authorized_keys fragment (the published slot-9A registry of
// the PAPI domain), so "any registered YubiKey can auth" follows the registry — add a
// card in PAPI, papi-ssh-sync refreshes the fragment, and it can log in.
type Registry struct {
	entries []RegistryEntry
}

// LoadRegistry reads + parses an authorized_keys fragment file.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read registry %s: %w", path, err)
	}
	return ParseRegistry(data)
}

// ParseRegistry collects every slot-9A ecdsa-sha2-nistp256 key (with its cn=/guid=
// principal) from authorized_keys bytes. Non-9A / non-ecdsa lines are skipped.
func ParseRegistry(data []byte) (*Registry, error) {
	var reg Registry
	rest := data
	for len(rest) > 0 {
		pub, comment, _, r, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break // trailing blanks / unparseable remainder
		}
		rest = r
		if pub.Type() != ssh.KeyAlgoECDSA256 {
			continue
		}
		ann := parseAnnotations(comment)
		if !strings.EqualFold(ann["slot"], "9A") {
			continue
		}
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			continue
		}
		ecpub, ok := ck.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		principal := ann["cn"]
		if principal == "" {
			principal = ann["guid"]
		}
		reg.entries = append(reg.entries, RegistryEntry{Principal: principal, PubKey: ecpub})
	}
	if len(reg.entries) == 0 {
		return nil, fmt.Errorf("registry has no slot-9A ecdsa keys")
	}
	return &reg, nil
}

// VerifyLogin returns the registered identity whose slot-9A key verifies sigMarkl
// over the §5.2 Preimage(domain, nonce). No match → error. (The set is small, so a
// linear scan is fine and avoids relating the markl id to the ssh key.)
func (r *Registry) VerifyLogin(domain, nonce, sigMarkl string) (RegistryEntry, error) {
	for _, e := range r.entries {
		if err := signchallenge.Verify(e.PubKey, domain, nonce, sigMarkl); err == nil {
			return e, nil
		}
	}
	return RegistryEntry{}, fmt.Errorf("signature matches no registered slot-9A key")
}

// Len reports the number of registered keys.
func (r *Registry) Len() int { return len(r.entries) }

// parseAnnotations parses a `key=value key=value` SSH comment into a map (fields
// without '=' — e.g. a leading "piggy" tag — are ignored).
func parseAnnotations(comment string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Fields(comment) {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = v
		}
	}
	return m
}
