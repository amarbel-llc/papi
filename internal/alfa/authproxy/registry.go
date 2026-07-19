package authproxy

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/alfa/signchallenge"
)

// RegistryEntry is one registered slot-9A identity: its ECDSA public key and the
// principal (the cn= annotation, falling back to guid=).
type RegistryEntry struct {
	Principal string
	PubKey    *ecdsa.PublicKey
}

// Registry is the set of registered slot-9A keys the verifier accepts, parsed from a
// papi-ssh-sync authorized_keys fragment (the published slot-9A registry of the PAPI
// domain), so "any registered YubiKey can auth" follows the registry. When loaded from
// a file (LoadRegistry), it hot-reloads: VerifyLogin re-reads the fragment when its
// mtime advances, so a card added or revoked by an external sync (papi-ssh-sync, or a
// fetch of /papi/ssh-authorized-keys) takes effect without restarting the verifier.
type Registry struct {
	mu      sync.RWMutex
	entries []RegistryEntry
	path    string    // source file for hot-reload; "" (ParseRegistry) disables it
	modTime time.Time // mtime of the last successful load
}

// LoadRegistry reads + parses an authorized_keys fragment file and remembers the path
// so VerifyLogin can hot-reload it when the file changes on disk (papi#41).
func LoadRegistry(path string) (*Registry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat registry %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read registry %s: %w", path, err)
	}
	reg, err := ParseRegistry(data)
	if err != nil {
		return nil, err
	}
	reg.path = path
	reg.modTime = info.ModTime()
	return reg, nil
}

// ParseRegistry collects every ecdsa-sha2-nistp256 key (with its cn=/guid=
// principal) from authorized_keys bytes — the published slot-9A auth keys, since a
// PAPI domain's §5 auth keys are exactly its P-256 slot-9A keys. The ECDSA-P256 key
// type IS the slot-9A discriminator, so this consumes the canonical
// /papi/ssh-authorized-keys body (RFC-0001 §4.2: guid=/cn= annotations, no slot=)
// AND a `piggy list --format=ssh` style line (which adds slot=9A). Lines that carry a
// `slot=` annotation naming a slot OTHER than 9A, and non-ecdsa lines, are skipped.
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
		if slot, ok := ann["slot"]; ok && !strings.EqualFold(slot, "9A") {
			continue // an explicit non-9A slot; canonical lines carry no slot= at all
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
		return nil, fmt.Errorf("registry has no ecdsa-sha2-nistp256 (slot-9A auth) keys")
	}
	return &reg, nil
}

// VerifyLogin returns the registered identity whose slot-9A key verifies sigMarkl
// over the §5.2 Preimage(domain, nonce). No match → error. (The set is small, so a
// linear scan is fine and avoids relating the markl id to the ssh key.) A file-backed
// registry is hot-reloaded first if its fragment changed on disk.
func (r *Registry) VerifyLogin(domain, nonce, sigMarkl string) (RegistryEntry, error) {
	r.maybeReload()
	r.mu.RLock()
	entries := r.entries
	r.mu.RUnlock()
	for _, e := range entries {
		if err := signchallenge.Verify(e.PubKey, domain, nonce, sigMarkl); err == nil {
			return e, nil
		}
	}
	return RegistryEntry{}, fmt.Errorf("signature matches no registered slot-9A key")
}

// maybeReload re-reads the fragment when its mtime advances, so an externally-synced
// registry takes effect without a verifier restart (papi#41). Best-effort: a failed
// stat/read/parse (including a transient empty write mid-refresh) keeps the last good
// set rather than locking out logins.
func (r *Registry) maybeReload() {
	if r.path == "" {
		return
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return
	}
	r.mu.RLock()
	stale := info.ModTime().After(r.modTime)
	r.mu.RUnlock()
	if !stale {
		return
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	parsed, err := ParseRegistry(data)
	if err != nil {
		return // keep the last good set
	}
	r.mu.Lock()
	r.entries = parsed.entries
	r.modTime = info.ModTime()
	r.mu.Unlock()
}

// Len reports the number of registered keys.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

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
