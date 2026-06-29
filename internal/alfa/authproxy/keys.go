package authproxy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// LoadCookieKey reads the verifier-only HMAC cookie key from a file (raw bytes,
// surrounding whitespace trimmed). It requires >= 32 bytes. circus provisions this
// from a slot-9D ebox decrypted at deploy time into a runtime secret file.
func LoadCookieKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cookie key %s: %w", path, err)
	}
	b = bytes.TrimSpace(b)
	if len(b) < 32 {
		return nil, fmt.Errorf("cookie key %s: %d bytes, need >= 32", path, len(b))
	}
	return b, nil
}

// LoadOraclePub reads the oracle's Ed25519 PUBLIC key from a file — standard-base64
// of the 32 raw key bytes (the form committed in-repo; it is not secret). The
// verifier holds only this, so it can verify an attestation but never forge one.
func LoadOraclePub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read oracle pubkey %s: %w", path, err)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode oracle pubkey %s: %w", path, err)
	}
	if len(dec) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("oracle pubkey %s: %d bytes, want %d", path, len(dec), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(dec), nil
}

// set builds a lookup set from a slice (e.g. repeated --allow-principal flags).
func set(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if it != "" {
			m[it] = true
		}
	}
	return m
}

// Set is the exported form of the allowlist-builder for command wiring.
func Set(items []string) map[string]bool { return set(items) }
