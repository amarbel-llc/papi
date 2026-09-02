package authproxy

import (
	"bytes"
	"fmt"
	"os"
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

// Set builds a lookup set from a slice (e.g. repeated --allow-principal flags). An
// empty slice yields nil, which the verifier treats as "no restriction".
func Set(items []string) map[string]bool {
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
