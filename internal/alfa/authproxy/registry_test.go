package authproxy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// ecdsaLine builds an ecdsa-sha2-nistp256 authorized_keys line with the given
// trailing comment (the annotation field).
func ecdsaLine(t *testing.T, comment string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line + "\n"
}

// TestParseRegistryCanonicalFormat is the load-bearing compatibility check: the
// published /papi/ssh-authorized-keys body (RFC-0001 §4.2) annotates lines with
// guid=/cn= and NO slot=. The registry MUST accept those — the verifier's whole
// source-of-truth depends on it.
func TestParseRegistryCanonicalFormat(t *testing.T) {
	body := ecdsaLine(t, "guid=ABCD1234 cn=alice") // no slot= — canonical endpoint shape
	reg, err := ParseRegistry([]byte(body))
	if err != nil {
		t.Fatalf("canonical (guid=/cn=, no slot=) rejected: %v", err)
	}
	if reg.Len() != 1 {
		t.Fatalf("Len = %d, want 1", reg.Len())
	}
	if got := reg.entries[0].Principal; got != "alice" {
		t.Errorf("principal = %q, want alice (from cn=)", got)
	}
}

func TestParseRegistryPiggyFormat(t *testing.T) {
	// `piggy list --format=ssh` adds a leading tag + slot=9A; still accepted.
	reg, err := ParseRegistry([]byte(ecdsaLine(t, "piggy slot=9A guid=DEAD cn=bob")))
	if err != nil || reg.Len() != 1 || reg.entries[0].Principal != "bob" {
		t.Fatalf("piggy-format line: err=%v len=%d", err, reg.Len())
	}
}

func TestParseRegistryPrincipalFallback(t *testing.T) {
	// No cn= → principal falls back to guid=.
	reg, err := ParseRegistry([]byte(ecdsaLine(t, "slot=9A guid=FEED")))
	if err != nil {
		t.Fatal(err)
	}
	if got := reg.entries[0].Principal; got != "FEED" {
		t.Errorf("principal = %q, want FEED (guid fallback)", got)
	}
}

func TestParseRegistrySkips(t *testing.T) {
	// A non-9A slot is skipped; an ed25519 line is skipped; only the 9A ecdsa
	// key survives.
	edpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edssh, err := ssh.NewPublicKey(edpub)
	if err != nil {
		t.Fatal(err)
	}
	edLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(edssh)), "\n") + " cn=ed\n"

	body := ecdsaLine(t, "slot=9D guid=AAAA cn=enc") + // explicit non-9A slot → skip
		edLine + // ed25519 → skip
		ecdsaLine(t, "guid=BBBB cn=keep") // the only keeper
	reg, err := ParseRegistry([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 || reg.entries[0].Principal != "keep" {
		t.Fatalf("expected only the 9A ecdsa key; len=%d principal=%q", reg.Len(),
			reg.entries[0].Principal)
	}
}

func TestParseRegistryEmpty(t *testing.T) {
	if _, err := ParseRegistry([]byte("# just a comment\n")); err == nil {
		t.Error("empty registry should error")
	}
}
