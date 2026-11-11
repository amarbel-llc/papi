// Package logingrant implements the login grant of RFC-0001 Amendment 29 (§5.2.1): a
// short canonical text, signed once by a registered slot-9A card key, that lets one
// ed25519 software key log in to the forward-auth verifier as one restricted principal
// for a bounded window.
//
// The package is pure: it parses, formats, signs and verifies bytes. Deciding whether
// a verifier honors a grant (registered card keys, allowed principals, deny list) is
// the verifier's job (internal/bravo/authproxy).
package logingrant

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/0/markl"
)

const (
	header = "papi login-grant v1"

	// maxTextBytes bounds a grant: it travels in a URL query, and nothing in it needs
	// more.
	maxTextBytes = 2048

	// MaxWindow is the longest not-before..expires span a grant may declare.
	MaxWindow = 168 * time.Hour

	// maxSessionSeconds bounds max-session: a login session never outlasts a day.
	maxSessionSeconds = 24 * 60 * 60

	timeLayout  = "2006-01-02T15:04:05Z"
	nonceBytes  = 16
	idBytes     = 16
	grantPrefix = "papi-login-grant-v1\n"
	loginPrefix = "papi-auth-soft-v1\n"
)

// fieldNames fixes the line order after the header.
var fieldNames = []string{"principal", "key", "domain", "not-before", "expires", "max-session", "nonce"}

var (
	principalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	domainRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
)

// Grant is a parsed login grant. Build and Parse are the only ways to obtain a
// validated one; Text and ID are derived from the fields, never stored, so a Grant
// cannot disagree with its own canonical text.
type Grant struct {
	Principal  string
	Key        ssh.PublicKey // ed25519 only
	Domain     string        // host[:port] the verifier binds signatures to
	NotBefore  time.Time
	Expires    time.Time // exclusive
	MaxSession time.Duration
	Nonce      string // base64url, 16 bytes
}

// Build validates g and returns its canonical text.
func Build(g Grant) ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	return g.Text(), nil
}

// Text renders the canonical grant text. It does not validate; use Build for that.
func (g Grant) Text() []byte {
	if g.Key == nil {
		return nil
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(g.Key)))
	var b strings.Builder
	b.WriteString(header + "\n")
	b.WriteString("principal: " + g.Principal + "\n")
	b.WriteString("key: " + key + "\n")
	b.WriteString("domain: " + g.Domain + "\n")
	b.WriteString("not-before: " + g.NotBefore.UTC().Format(timeLayout) + "\n")
	b.WriteString("expires: " + g.Expires.UTC().Format(timeLayout) + "\n")
	b.WriteString("max-session: " + strconv.FormatInt(int64(g.MaxSession/time.Second), 10) + "\n")
	b.WriteString("nonce: " + g.Nonce + "\n")
	return []byte(b.String())
}

// ID is the grant id: lowercase hex of the first 16 bytes of SHA-256 of the text.
func (g Grant) ID() string {
	sum := sha256.Sum256(g.Text())
	return hex.EncodeToString(sum[:idBytes])
}

func (g Grant) validate() error {
	if !principalRE.MatchString(g.Principal) {
		return fmt.Errorf("principal %q is not %s", g.Principal, principalRE)
	}
	if len(g.Domain) > 255 || !domainRE.MatchString(g.Domain) {
		return fmt.Errorf("domain %q is not a lowercase host[:port]", g.Domain)
	}
	if g.Key == nil || g.Key.Type() != ssh.KeyAlgoED25519 {
		return errors.New("key must be an ssh-ed25519 public key")
	}
	if g.NotBefore.Nanosecond() != 0 || g.Expires.Nanosecond() != 0 {
		return errors.New("not-before and expires must be whole seconds")
	}
	if !g.NotBefore.Before(g.Expires) {
		return errors.New("expires must be after not-before")
	}
	if g.Expires.Sub(g.NotBefore) > MaxWindow {
		return fmt.Errorf("window %s exceeds the %s maximum", g.Expires.Sub(g.NotBefore), MaxWindow)
	}
	if g.MaxSession%time.Second != 0 || g.MaxSession < time.Second ||
		g.MaxSession > maxSessionSeconds*time.Second {
		return fmt.Errorf("max-session must be 1..%d whole seconds", maxSessionSeconds)
	}
	raw, err := base64.RawURLEncoding.DecodeString(g.Nonce)
	if err != nil || len(raw) != nonceBytes || base64.RawURLEncoding.EncodeToString(raw) != g.Nonce {
		return fmt.Errorf("nonce must be %d bytes of unpadded base64url", nonceBytes)
	}
	return nil
}

// Parse is the strict inverse of Text: it accepts a byte string only if it equals the
// canonical rendering of the grant it describes.
func Parse(text []byte) (Grant, error) {
	if len(text) > maxTextBytes {
		return Grant{}, fmt.Errorf("grant is %d bytes, over the %d limit", len(text), maxTextBytes)
	}
	s := string(text)
	if !strings.HasSuffix(s, "\n") {
		return Grant{}, errors.New("grant must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) != len(fieldNames)+1 || lines[0] != header {
		return Grant{}, fmt.Errorf("grant must be %q plus exactly %d fields", header, len(fieldNames))
	}
	vals := make(map[string]string, len(fieldNames))
	for i, name := range fieldNames {
		v, ok := strings.CutPrefix(lines[i+1], name+": ")
		if !ok {
			return Grant{}, fmt.Errorf("line %d must start %q", i+2, name+": ")
		}
		vals[name] = v
	}

	key, err := parseKey(vals["key"])
	if err != nil {
		return Grant{}, err
	}
	notBefore, err := time.Parse(timeLayout, vals["not-before"])
	if err != nil {
		return Grant{}, fmt.Errorf("not-before: %w", err)
	}
	expires, err := time.Parse(timeLayout, vals["expires"])
	if err != nil {
		return Grant{}, fmt.Errorf("expires: %w", err)
	}
	seconds, err := strconv.ParseInt(vals["max-session"], 10, 64)
	if err != nil {
		return Grant{}, fmt.Errorf("max-session: %w", err)
	}
	if seconds < 0 || seconds > maxSessionSeconds {
		return Grant{}, fmt.Errorf("max-session must be 1..%d seconds", maxSessionSeconds)
	}
	g := Grant{
		Principal:  vals["principal"],
		Key:        key,
		Domain:     vals["domain"],
		NotBefore:  notBefore,
		Expires:    expires,
		MaxSession: time.Duration(seconds) * time.Second,
		Nonce:      vals["nonce"],
	}
	if err := g.validate(); err != nil {
		return Grant{}, err
	}
	if !bytes.Equal(g.Text(), text) {
		return Grant{}, errors.New("grant is not in canonical form")
	}
	return g, nil
}

// parseKey reads "ssh-ed25519 <base64>" with no comment.
func parseKey(v string) (ssh.PublicKey, error) {
	fields := strings.Split(v, " ")
	if len(fields) != 2 || fields[0] != ssh.KeyAlgoED25519 {
		return nil, errors.New("key must be exactly `ssh-ed25519 <base64>`")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	return pub, nil
}

// ValidAt reports whether now falls in [not-before, expires).
func (g Grant) ValidAt(now time.Time) error {
	if now.Before(g.NotBefore) {
		return errors.New("grant is not yet valid")
	}
	if !now.Before(g.Expires) {
		return errors.New("grant has expired")
	}
	return nil
}

// GrantPreimage is what the card signs: the domain-separation tag, then the text.
func GrantPreimage(text []byte) []byte {
	return append([]byte(grantPrefix), text...)
}

// LoginPreimage is what the software key signs for one login. Its tag differs from the
// card login's papi-auth-v1, and it is bound to the grant id, so a signature made for
// one purpose or one grant is never valid for another.
func LoginPreimage(domain, nonce, grantID string) []byte {
	return []byte(loginPrefix + domain + "\n" + nonce + "\n" + grantID)
}

// CardSigner signs bytes with the slot-9A key of the card identified by guid, returning
// raw r‖s. It is structurally the same seam as signchallenge.Signer.
type CardSigner interface {
	SignSlot9A(ctx context.Context, guid string, msg []byte) (rs []byte, err error)
}

// SignGrant signs the grant text with the card and returns the signature as a
// papi-login-grant-sig-v1 markl id.
func SignGrant(ctx context.Context, signer CardSigner, guid string, text []byte) (string, error) {
	if _, err := Parse(text); err != nil {
		return "", fmt.Errorf("refusing to sign a malformed grant: %w", err)
	}
	rs, err := signer.SignSlot9A(ctx, guid, GrantPreimage(text))
	if err != nil {
		return "", fmt.Errorf("slot-9A sign of the grant: %w", err)
	}
	return markl.Build(markl.PurposeLoginGrantSig, markl.FormatEcdsaP256Sig, rs)
}

// VerifyGrantSig checks sigMarkl over the grant text under a card public key.
func VerifyGrantSig(pub *ecdsa.PublicKey, text []byte, sigMarkl string) error {
	id, err := markl.Parse(sigMarkl)
	if err != nil {
		return fmt.Errorf("parse grant signature: %w", err)
	}
	if id.Purpose != markl.PurposeLoginGrantSig || id.Format != markl.FormatEcdsaP256Sig {
		return fmt.Errorf("signature is %s/%s, want %s/%s",
			id.Purpose, id.Format, markl.PurposeLoginGrantSig, markl.FormatEcdsaP256Sig)
	}
	if len(id.Payload) != 64 {
		return fmt.Errorf("signature payload is %d bytes, want 64", len(id.Payload))
	}
	digest := sha256.Sum256(GrantPreimage(text))
	r := new(big.Int).SetBytes(id.Payload[:32])
	s := new(big.Int).SetBytes(id.Payload[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("grant signature does not verify")
	}
	return nil
}

// EncodeSig / DecodeSig carry a raw ed25519 login signature as unpadded base64url.
func EncodeSig(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// SignLogin signs the login preimage with a software key held in memory.
func SignLogin(priv ed25519.PrivateKey, domain, nonce, grantID string) string {
	return EncodeSig(ed25519.Sign(priv, LoginPreimage(domain, nonce, grantID)))
}

// VerifyLogin checks the software key's login signature for this grant.
func (g Grant) VerifyLogin(domain, nonce, sig string) error {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("login signature is not 64 bytes of unpadded base64url")
	}
	ck, ok := g.Key.(ssh.CryptoPublicKey)
	if !ok {
		return errors.New("grant key has no crypto public key")
	}
	pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return errors.New("grant key is not ed25519")
	}
	if !ed25519.Verify(pub, LoginPreimage(domain, nonce, g.ID()), raw) {
		return errors.New("login signature does not verify")
	}
	return nil
}

// EncodeText / DecodeText carry grant text in a URL query as unpadded base64url.
func EncodeText(text []byte) string { return base64.RawURLEncoding.EncodeToString(text) }

// DecodeText reverses EncodeText, refusing anything over the size limit before it
// allocates.
func DecodeText(s string) ([]byte, error) {
	if len(s) > base64.RawURLEncoding.EncodedLen(maxTextBytes) {
		return nil, fmt.Errorf("grant text is over the %d byte limit", maxTextBytes)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("grant text: %w", err)
	}
	return raw, nil
}
