//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"code.linenisgreat.com/hyphence/go/hyphence"
	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// HyphenceSigner signs msg with the slot-9A key of the card identified by guid,
// returning the raw 64-byte r‖s ECDSA P-256 signature. msg is the bare signing
// input, not a pre-hash: the card (or agent) hashes SHA-256 itself.
type HyphenceSigner interface {
	SignSlot9A(ctx context.Context, guid string, msg []byte) (rs []byte, err error)
}

// PigpenSigner predates the generic signer and is kept so existing callers compile.
type PigpenSigner = HyphenceSigner

var (
	ErrHyphenceUnsigned         = errors.New("document carries no signature line for the purpose")
	ErrHyphenceSigMalformed     = errors.New("signature line is not a well-formed ecdsa_p256_sig markl-id")
	ErrHyphenceNoPublishedKey   = errors.New("domain publishes no piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub key to verify against")
	ErrHyphenceSigInvalid       = errors.New("signature does not verify against any published slot-9A key")
	ErrHyphenceAlreadySigned    = errors.New("document already carries a signature line for the purpose; refusing to overwrite")
	ErrHyphenceNoTypeLine       = errors.New("document has no `!` type line to insert the signature line before")
	ErrHyphenceMultipleSigLines = errors.New("document carries more than one signature line for the purpose")
)

// validateHyphenceSigPurpose rejects purposes that could not round-trip as the
// `purpose@` decoration of a markl-id.
func validateHyphenceSigPurpose(purpose string) error {
	if purpose == "" || strings.ContainsAny(purpose, "@ \t\n") {
		return fmt.Errorf("invalid signature purpose %q", purpose)
	}
	return nil
}

// parseHyphenceDocument splits a hyphence document into its metadata lines and
// its body bytes (everything after the blank separator line; nil when absent).
func parseHyphenceDocument(data []byte) ([]hyphence.MetadataLine, []byte, error) {
	doc := &hyphence.Document{}
	var body bytes.Buffer
	reader := hyphence.Reader{
		RequireMetadata: true,
		Metadata:        &hyphence.MetadataBuilder{Doc: doc},
		Blob:            &body,
	}
	if _, err := reader.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, nil, err
	}
	return doc.Metadata, body.Bytes(), nil
}

func isHyphenceSigLine(l hyphence.MetadataLine, purpose string) bool {
	return l.Prefix == '-' && strings.HasPrefix(l.Value, purpose+"@")
}

// HyphenceStripSelfBytes is the signed input for a hyphence document signature
// under purpose: the metadata with every `-` line carrying that purpose removed,
// canonicalized and re-emitted by hyphence's FormatBodyEmitter, which appends the
// blank separator line and the body bytes verbatim when body is non-empty. With
// an empty body this is byte-identical to the payload-less §14.2 pigpen input.
func HyphenceStripSelfBytes(lines []hyphence.MetadataLine, body []byte, purpose string) ([]byte, error) {
	stripped := make([]hyphence.MetadataLine, 0, len(lines))
	for _, l := range lines {
		if isHyphenceSigLine(l, purpose) {
			continue
		}
		stripped = append(stripped, l)
	}
	return emitHyphence(stripped, body)
}

func emitHyphence(lines []hyphence.MetadataLine, body []byte) ([]byte, error) {
	doc := &hyphence.Document{Metadata: lines}
	var buf bytes.Buffer
	emitter := &hyphence.FormatBodyEmitter{Doc: doc, Out: &buf}
	if _, err := emitter.ReadFrom(bytes.NewReader(body)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SignHyphence signs a hyphence document, body included, under purpose and
// returns it re-emitted canonically with a `- <purpose>@ecdsa_p256_sig-…` line
// inserted immediately before the `!` type line.
func SignHyphence(ctx context.Context, signer HyphenceSigner, guid, purpose string, data []byte) ([]byte, error) {
	if err := validateHyphenceSigPurpose(purpose); err != nil {
		return nil, err
	}
	lines, body, err := parseHyphenceDocument(data)
	if err != nil {
		return nil, fmt.Errorf("hyphence: sign: parse document: %w", err)
	}

	typeLineIdx := -1
	for i, l := range lines {
		if isHyphenceSigLine(l, purpose) {
			return nil, ErrHyphenceAlreadySigned
		}
		if l.Prefix == '!' && typeLineIdx < 0 {
			typeLineIdx = i
		}
	}
	if typeLineIdx < 0 {
		return nil, ErrHyphenceNoTypeLine
	}

	input, err := HyphenceStripSelfBytes(lines, body, purpose)
	if err != nil {
		return nil, fmt.Errorf("hyphence: sign: reconstruct signed input: %w", err)
	}
	raw, err := signer.SignSlot9A(ctx, guid, input)
	if err != nil {
		return nil, fmt.Errorf("hyphence: sign: %w", err)
	}
	sigID, err := markl.Build(purpose, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		return nil, fmt.Errorf("hyphence: sign: build signature markl-id: %w", err)
	}

	signed := make([]hyphence.MetadataLine, 0, len(lines)+1)
	signed = append(signed, lines[:typeLineIdx]...)
	signed = append(signed, hyphence.MetadataLine{Prefix: '-', Value: sigID})
	signed = append(signed, lines[typeLineIdx:]...)

	out, err := emitHyphence(signed, body)
	if err != nil {
		return nil, fmt.Errorf("hyphence: sign: re-encode signed document: %w", err)
	}
	return out, nil
}

// VerifyHyphenceSignature verifies data's signature under purpose against every
// slot-9A key in publishedIDs (the bare ids of /papi/piggy-ids), returning the
// markl-id of the key that verified.
func VerifyHyphenceSignature(data []byte, purpose string, publishedIDs []string) (string, error) {
	return verifyHyphence(data, purpose, func() []string { return publishedIDs })
}

// verifyHyphence calls fetchPublishedIDs only once a well-formed signature line
// is found, so malformed or unsigned documents cost no /papi/piggy-ids fetch.
func verifyHyphence(data []byte, purpose string, fetchPublishedIDs func() []string) (string, error) {
	if err := validateHyphenceSigPurpose(purpose); err != nil {
		return "", err
	}
	lines, body, err := parseHyphenceDocument(data)
	if err != nil {
		return "", fmt.Errorf("parse document: %w", err)
	}

	var sigValue string
	for _, l := range lines {
		if !isHyphenceSigLine(l, purpose) {
			continue
		}
		if sigValue != "" {
			return "", ErrHyphenceMultipleSigLines
		}
		sigValue = l.Value
	}
	if sigValue == "" {
		return "", ErrHyphenceUnsigned
	}
	sigID, err := markl.Parse(sigValue)
	if err != nil || sigID.Purpose != purpose || sigID.Format != markl.FormatEcdsaP256Sig {
		return "", ErrHyphenceSigMalformed
	}

	input, err := HyphenceStripSelfBytes(lines, body, purpose)
	if err != nil {
		return "", fmt.Errorf("reconstruct signed input: %w", err)
	}

	if len(sigID.Payload) != 64 {
		return "", ErrHyphenceSigMalformed
	}
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sigID.Payload[:32])
	s := new(big.Int).SetBytes(sigID.Payload[32:])

	sawKey := false
	for _, id := range fetchPublishedIDs() {
		keyID, err := markl.Parse(id)
		if err != nil || keyID.Purpose != markl.PurposePIVAuth || keyID.Format != markl.FormatSSHEcdsaNistp256Pub {
			continue
		}
		pub, err := p256FromCompressed(keyID.Payload)
		if err != nil {
			continue
		}
		sawKey = true
		if ecdsa.Verify(pub, digest[:], r, s) {
			return id, nil
		}
	}
	if !sawKey {
		return "", ErrHyphenceNoPublishedKey
	}
	return "", ErrHyphenceSigInvalid
}

// VerifyHyphenceForDomain verifies data against c's live /papi/piggy-ids.
func VerifyHyphenceForDomain(ctx context.Context, c *papi.Client, data []byte, purpose string) (string, error) {
	return verifyHyphence(data, purpose, func() []string { return fetchPiggyAuthIDs(ctx, c) })
}

// ResolveHyphence fetches path from c, verifies its signature under purpose
// against the domain's live /papi/piggy-ids, and returns the fetched bytes
// unmodified. Every failure, including an unsigned document, is an error.
func ResolveHyphence(ctx context.Context, c *papi.Client, path, purpose string) ([]byte, error) {
	resp, err := c.Fetch(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("hyphence: resolve %s%s: fetch failed: %w", c.BaseURL, path, err)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("hyphence: resolve %s%s: unexpected HTTP %d", c.BaseURL, path, resp.Status)
	}
	if _, err := VerifyHyphenceForDomain(ctx, c, resp.Body, purpose); err != nil {
		return nil, fmt.Errorf("hyphence: resolve %s%s: %w", c.BaseURL, path, err)
	}
	return resp.Body, nil
}
