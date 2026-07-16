//go:build !wasip1 && !(js && wasm)

// The hyphence import below pulls in purse-first/libs/dewey transitively,
// which has no wasip1/js-wasm implementation of its OS-file-attribute
// syscall wrapper (setUserChanges in dewey's internal/delta/files package).
// internal/alfa/inspect is imported wholesale by both cmd/papi-verify-wasm
// (GOOS=wasip1) and cmd/papi-client-wasm (GOOS=js GOARCH=wasm), and Go
// compiles every file in an imported package for the target platform even
// when its exported symbols go uncalled — so this file (and its
// hyphence/dewey dependency) must stay out of both wasm builds until
// nothing outside inspect calls parsePigpenMetadataLines under those
// targets (see `just build-wasm` / `just build-wasm-client`).
package inspect

import (
	"bytes"

	"github.com/amarbel-llc/hyphence/go/hyphence"
)

// parsePigpenMetadataLines decodes the metadata section of a hyphence
// document (RFC 0001) into its ordered []MetadataLine, discarding any
// body bytes that follow the closing boundary. This is deliberately a
// thin wrapper around hyphence's own machinery — hyphence.Reader
// driving hyphence.MetadataBuilder (the same pairing hyphence's own
// `hyphence format` subcommand uses) — with no pigpen-specific
// interpretation of the lines. That interpretation (locating the
// `piggy-recipient-v1@...` and `! pigpen-v1` lines, verifying the
// provisional self-signature) is Task B3.
func parsePigpenMetadataLines(data []byte) ([]hyphence.MetadataLine, error) {
	doc := &hyphence.Document{}
	reader := hyphence.Reader{
		RequireMetadata: true,
		Metadata:        &hyphence.MetadataBuilder{Doc: doc},
		Blob:            &hyphence.CountingDiscardReaderFrom{},
	}

	if _, err := reader.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, err
	}

	return doc.Metadata, nil
}
