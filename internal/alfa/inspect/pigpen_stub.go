//go:build wasip1 || (js && wasm)

// This file provides a no-op pigpenSignaturePoints for wasip1/js-wasm builds.
// The real implementation (pigpen.go) is excluded from those targets — it
// transitively imports hyphence, which pulls in purse-first/libs/dewey (no
// wasip1/js-wasm implementation of its OS-file-attribute syscall wrapper; see
// pigpen.go's own header comment). Run (inspect.go) carries no build tag of
// its own — it compiles into both wasm targets because cmd/papi-verify-wasm
// and cmd/papi-client-wasm both import package inspect wholesale — and it
// calls pigpenSignaturePoints directly as part of its checklist. Go compiles
// every file in an imported package for the target platform even when a
// symbol goes uncalled from that target's actual entrypoint, so
// pigpenSignaturePoints must exist as a symbol under every target inspect.go
// compiles for, even though neither wasm entrypoint (papi-verify-wasm's
// VerifyReceiptWithPublishedIDs path, papi-client-wasm's
// VerifyDocumentWithPublishedIDs path) ever calls Run itself.
package inspect

import (
	"context"

	"code.linenisgreat.com/papi/internal/0/papi"
)

// pigpenSignaturePoints is a no-op stub under wasip1/js-wasm builds; see this
// file's header comment for why. It contributes no points to Run's checklist.
func pigpenSignaturePoints(_ context.Context, _ *papi.Client) []point {
	return nil
}
