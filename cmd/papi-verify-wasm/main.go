// Command papi-verify-wasm is the network-free enrollment-receipt verifier
// (FDR-0002), built to expose papi's verification core as a WASI (wasip1) module.
// It lets a host without a Go binary — e.g. site-linenisgreat verifying receipts
// natively through a php-wasm runtime — run the same self_proof + attestation
// checks as `papi verify-receipt`, but against keys the caller already holds
// (its own /papi/piggy-ids) rather than fetching them, so it needs no network.
//
// It imports only internal/alfa/inspect (+ stdlib) — never the enroll TUI — so it
// cross-compiles cleanly under `GOOS=wasip1 GOARCH=wasm` (see `just build-wasm`).
// The same source also builds as an ordinary host CLI, which is what keeps it
// under host `go vet` / `go build ./...`.
//
// It reads one JSON envelope on stdin and writes the verdict JSON on stdout:
//
//	stdin:  {"receipt": {<papi-enroll-receipt-v1>}, "published_ids": ["piggy-piv_auth-v1@…", …]}
//	stdout: {"ok": true, "checks": [{"name":"self_proof","ok":true,"detail":"…"}, …]}
//
// published_ids may be the domain's whole piggy-ids list — non-slot-9A entries
// (the piggy-recipient-v1 9D keys) are ignored. Exit code: 0 verified, 1 a check
// failed, 2 malformed input.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"code.linenisgreat.com/papi/internal/alfa/inspect"
)

// request is the stdin envelope. Receipt is held as RawMessage so the receipt's
// exact bytes reach the verifier (its canonical form is recomputed via JCS, so
// this is belt-and-suspenders).
type request struct {
	Receipt      json.RawMessage `json:"receipt"`
	PublishedIDs []string        `json:"published_ids"`
}

func main() { os.Exit(run(os.Stdin, os.Stdout, os.Stderr)) }

func run(stdin io.Reader, stdout, stderr io.Writer) int {
	in, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read stdin:", err)
		return 2
	}
	var req request
	if err := json.Unmarshal(in, &req); err != nil {
		fmt.Fprintln(stderr, "stdin is not a {receipt, published_ids} JSON object:", err)
		return 2
	}
	if len(req.Receipt) == 0 {
		fmt.Fprintln(stderr, `stdin envelope is missing the "receipt" field`)
		return 2
	}
	res, err := inspect.VerifyReceiptWithPublishedIDs(req.Receipt, req.PublishedIDs)
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(res); err != nil {
		fmt.Fprintln(stderr, "encode verdict:", err)
		return 2
	}
	if !res.OK {
		return 1
	}
	return 0
}
