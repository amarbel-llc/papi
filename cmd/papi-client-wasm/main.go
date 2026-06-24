// Command papi-client-wasm exposes papi's network-free client core (FDR-0007) as
// a WASI (wasip1) module: it decodes RFC-0001 wire bodies a caller already
// fetched (the TypeScript wrapper does the HTTP), so JS/zx consumers reuse papi's
// Go parsing instead of re-deriving the wire format. Like papi-verify-wasm
// (FDR-0002) it imports no TUI subtree, so it cross-compiles under
// `GOOS=wasip1 GOARCH=wasm` (see `just build-wasm-client`), and the same source
// builds as an ordinary host CLI, which keeps it under host `go build ./...`.
//
// It reads one JSON request on stdin and writes the decoded JSON on stdout:
//
//	stdin:  {"fn": "decode_document", "body": "<raw GET /papi body, enveloped or not>"}
//	stdout: {<decoded Document>}
//
// fn ∈ {decode_document, decode_discovery, decode_repos, decode_profiles,
// decode_caches}. Exit code: 0 ok, 2 malformed input / unknown fn / decode error.
// It performs no network I/O (a wasip1 module has no sockets): the caller fetches
// the body and passes it in.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/amarbel-llc/papi/internal/0/papi"
)

// request is the stdin envelope: a function selector and the raw endpoint body.
type request struct {
	Fn   string `json:"fn"`
	Body string `json:"body"`
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
		fmt.Fprintln(stderr, "stdin is not a {fn, body} JSON object:", err)
		return 2
	}
	out, err := dispatch(req)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", req.Fn, err)
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintln(stderr, "encode:", err)
		return 2
	}
	return 0
}

// dispatch decodes the request body with the pure papi decoder named by fn.
func dispatch(req request) (any, error) {
	body := []byte(req.Body)
	switch req.Fn {
	case "decode_document":
		doc, _, err := papi.DecodeDocument(body)
		return doc, err
	case "decode_discovery":
		return papi.DecodeDiscovery(body)
	case "decode_repos":
		return papi.DecodeRepos(body)
	case "decode_profiles":
		return papi.DecodeProfiles(body)
	case "decode_caches":
		return papi.DecodeCaches(body)
	default:
		return nil, fmt.Errorf("unknown fn (want decode_document|decode_discovery|decode_repos|decode_profiles|decode_caches)")
	}
}
