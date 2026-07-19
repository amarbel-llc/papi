// Command papi-client-wasm exposes papi's network-free client core (FDR-0007) to
// JS/zx consumers: it decodes RFC-0001 wire bodies a caller already fetched (the
// TypeScript wrapper does the HTTP), so JS reuses papi's Go parsing instead of
// re-deriving the wire format. Like papi-verify-wasm (FDR-0002) it imports no TUI
// subtree, so it cross-compiles to WASM.
//
// The primary build target is js/wasm (GOOS=js GOARCH=wasm), driven via Go's
// canonical wasm_exec.js loader. The earlier wasip1 target was dropped because
// Bun's node:wasi cannot instantiate a Go wasip1 module (it OOBs at start() on
// every Bun through 1.4.0-canary.1; see FDR-0007). The js/wasm build registers a
// synchronous `papiCall(reqJSON) -> resJSON` global (export_js.go); the same
// source still builds as an ordinary host CLI (main.go) over stdin/stdout, which
// keeps it under host `go build ./...` and exercises dispatch() in tests.
//
// The request envelope, on either entrypoint:
//
//	{"fn": "decode_document", "body": "<raw GET /papi body, enveloped or not>"}
//
// fn ∈ {decode_document, decode_discovery, decode_repos, decode_profiles,
// decode_caches, verify_document}. verify_document additionally takes
// "published_ids" (the domain's /papi/piggy-ids slot-9A markl-ids, the §10 trust
// anchor). No network I/O happens here: the caller fetches the body and passes it
// in.
package main

import (
	"encoding/json"
	"fmt"

	"code.linenisgreat.com/papi/internal/0/papi"
	"code.linenisgreat.com/papi/internal/alfa/inspect"
)

// request is the wire envelope: a function selector and the raw endpoint body.
type request struct {
	Fn   string `json:"fn"`
	Body string `json:"body"`
	// PublishedIDs are the domain's published slot-9A markl-ids (its
	// /papi/piggy-ids), supplied for verify_document (the RFC-0001 §10.1 trust
	// anchor; the verifier takes keys from here, never the document itself).
	PublishedIDs []string `json:"published_ids,omitempty"`
}

// response is the JS-facing result envelope. syscall/js cannot surface a Go
// error, so dispatchJSON encodes failures as {ok:false, error} rather than
// throwing; the TS wrapper rethrows on !ok.
type response struct {
	OK    bool   `json:"ok"`
	Value any    `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
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
	case "verify_document":
		data, _, err := papi.DecodeEnvelope(body)
		if err != nil {
			return nil, err
		}
		return inspect.VerifyDocumentWithPublishedIDs(data, req.PublishedIDs)
	default:
		return nil, fmt.Errorf("unknown fn (want decode_document|decode_discovery|decode_repos|decode_profiles|decode_caches|verify_document)")
	}
}

// dispatchJSON parses a {fn, body} request and returns the JSON-encoded response
// envelope. It never returns an error: malformed input, unknown fn, and decode
// failures are all encoded as {ok:false, error}. This is the js/wasm call path.
func dispatchJSON(reqBytes []byte) []byte {
	var req request
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return encodeResponse(response{Error: fmt.Sprintf("request is not a {fn, body} JSON object: %v", err)})
	}
	out, err := dispatch(req)
	if err != nil {
		return encodeResponse(response{Error: fmt.Sprintf("%s: %v", req.Fn, err)})
	}
	return encodeResponse(response{OK: true, Value: out})
}

// encodeResponse marshals the envelope, degrading to a hand-rolled error envelope
// if the decoded value somehow fails to marshal (it never should).
func encodeResponse(r response) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		return []byte(`{"ok":false,"error":"encode response failed"}`)
	}
	return b
}
