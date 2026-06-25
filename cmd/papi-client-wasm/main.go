//go:build !(js && wasm)

// Host/CLI entrypoint for papi-client-wasm (the package doc lives in dispatch.go).
// It reads one {fn, body} JSON request on stdin and writes the decoded JSON value
// on stdout (exit 0 ok, 2 on malformed input / unknown fn / decode error). The
// js/wasm build (export_js.go) is the primary target; this stdin/stdout form keeps
// the command runnable as a host CLI and lets the tests drive run()/dispatch()
// without a wasm host.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

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
