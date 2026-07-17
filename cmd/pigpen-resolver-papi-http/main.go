// Command pigpen-resolver-papi-http is the "papi-http" pigpen-resolver
// plugin ratified by piggy RFC 0010 (papi#54, piggy#216): the artifact piggy
// PATH-discovers and invokes when it needs to resolve a self-signed pigpen
// document (RFC-0001 §14) for a domain whose kind is "papi-http".
//
// piggy's own resolver-plugin contract (RFC 0010 §6) fixes the invocation
// shape exactly:
//
//	pigpen-resolver-papi-http resolve <locator>
//
// where <locator> is a bare domain or URL identifying the papi origin (the
// same shape papi.NewClient accepts). This binary:
//
//   - never reads stdin;
//   - on success, writes the resolved pigpen-v1 document bytes to stdout,
//     verbatim, and nothing else, then exits 0;
//   - on any failure (malformed argv, an unreachable origin, a missing or
//     unverifiable /papi/pigpen document, ...), writes a free-text
//     diagnostic to stderr and exits 1 — a single exit code for every
//     failure class, since piggy's contract only discriminates zero/non-zero
//     (no finer-grained code has a consumer on the piggy side).
//
// Diagnostics are NOT self-prefixed with "pigpen-resolver-papi-http:" —
// piggy already wraps a failing resolver's stderr with its own
// kind="papi-http"/locator="..." context, so a repeated self-label here
// would just double up. This mirrors cmd/papi-verify-wasm's convention (no
// self-prefix there either).
//
// The actual fetch-verify-passthrough work is entirely
// internal/alfa/inspect.ResolvePigpen; this binary is a thin argv/exit-code
// shim around it. See docs/rfcs/0001-personal-api-papi-wire-format.md §14
// for the pigpen document's wire format and self-signature scheme, and
// docs/plans/2026-07-17-pigpen-resolver-papi-http.md for this binary's own
// design/task breakdown (papi#54 Task C3).
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/amarbel-llc/papi/internal/0/papi"
	"github.com/amarbel-llc/papi/internal/alfa/inspect"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "resolve" {
		fmt.Fprintln(stderr, "usage: pigpen-resolver-papi-http resolve <locator>")
		return 1
	}

	c, err := papi.NewClient(args[1])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	doc, err := inspect.ResolvePigpen(context.Background(), c)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if _, err := stdout.Write(doc); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
