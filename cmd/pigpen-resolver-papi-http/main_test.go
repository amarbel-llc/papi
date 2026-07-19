package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/alfa/pigpenfixture"
)

func TestRunArgvValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"empty args", []string{}},
		{"resolve with no locator", []string{"resolve"}},
		{"resolve with extra arg", []string{"resolve", "http://example.com", "extra"}},
		{"wrong verb", []string{"wrong", "http://example.com"}},
		{"locator only, no verb", []string{"http://example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout must be empty on a usage error, got %q", stdout.String())
			}
			if !strings.Contains(strings.ToLower(stderr.String()), "usage") {
				t.Errorf("stderr must contain a usage diagnostic, got %q", stderr.String())
			}
			if strings.HasPrefix(stderr.String(), "pigpen-resolver-papi-http:") {
				t.Errorf("stderr must not carry a self-prefix, got %q", stderr.String())
			}
		})
	}
}

// TestRunClientConstructionFailure covers the papi.NewClient(args[1]) error
// path: a locator that fails to normalize into a base URL at all (distinct
// from a locator that normalizes fine but fails to resolve over HTTP,
// covered by TestRunResolveFailure below).
func TestRunClientConstructionFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", ""}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr must contain the underlying failure reason, got empty stderr")
	}
	if strings.HasPrefix(stderr.String(), "pigpen-resolver-papi-http:") {
		t.Errorf("stderr must not carry a self-prefix, got %q", stderr.String())
	}
}

// TestRunResolveFailure covers inspect.ResolvePigpen's own error path: a
// reachable server that simply doesn't implement /papi/pigpen (404) — the
// simplest, cheapest failure fixture that doesn't require building any
// signed-document bytes. ResolvePigpen's full range of failure classes
// (unsigned, invalid signature, malformed lock, unpublished key, etc.) is
// already exhaustively covered by internal/alfa/inspect/pigpen_test.go; this
// test only needs to prove run() correctly surfaces *a* ResolvePigpen error
// to stderr with exit 1.
func TestRunResolveFailure(t *testing.T) {
	srv := httptest.NewServer(http.NewServeMux()) // no routes registered -> 404 on everything
	t.Cleanup(srv.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", srv.URL}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "404") {
		t.Errorf("stderr must contain the underlying failure reason (HTTP 404), got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), srv.URL) {
		t.Errorf("stderr should embed the locator %q (from ResolvePigpen's own error), got %q", srv.URL, stderr.String())
	}
	if strings.HasPrefix(stderr.String(), "pigpen-resolver-papi-http:") {
		t.Errorf("stderr must not carry a self-prefix, got %q", stderr.String())
	}
}

// TestRunSuccess is the end-to-end happy path: correct argv against a
// fixture (internal/alfa/pigpenfixture, shared with the root papi CLI's own
// `pigpen resolve` test suite) serving a genuinely self-signed pigpen
// document -> exit 0, stdout equal to the exact document bytes, stderr
// empty.
func TestRunSuccess(t *testing.T) {
	srv, doc := pigpenfixture.NewServer(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", srv.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr must be empty on success, got %q", stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), doc) {
		t.Errorf("stdout must equal the resolved document bytes exactly:\ngot:  %q\nwant: %q", stdout.Bytes(), doc)
	}
}
