package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// papiServer is a hermetic PAPI fixture: an enveloped discovery doc (mirroring
// the reference impl, including an http:// resource link) plus a projected
// document.
func papiServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"version":"papi/v0","handle":"tester",
			"resources":{"document":"http://example.test/papi","forges":"https://example.test/papi/forges"},
			"auth":{"scheme":"piggy-challenge-response"}},"meta":{"type":"papi-discovery","count":2}}`))
	})
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"version":"papi/v0",
			"person":{"handle":"tester","name":"Test User"},
			"piggy":{"encryption_recipients":[{"id":"r1"}],"ssh_authorized_keys":[{"key":"k1"},{"key":"k2"}]},
			"forges":[{"id":"gh","kind":"github","repos":[{},{}]}],
			"templates":[{"id":"eng","flakeref":"github:x/y#eng"}]},"meta":{"type":"papi"}}`))
	})
	return httptest.NewServer(mux)
}

func TestRunEmitsValidNdjsonCrap(t *testing.T) {
	srv := papiServer()
	defer srv.Close()

	var buf bytes.Buffer
	if err := Run(context.Background(), &buf, srv.URL); err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("want a multi-record stream, got %d line(s):\n%s", len(lines), buf.String())
	}

	var (
		sawHeader, sawPlan, sawSummary bool
		descriptions                   []string
		summaryValid                   bool
	)
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i, err, line)
		}
		switch rec["type"] {
		case "crap":
			if i != 0 {
				t.Errorf("crap header at line %d, want line 0", i)
			}
			sawHeader = true
		case "plan":
			sawPlan = true
		case "test":
			if d, ok := rec["description"].(string); ok {
				descriptions = append(descriptions, d)
			}
		case "summary":
			if sawSummary {
				t.Error("more than one summary record")
			}
			sawSummary = true
			summaryValid, _ = rec["valid"].(bool)
		}
	}

	if !sawHeader || !sawPlan || !sawSummary {
		t.Errorf("header=%v plan=%v summary=%v", sawHeader, sawPlan, sawSummary)
	}
	if !summaryValid {
		t.Error("summary.valid = false, want true")
	}

	joined := strings.Join(descriptions, "\n")
	for _, want := range []string{
		`handle "tester"`,
		"Test User",
		"1 encryption recipient(s), 2 ssh key(s)",
		"forges: 1 (github/gh) with 2 repo(s)",
		"http://", // the insecure-resource fact (RFC §4.1 / linenisgreat#26)
		"templates: 1 (eng)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("introspection missing %q in:\n%s", want, joined)
		}
	}
}
