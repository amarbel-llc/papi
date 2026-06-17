package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// conformantServer is a hermetic, RFC-0001-conformant PAPI fixture: an enveloped
// discovery doc, a projected /papi with no acl leak and meta.visibility=public,
// the two text endpoints, and auth endpoints returning the specified error
// codes. Its resource links are http:// (httptest is plaintext), which is a
// SHOULD violation, not a MUST — so Run still passes.
func conformantServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"version":"papi/v0","handle":"tester",
			"resources":{"document":%q,"piggy_ids":%q,"ssh_authorized_keys":%q},
			"auth":{"scheme":"piggy-challenge-response"}},"meta":{"type":"papi-discovery","count":3}}`,
			base+"/papi", base+"/papi/piggy-ids", base+"/papi/ssh-authorized-keys")
	})
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"version":"papi/v0",
			"person":{"handle":"tester","name":"Test User"},
			"piggy":{"encryption_recipients":[{"id":"r1"}],"ssh_authorized_keys":[{"key":"k1"},{"key":"k2"}]},
			"forges":[{"id":"gh","kind":"github","repos":[{},{}]}],
			"templates":[{"id":"eng","flakeref":"github:x/y#eng"}]},
			"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`)
	})
	mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "# piggy-ids\npiggy-recipient-v1@pivy_ecdh_p256_pub-aaa\n")
	})
	mux.HandleFunc("/papi/ssh-authorized-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ecdsa-sha2-nistp256 AAAAfake tester\n")
	})
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if s, _ := m["recipient"].(string); s != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	return httptest.NewServer(mux)
}

func TestRunConformant(t *testing.T) {
	srv := conformantServer()
	defer srv.Close()

	var buf bytes.Buffer
	if err := Run(context.Background(), &buf, srv.URL, Options{}); err != nil {
		t.Fatalf("Run on a conformant fixture: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("want a multi-record stream, got %d line(s):\n%s", len(lines), buf.String())
	}

	var sawHeader, sawPlan, sawSummary, summaryValid bool
	var descriptions []string
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i, err, line)
		}
		switch rec["type"] {
		case "crap":
			if i != 0 {
				t.Errorf("crap header at line %d, want 0", i)
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

	if !sawHeader || !sawPlan || !sawSummary || !summaryValid {
		t.Errorf("header=%v plan=%v summary=%v valid=%v", sawHeader, sawPlan, sawSummary, summaryValid)
	}

	joined := strings.Join(descriptions, "\n")
	for _, want := range []string{
		`handle "tester"`,
		"Test User",
		"1 encryption recipient(s), 2 ssh key(s)",
		"forges: 1 (github/gh) with 2 repo(s)",
		"templates: 1 (eng)",
		"http://",                             // insecure-resource fact (§4.1 / linenisgreat#26)
		"strips acl",                          // conformance verdict (§2.6)
		"{data,meta}, meta.visibility=public", // envelope verdict (§4.2)
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("stream missing %q in:\n%s", want, joined)
		}
	}
}
