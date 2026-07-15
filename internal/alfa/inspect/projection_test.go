package inspect

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/papi"
)

// projectionServer serves anonymous /papi/forges + /papi/repos for the reconciliation
// check (data supplied as the raw JSON arrays, wrapped in the §4.2 envelope).
func projectionServer(forges, repos string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":`+forges+`,"meta":{"type":"forges","visibility":"public"}}`)
	})
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":`+repos+`,"meta":{"type":"repos","visibility":"public"}}`)
	})
	return httptest.NewServer(mux)
}

// hasShouldFail reports whether any point is a failing SHOULD verdict (reported but
// not tripping the exit code).
func hasShouldFail(pts []point) bool {
	for _, p := range pts {
		if !p.ok && p.reason == "" && !p.must {
			return true
		}
	}
	return false
}

// TestProjectionReconciled: repos resolve their forge and join a clone channel — no
// failures.
func TestProjectionReconciled(t *testing.T) {
	srv := projectionServer(
		`[{"id":"forgejo-krone","kind":"forgejo","base_url":"https://forge.example.com","ssh_clone":"ssh://git@forge.example.com:2222"}]`,
		`[{"name":"a","owner":"o","forge":"forgejo-krone","url":"https://forge.example.com/o/a"}]`,
	)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := projectionChecks(context.Background(), c)
	if hasShouldFail(pts) || hasMustFail(pts) {
		t.Fatalf("conformant projection should have no failures:\n%s", descs(pts))
	}
}

// TestProjectionDanglingForge: a repo names a forge absent from /papi/forges — a SHOULD
// failure (dangling provenance), not a hard MUST (the invariant is normative only once
// pinned in an RFC amendment, FDR-0011).
func TestProjectionDanglingForge(t *testing.T) {
	srv := projectionServer(
		`[{"id":"forgejo-krone","kind":"forgejo","base_url":"https://forge.example.com"}]`,
		`[{"name":"a","owner":"o","forge":"ghost","url":"https://github.com/o/a"}]`,
	)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := projectionChecks(context.Background(), c)
	if !hasShouldFail(pts) {
		t.Fatalf("a dangling forge should be a SHOULD failure:\n%s", descs(pts))
	}
	if hasMustFail(pts) {
		t.Errorf("projection drift should be SHOULD, not MUST (pending the amendment):\n%s", descs(pts))
	}
	if !strings.Contains(descs(pts), "resolves to a /papi/forges id") {
		t.Errorf("want the forge-resolution verdict:\n%s", descs(pts))
	}
}

// TestProjectionUnreachableClone: a repo whose forge carries no clone channel and whose
// own url has no host is unreachable — the papi#50 silent-omission class, flagged SHOULD.
func TestProjectionUnreachableClone(t *testing.T) {
	srv := projectionServer(
		`[{"id":"bare","kind":"bare","base_url":""}]`,
		`[{"name":"a","owner":"o","forge":"bare","url":""}]`,
	)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := projectionChecks(context.Background(), c)
	if !hasShouldFail(pts) {
		t.Fatalf("an unreachable repo should be a SHOULD failure:\n%s", descs(pts))
	}
	if !strings.Contains(descs(pts), "joins a clone channel") {
		t.Errorf("want the clone-channel verdict:\n%s", descs(pts))
	}
}

// TestProjectionCanonicalMissingMarker: a dual-homed repo (same owner/name on two forges)
// with no canonical:true is a MUST failure from the canonical check, even if the
// FDR-0011 projection checks pass.
func TestProjectionCanonicalMissingMarker(t *testing.T) {
	srv := projectionServer(
		`[{"id":"fj","kind":"forgejo","base_url":"https://forge.example.com","ssh_clone":"ssh://git@forge.example.com:2222"},
		  {"id":"gh","kind":"github","base_url":"https://github.com","ssh_clone":"ssh://git@github.com"}]`,
		`[{"name":"a","owner":"o","forge":"fj","url":"https://forge.example.com/o/a"},
		  {"name":"a","owner":"o","forge":"gh","url":"https://github.com/o/a"}]`,
	)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := projectionChecks(context.Background(), c)
	if !hasMustFail(pts) {
		t.Fatalf("dual-homed repo without canonical:true must be a MUST failure:\n%s", descs(pts))
	}
	if !strings.Contains(descs(pts), "canonical marker") {
		t.Errorf("want the canonical-marker verdict in output:\n%s", descs(pts))
	}
}

// TestProjectionCanonicalSuppressedByForgesFailure: the canonical-marker MUST check must
// run and emit a result even when /papi/forges is unavailable.
func TestProjectionCanonicalSuppressedByForgesFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/papi/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Two entries for the same owner/name with no canonical marker — a MUST violation.
		io.WriteString(w, `{"data":[
			{"name":"a","owner":"o","forge":"fj","url":"https://forge.example.com/o/a"},
			{"name":"a","owner":"o","forge":"gh","url":"https://github.com/o/a"}
		],"meta":{"type":"repos","visibility":"public"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pts := projectionChecks(context.Background(), c)
	if !hasMustFail(pts) {
		t.Fatalf("canonical MUST violation must be reported even when /papi/forges is down:\n%s", descs(pts))
	}
}
