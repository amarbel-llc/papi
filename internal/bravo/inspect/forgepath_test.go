package inspect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// forgePathPointsFor serves /papi/forges with one forge whose base_url is the
// test server itself, and answers git smart-HTTP discovery only for the paths
// in serves. It returns the §1.1 path_includes_identity verdicts.
func forgePathPointsFor(t *testing.T, pathIncludesIdentity *bool, serves ...string) []point {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/papi/forges", func(w http.ResponseWriter, _ *http.Request) {
		entry := map[string]any{"id": "f", "kind": "forgejo", "base_url": srv.URL, "identity": "alice"}
		if pathIncludesIdentity != nil {
			entry["path_includes_identity"] = *pathIncludesIdentity
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{entry}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for _, p := range serves {
			if r.URL.Path == p+"/info/refs" && r.URL.Query().Get("service") == "git-upload-pack" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		http.NotFound(w, r)
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	return forgePathIdentityChecks(context.Background(), c, []papi.Repo{{Name: "madder", Owner: "alice", Forge: "f"}})
}

func onePoint(t *testing.T, pts []point) point {
	t.Helper()
	if len(pts) != 1 {
		t.Fatalf("want one point, got %+v", pts)
	}
	return pts[0]
}

func TestForgePathDeclaredFreeServes(t *testing.T) {
	no := false
	p := onePoint(t, forgePathPointsFor(t, &no, "/madder.git"))
	if !p.ok || p.reason != "" {
		t.Fatalf("a declared identity-free forge serving <name>.git should pass, got %+v", p)
	}
}

func TestForgePathDeclaredFreeDoesNotServe(t *testing.T) {
	no := false
	p := onePoint(t, forgePathPointsFor(t, &no, "/alice/madder.git"))
	if p.ok || p.reason != "" || !strings.Contains(p.desc, "does not serve") {
		t.Fatalf("a false declaration should fail, got %+v", p)
	}
}

func TestForgePathConventionalServes(t *testing.T) {
	p := onePoint(t, forgePathPointsFor(t, nil, "/alice/madder.git"))
	if !p.ok || p.reason != "" {
		t.Fatalf("a conventional forge serving <identity>/<name>.git should pass, got %+v", p)
	}
}

// The motivating bug (papi#85): the forge is identity-free but says nothing.
func TestForgePathUndeclaredFreeFails(t *testing.T) {
	p := onePoint(t, forgePathPointsFor(t, nil, "/madder.git"))
	if p.ok || p.reason != "" || !strings.Contains(p.desc, "does not declare") {
		t.Fatalf("an undeclared identity-free forge should fail, got %+v", p)
	}
}

func TestForgePathNeitherServesSkips(t *testing.T) {
	p := onePoint(t, forgePathPointsFor(t, nil))
	if p.reason == "" {
		t.Fatalf("a forge serving neither path should skip, got %+v", p)
	}
}
