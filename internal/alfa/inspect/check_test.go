package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/0/papi"
)

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("bad fixture JSON: %v", err)
	}
	return v
}

func TestFindACL(t *testing.T) {
	leak := mustJSON(t, `{"data":{"person":{"contact":{"acl":["x"],"email":"e"}}}}`)
	if at := findACL(leak); at == "" {
		t.Error("findACL missed a nested acl key")
	}
	clean := mustJSON(t, `{"data":{"person":{"handle":"x"}},"meta":{"type":"papi"}}`)
	if at := findACL(clean); at != "" {
		t.Errorf("findACL false positive at %q", at)
	}
	listLeak := mustJSON(t, `{"data":{"forges":[{"id":"a"},{"id":"b","acl":["y"]}]}}`)
	if at := findACL(listLeak); at == "" {
		t.Error("findACL missed an acl inside a list element")
	}
}

func TestHasPrivateVisibility(t *testing.T) {
	if !hasPrivateVisibility(mustJSON(t, `{"a":{"visibility":"private"}}`)) {
		t.Error("missed visibility:private")
	}
	if hasPrivateVisibility(mustJSON(t, `{"a":{"visibility":"public"}}`)) {
		t.Error("false positive on visibility:public")
	}
}

func hasMustFail(pts []point) bool {
	for _, p := range pts {
		if !p.ok && p.must && p.reason == "" {
			return true
		}
	}
	return false
}

func TestEnvelopePoints(t *testing.T) {
	good := &papi.Response{
		Path: "/papi", Status: 200,
		Body: []byte(`{"data":{},"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`),
	}
	if hasMustFail(envelopePoints(good)) {
		t.Error("conformant envelope produced a MUST failure")
	}
	missingVisibility := &papi.Response{
		Path: "/papi/forges", Status: 200,
		Body: []byte(`{"data":[],"meta":{"type":"forges"}}`),
	}
	if !hasMustFail(envelopePoints(missingVisibility)) {
		t.Error("missing meta.visibility not flagged as a MUST failure")
	}
	scoped := &papi.Response{
		Path: "/papi", Status: 200,
		Body: []byte(`{"data":{},"meta":{"type":"papi","version":"papi/v0","visibility":"scoped"}}`),
	}
	if !hasMustFail(envelopePoints(scoped)) {
		t.Error("meta.visibility=scoped for anon not flagged as a MUST failure")
	}
}

func TestTextEndpointPoint(t *testing.T) {
	enveloped := &papi.Response{
		Path: "/papi/piggy-ids", Status: 200, ContentType: "application/json",
		Body: []byte(`{"data":[],"meta":{}}`),
	}
	if p := textEndpointPoint(enveloped); p.ok || !p.must {
		t.Errorf("enveloped text endpoint not a MUST failure: %+v", p)
	}
	raw := &papi.Response{
		Path: "/papi/piggy-ids", Status: 200, ContentType: "text/plain; charset=utf-8",
		Body: []byte("# ids\npiggy-recipient-v1@pivy_ecdh_p256_pub-aaa\n"),
	}
	if p := textEndpointPoint(raw); !p.ok {
		t.Errorf("raw text/plain endpoint flagged: %s", p.desc)
	}
}

func TestAuthUnknownPoint(t *testing.T) {
	if p := authUnknownPoint(http.StatusForbidden); !p.ok || p.reason != "" {
		t.Error("403 should be a pass")
	}
	if p := authUnknownPoint(http.StatusServiceUnavailable); p.reason == "" {
		t.Error("503 should be a skip (auth tier unavailable)")
	}
	if p := authUnknownPoint(http.StatusOK); !p.must {
		t.Error("200 should be a MUST failure")
	}
}

func hasSkip(pts []point) bool {
	for _, p := range pts {
		if p.reason != "" {
			return true
		}
	}
	return false
}

func TestRepoCanonicalChecks(t *testing.T) {
	// No repos at all: nothing to validate → skip, not ok.
	if pts := repoCanonicalChecks(nil); hasMustFail(pts) || !hasSkip(pts) {
		t.Error("empty repos must produce a skip, not a MUST failure or a plain ok")
	}

	// Single-entry per owner/name: no multi-forge constraint → skip.
	single := []papi.Repo{
		{Owner: "alice", Name: "foo", Forge: "fj"},
	}
	if pts := repoCanonicalChecks(single); hasMustFail(pts) || !hasSkip(pts) {
		t.Error("single-entry repo must produce a skip (no multi-forge repos to validate)")
	}

	// Same name from different owners IS the dual-homed shape: owner is the
	// forge-side identity and necessarily differs per forge entry, so the
	// amendment's bare-name grouping must demand a marker here (papi#55 —
	// an owner-scoped key would never see the migration case at all).
	diffOwners := []papi.Repo{
		{Owner: "alice", Name: "utils", Forge: "fj"},
		{Owner: "bob", Name: "utils", Forge: "gh"},
	}
	if pts := repoCanonicalChecks(diffOwners); !hasMustFail(pts) {
		t.Error("same name across owners (dual-homed shape) with no canonical:true must be a MUST failure")
	}
	diffOwnersMarked := []papi.Repo{
		{Owner: "alice", Name: "utils", Forge: "fj", Canonical: true},
		{Owner: "bob", Name: "utils", Forge: "gh"},
	}
	if pts := repoCanonicalChecks(diffOwnersMarked); hasMustFail(pts) {
		t.Error("same name across owners with exactly one canonical:true must pass")
	}

	dualOK := []papi.Repo{
		{Owner: "alice", Name: "foo", Forge: "fj", Canonical: true},
		{Owner: "alice", Name: "foo", Forge: "gh"},
	}
	if pts := repoCanonicalChecks(dualOK); hasMustFail(pts) {
		t.Error("dual-entry repo with exactly one canonical:true must pass")
	}

	dualMissing := []papi.Repo{
		{Owner: "alice", Name: "foo", Forge: "fj"},
		{Owner: "alice", Name: "foo", Forge: "gh"},
	}
	pts := repoCanonicalChecks(dualMissing)
	if !hasMustFail(pts) {
		t.Error("dual-entry repo with no canonical:true must be a MUST failure")
	}

	dualDouble := []papi.Repo{
		{Owner: "alice", Name: "foo", Forge: "fj", Canonical: true},
		{Owner: "alice", Name: "foo", Forge: "gh", Canonical: true},
	}
	pts = repoCanonicalChecks(dualDouble)
	if !hasMustFail(pts) {
		t.Error("dual-entry repo with two canonical:true must be a MUST failure")
	}

	mixed := []papi.Repo{
		{Owner: "alice", Name: "foo", Forge: "fj", Canonical: true},
		{Owner: "alice", Name: "foo", Forge: "gh"},
		{Owner: "alice", Name: "bar", Forge: "fj"},
	}
	if pts := repoCanonicalChecks(mixed); hasMustFail(pts) {
		t.Error("foo correctly marked, bar single-entry: must pass")
	}
}

func TestRunNonConformantACLLeak(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		fmt.Fprintf(w, `{"data":{"version":"papi/v0","handle":"leaky","resources":{"document":%q},"auth":{"scheme":"x"}},"meta":{}}`,
			base+"/papi")
	})
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		// Leaks an acl key to the anonymous principal — a §2.6 HARD FAIL.
		io.WriteString(w, `{"data":{"person":{"acl":["authenticated"],"handle":"leaky"}},"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`)
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
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var buf bytes.Buffer
	err := Run(context.Background(), &buf, srv.URL, Options{})
	if !errors.Is(err, ErrNonConformant) {
		t.Fatalf("expected ErrNonConformant, got %v", err)
	}
	if !strings.Contains(buf.String(), "leaks an acl key") {
		t.Errorf("acl-leak HARD FAIL not reported in the stream:\n%s", buf.String())
	}
}

func TestParseLinkImmutable(t *testing.T) {
	cases := []struct {
		headers []string
		want    string
	}{
		{nil, ""},
		{[]string{""}, ""},
		{[]string{`<https://example.com/a.tar.gz>; rel="immutable"`}, "https://example.com/a.tar.gz"},
		{[]string{`<https://example.com/a.tar.gz>; rel=immutable`}, "https://example.com/a.tar.gz"},
		{[]string{`<https://example.com/a.tar.gz>; rel="prefetch"`}, ""},
		// Unquoted rel=immutable-archive must NOT match.
		{[]string{`<https://example.com/a.tar.gz>; rel=immutable-archive`}, ""},
		// Multiple entries in one header: pick the immutable one.
		{
			[]string{`<https://example.com/latest.tar.gz>; rel="latest", <https://example.com/pin.tar.gz>; rel="immutable"`},
			"https://example.com/pin.tar.gz",
		},
		// Multiple Link headers: find it in the second.
		{
			[]string{`<https://example.com/latest.tar.gz>; rel="latest"`, `<https://example.com/pin.tar.gz>; rel="immutable"`},
			"https://example.com/pin.tar.gz",
		},
	}
	for _, c := range cases {
		got := parseLinkImmutable(c.headers)
		if got != c.want {
			t.Errorf("parseLinkImmutable(%v) = %q, want %q", c.headers, got, c.want)
		}
	}
}

func TestCanonicalRepoEntries(t *testing.T) {
	// Single-entry repo: implicitly canonical.
	repos := []papi.Repo{{Name: "foo", Owner: "alice", Forge: "fj"}}
	got := canonicalRepoEntries(repos)
	if len(got) != 1 || got[0].Name != "foo" {
		t.Errorf("single-entry repo not included: %v", got)
	}

	// Multi-entry: only the one with canonical:true is included.
	multi := []papi.Repo{
		{Name: "bar", Owner: "alice", Forge: "fj", Canonical: true},
		{Name: "bar", Owner: "bob", Forge: "gh"},
	}
	got = canonicalRepoEntries(multi)
	if len(got) != 1 || !got[0].Canonical {
		t.Errorf("multi-entry: expected only canonical entry, got %v", got)
	}

	// Multi-entry with no canonical marker: no entries returned.
	none := []papi.Repo{
		{Name: "baz", Owner: "alice", Forge: "fj"},
		{Name: "baz", Owner: "bob", Forge: "gh"},
	}
	if got := canonicalRepoEntries(none); len(got) != 0 {
		t.Errorf("multi-entry with no canonical: expected empty, got %v", got)
	}
}

func TestFlakeURLChecks(t *testing.T) {
	// Stub tarball server: /good.tar.gz returns 200 + Link immutable pointing to
	// /pinned.tar.gz; /noimm.tar.gz returns 200 with no Link header;
	// /missing.tar.gz returns 404; /pinned.tar.gz returns 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good.tar.gz":
			pinURL := "http://" + r.Host + "/pinned.tar.gz"
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="immutable"`, pinURL))
			w.WriteHeader(http.StatusOK)
		case "/noimm.tar.gz":
			w.WriteHeader(http.StatusOK)
		case "/pinned.tar.gz":
			w.WriteHeader(http.StatusOK)
		case "/missing.tar.gz":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	t.Run("no flake_url", func(t *testing.T) {
		repos := []papi.Repo{{Name: "foo", Owner: "alice", Forge: "fj"}}
		pts := flakeURLChecks(ctx, c, repos)
		if !hasSkip(pts) || hasMustFail(pts) {
			t.Error("no flake_url should produce a skip, not a failure")
		}
	})

	t.Run("non-canonical multi-entry skipped", func(t *testing.T) {
		// Two entries for "bar", neither canonical — no canonical entry to check.
		repos := []papi.Repo{
			{Name: "bar", Owner: "alice", Forge: "fj", FlakeURL: srv.URL + "/missing.tar.gz"},
			{Name: "bar", Owner: "bob", Forge: "gh", FlakeURL: srv.URL + "/good.tar.gz"},
		}
		pts := flakeURLChecks(ctx, c, repos)
		if !hasSkip(pts) || hasMustFail(pts) {
			t.Error("non-canonical multi-entry with flake_url should skip, not MUST-fail")
		}
	})

	t.Run("fetchable with Link immutable", func(t *testing.T) {
		repos := []papi.Repo{{Name: "foo", Owner: "alice", Forge: "fj", FlakeURL: srv.URL + "/good.tar.gz"}}
		pts := flakeURLChecks(ctx, c, repos)
		if hasMustFail(pts) || hasSkip(pts) {
			t.Errorf("good flake_url with Link immutable should pass: %+v", pts)
		}
	})

	t.Run("fetchable without Link immutable is shouldFail", func(t *testing.T) {
		repos := []papi.Repo{{Name: "foo", Owner: "alice", Forge: "fj", FlakeURL: srv.URL + "/noimm.tar.gz"}}
		pts := flakeURLChecks(ctx, c, repos)
		if hasMustFail(pts) {
			t.Error("missing Link immutable should be SHOULD-fail, not MUST-fail")
		}
		hasShouldFail := false
		for _, p := range pts {
			if !p.ok && !p.must && p.reason == "" {
				hasShouldFail = true
			}
		}
		if !hasShouldFail {
			t.Errorf("missing Link immutable header should produce a shouldFail: %+v", pts)
		}
	})

	t.Run("non-200 is mustFail", func(t *testing.T) {
		repos := []papi.Repo{{Name: "foo", Owner: "alice", Forge: "fj", FlakeURL: srv.URL + "/missing.tar.gz"}}
		pts := flakeURLChecks(ctx, c, repos)
		if !hasMustFail(pts) {
			t.Error("non-200 flake_url should produce a MUST-fail")
		}
	})

	t.Run("canonical entry in dual-homed repo is checked", func(t *testing.T) {
		repos := []papi.Repo{
			{Name: "bar", Owner: "alice", Forge: "fj", Canonical: true, FlakeURL: srv.URL + "/good.tar.gz"},
			{Name: "bar", Owner: "bob", Forge: "gh"},
		}
		pts := flakeURLChecks(ctx, c, repos)
		if hasMustFail(pts) || hasSkip(pts) {
			t.Errorf("canonical entry with good flake_url should pass: %+v", pts)
		}
	})
}
