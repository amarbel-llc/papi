package inspect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

type rawEndpointFixture struct {
	path, resourceKey, contentType, body string
}

func conformancePointsForRaw(t *testing.T, fixtures []rawEndpointFixture) []point {
	t.Helper()
	mux := http.NewServeMux()
	disc := &papi.Discovery{Resources: map[string]string{}}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for _, f := range fixtures {
		mux.HandleFunc(f.path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", f.contentType)
			_, _ = w.Write([]byte(f.body))
		})
		disc.Resources[f.resourceKey] = srv.URL + f.path
	}
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return conformanceChecks(context.Background(), c, disc)
}

func pointsAbout(pts []point, path string) []point {
	var out []point
	for _, p := range pts {
		if strings.Contains(p.desc, path) {
			out = append(out, p)
		}
	}
	return out
}

func TestConformanceAdvertisedRawEndpointsAreNotEnveloped(t *testing.T) {
	fixtures := []rawEndpointFixture{
		{"/papi/pigpen", "pigpen", "text/vnd.pigpen", "---\n! pigpen-v1\n---\n"},
		{"/papi/bootstrap", "bootstrap", "text/plain; charset=utf-8", "#!/bin/sh\nexit 0\n"},
		{conformistProfilePath, conformistProfileResourceKey, "text/plain; charset=utf-8", "---\n! toml-conformist_profile-v1\n---\n"},
	}
	pts := conformancePointsForRaw(t, fixtures)
	for _, f := range fixtures {
		about := pointsAbout(pts, f.path)
		if len(about) == 0 {
			t.Errorf("%s: no conformance point emitted", f.path)
		}
		for _, p := range about {
			if !p.ok {
				t.Errorf("%s: correctly served raw endpoint failed: %+v", f.path, p)
			}
		}
	}
}

func TestConformancePigpenWrongContentTypeIsShouldFailure(t *testing.T) {
	pts := pointsAbout(conformancePointsForRaw(t, []rawEndpointFixture{
		{"/papi/pigpen", "pigpen", "text/plain; charset=utf-8", "---\n! pigpen-v1\n---\n"},
	}), "/papi/pigpen")
	if len(pts) != 1 || pts[0].ok || pts[0].must || pts[0].reason != "" {
		t.Fatalf("want exactly one SHOULD failure for a text/plain pigpen, got %+v", pts)
	}
}
