//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

func conformistProfilePointsFor(t *testing.T, body []byte, status int, advertised bool, authIDs []string) []point {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(conformistProfilePath, func(w http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/papi/piggy-ids", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# ids\n" + strings.Join(authIDs, "\n") + "\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	disc := &papi.Discovery{Resources: map[string]string{}}
	if advertised {
		disc.Resources[conformistProfileResourceKey] = srv.URL + conformistProfilePath
	}
	return conformistProfilePoints(context.Background(), c, disc)
}

type pointCounts struct{ ok, skip, should, must int }

func countPoints(pts []point) pointCounts {
	var n pointCounts
	for _, p := range pts {
		switch {
		case p.reason != "":
			n.skip++
		case p.ok:
			n.ok++
		case p.must:
			n.must++
		default:
			n.should++
		}
	}
	return n
}

func TestConformistProfilePoints(t *testing.T) {
	s := newPigpenSigner(t)
	signed := signTestProfile(t, s)
	published := []string{s.keyID}
	wrongType := bytes.Replace([]byte(testProfileDoc), []byte("toml-conformist_profile-v1"), []byte("toml-other-v1"), 1)

	cases := []struct {
		name       string
		body       []byte
		status     int
		advertised bool
		authIDs    []string
		want       pointCounts
	}{
		{"not implemented", nil, http.StatusNotFound, false, published, pointCounts{skip: 1}},
		{"advertised but 404", nil, http.StatusNotFound, true, published, pointCounts{must: 1}},
		{"signed and advertised", signed, http.StatusOK, true, published, pointCounts{ok: 1}},
		{"served but not advertised", signed, http.StatusOK, false, published, pointCounts{ok: 2, must: 1}},
		{"unsigned", []byte(testProfileDoc), http.StatusOK, true, published, pointCounts{should: 1}},
		{"tampered body", bytes.Replace(signed, []byte("enabled = true"), []byte("enabled = false"), 1), http.StatusOK, true, published, pointCounts{must: 1}},
		{"key not published", signed, http.StatusOK, true, nil, pointCounts{skip: 1}},
		{"wrong type", wrongType, http.StatusOK, true, published, pointCounts{must: 1, should: 1}},
		{"not hyphence", []byte(`{"data":{},"meta":{}}`), http.StatusOK, true, published, pointCounts{must: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pts := conformistProfilePointsFor(t, tc.body, tc.status, tc.advertised, tc.authIDs)
			if got := countPoints(pts); got != tc.want {
				t.Fatalf("got %+v, want %+v: %+v", got, tc.want, pts)
			}
		})
	}
}

func TestConformistProfileIsTextEndpoint(t *testing.T) {
	if !isTextEndpoint(conformistProfilePath) {
		t.Errorf("%s must be probed as a raw text endpoint, not a JSON envelope", conformistProfilePath)
	}
}
