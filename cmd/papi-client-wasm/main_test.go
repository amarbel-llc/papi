package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/papi"
)

// runFn drives the wasm harness's run() as a host binary: it builds a
// {fn, body} request (body is JSON-string-encoded) and returns stdout + exit code.
func runFn(t *testing.T, fn, body string) (string, int) {
	t.Helper()
	bj, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	in := strings.NewReader(`{"fn":"` + fn + `","body":` + string(bj) + `}`)
	var out, errb bytes.Buffer
	code := run(in, &out, &errb)
	if code != 0 {
		t.Logf("stderr: %s", errb.String())
	}
	return out.String(), code
}

func TestDecodeProfilesAndRepos(t *testing.T) {
	profilesBody := `{"data":[{"id":"framework-laptop",` +
		`"flakeref":"github:amarbel-llc/eng#nixosConfigurations.framework-laptop",` +
		`"home_flakeref":"github:amarbel-llc/eng#homeConfigurations.framework-laptop",` +
		`"kind":"nixos-configuration"}],"meta":{"type":"profiles","count":1}}`
	out, code := runFn(t, "decode_profiles", profilesBody)
	if code != 0 {
		t.Fatalf("decode_profiles exit %d:\n%s", code, out)
	}
	var ps []papi.Profile
	if err := json.Unmarshal([]byte(out), &ps); err != nil {
		t.Fatalf("output not []Profile: %v\n%s", err, out)
	}
	if len(ps) != 1 || ps[0].ID != "framework-laptop" || ps[0].HomeFlakeref == "" {
		t.Fatalf("decoded = %+v", ps)
	}

	reposBody := `{"data":[{"name":"papi","url":"https://github.com/amarbel-llc/papi",` +
		`"owner":"amarbel-llc"}],"meta":{"count":1}}`
	out, code = runFn(t, "decode_repos", reposBody)
	if code != 0 {
		t.Fatalf("decode_repos exit %d:\n%s", code, out)
	}
	var rs []papi.Repo
	if err := json.Unmarshal([]byte(out), &rs); err != nil {
		t.Fatalf("output not []Repo: %v\n%s", err, out)
	}
	if len(rs) != 1 || rs[0].Name != "papi" {
		t.Fatalf("decoded = %+v", rs)
	}
}

func TestDecodeDocumentAndUnknownFn(t *testing.T) {
	docBody := `{"data":{"version":"papi/v0","profiles":[{"id":"dev",` +
		`"flakeref":"github:x#homeConfigurations.dev","kind":"home-configuration"}]},"meta":{}}`
	out, code := runFn(t, "decode_document", docBody)
	if code != 0 {
		t.Fatalf("decode_document exit %d:\n%s", code, out)
	}
	var doc papi.Document
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output not Document: %v\n%s", err, out)
	}
	if doc.Version != "papi/v0" || len(doc.Profiles) != 1 {
		t.Fatalf("decoded = %+v", doc)
	}

	// An unknown fn is a malformed request → exit 2.
	if _, code := runFn(t, "decode_bogus", "{}"); code != 2 {
		t.Errorf("unknown fn exit = %d, want 2", code)
	}
}
