//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPigpenGrammarConformance feeds every metadata line of a real,
// SignPigpen-shaped pigpen document (papi#54, RFC-0001 §14) through
// langlang's parse of hyphence's OWN canonical content grammar
// (linenisgreat/hyphence docs/rfcs/hyphence-content.peg). Papi deliberately
// vendors no grammar of its own for this (papi#60): a pigpen document IS a
// hyphence-content document — every `-`/`!` line papi's producer emits is a
// markl-id or bare identifier, a pure subset of hyphence-content's
// DashContent/TypeContent productions, so the single source of truth is
// hyphence's own grammar file, not a papi copy.
//
// The assertion is on the matched PRODUCTION, not on "did it parse" (papi#61):
// hyphence-content's entry rule ends in a FreeText catch-all that swallows any
// single-line input, so a bare parse check has zero power. See
// hyphenceContentStructuredProductions, and the rejects-garbage subtest that
// proves this test can actually fail.
//
// Scope: this asserts each value reaches a structured production, NOT that it
// is semantically valid — a PEG cannot judge blech32 checksums, key material,
// or signature correctness. Those are the decoder's and verifier's job.
//
// Hermetic under `just test-grammar` (papi#58/#60): that recipe builds the
// langlang CLI (`.#langlang`) and hyphence's grammar (`.#hyphence-content-grammar`)
// from flake inputs and hands them in via LANGLANG_BIN / PAPI_HYPHENCE_GRAMMAR.
// SKIPs (never fails) when neither the env vars nor a fallback (langlang on
// PATH, a sibling ~/eng/repos/hyphence checkout) resolves — so a plain
// `go test ./...` outside the wired recipe still passes.
func TestPigpenGrammarConformance(t *testing.T) {
	langlangBin, err := resolveLanglangBin()
	if err != nil {
		t.Skipf("langlang binary unavailable (papi#58; set LANGLANG_BIN or run `just test-grammar`): %v", err)
	}
	grammarPath, err := resolveHyphenceContentGrammar()
	if err != nil {
		t.Skipf("hyphence-content.peg unavailable (papi#60; set PAPI_HYPHENCE_GRAMMAR or run `just test-grammar`): %v", err)
	}

	signer := newPigpenSigner(t)
	signedDoc := buildPigpenDoc(t, signer, true, false)
	lines, err := parsePigpenMetadataLines(signedDoc)
	if err != nil {
		t.Fatalf("parsePigpenMetadataLines: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("want 3 metadata lines (auth key, self-sig, type) in the fixture, got %d: %+v", len(lines), lines)
	}

	for _, l := range lines {
		l := l
		t.Run(string(l.Prefix)+" "+l.Value, func(t *testing.T) {
			assertParsesAsHyphenceContent(t, langlangBin, grammarPath, l.Value)
		})
	}

	// The zero-power guard (hyphence#9's lesson, papi#61): prove the assertion
	// above can actually FAIL. "It parsed" is true of every single-line string
	// via the FreeText catch-all, so without this a regression that made every
	// pigpen line degrade to FreeText would still look green. Both vectors
	// contain spaces, which no Ident can, so they cannot reach a structured
	// production.
	t.Run("rejects-garbage", func(t *testing.T) {
		for _, garbage := range []string{
			"not a valid @@@ markl id",
			"two words",
		} {
			garbage := garbage
			t.Run(garbage, func(t *testing.T) {
				assertRejectedAsHyphenceContent(t, langlangBin, grammarPath, garbage)
			})
		}
	})
}

// resolveLanglangBin locates the langlang CLI: LANGLANG_BIN (set by `just
// test-grammar` to the `.#langlang` flake build) wins, else a langlang already
// on $PATH (e.g. from langlang's own devShell) is used. LANGLANG_BIN rather
// than a PAPI_-prefixed name deliberately: langlang is a domain-neutral shared
// tool and piggy's own grammar gate reads the same variable (piggy#220), so one
// export works across both repos.
func resolveLanglangBin() (string, error) {
	if bin := os.Getenv("LANGLANG_BIN"); bin != "" {
		return bin, nil
	}
	return exec.LookPath("langlang")
}

// resolveHyphenceContentGrammar locates hyphence-content.peg: PAPI_HYPHENCE_GRAMMAR
// (set by `just test-grammar` to the `.#hyphence-content-grammar` flake build)
// wins, else a sibling ~/eng/repos/hyphence checkout is tried for local,
// non-nix dev. papi deliberately vendors no grammar copy of its own (papi#60).
func resolveHyphenceContentGrammar() (string, error) {
	if p := os.Getenv("PAPI_HYPHENCE_GRAMMAR"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(home, "eng", "repos", "hyphence", "docs", "rfcs", "hyphence-content.peg")
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

// hyphenceContentStructuredProductions are the HyphenceContent alternatives
// that represent a real, structured metadata value.
//
// Asserting merely that a line "parsed" is worthless: the entry rule's final
// alternative is `FreeText <- (!LF .)*`, which matches ANY non-newline byte
// sequence, so every single-line string on earth parses (hyphence#9's
// zero-power trap; papi#61). PEG's ordered choice is deterministic and
// FreeText is deliberately last, so the alternative that actually WON is the
// discriminator — a real value lands on a structured production, and only
// garbage falls through to FreeText.
//
// Why this is a set rather than a per-PREFIX expectation: hyphence-content.peg
// tries DashContent FIRST (its own note: "DashContent is tried first since its
// FieldContent branch is the only shape that can require a `=`"), and
// DashContent's bare-Ident branch shadows TypeContent's. Empirically the `!`
// line value `pigpen-v1` therefore matches DashContent, not TypeContent, so
// pinning `!` lines to TypeContent through this combined entry rule is not
// possible. Aiming langlang directly at one named production would need a
// start-rule selector it does not have (its -input mode always parses the
// grammar's first rule); that is an ergonomics gap upstream, not a blocker
// here — rejecting the catch-all is what gives this gate its teeth.
var hyphenceContentStructuredProductions = map[string]bool{
	"DashContent": true,
	"TypeContent": true,
	"BlobContent": true,
}

// langlang colors its tree dump with SGR escapes and offers no -no-color flag,
// so strip them before matching or an anchored pattern only ever sees the
// escape sequence.
var ansiSGRPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

// The direct child of the HyphenceContent root in langlang's tree dump — i.e.
// the alternative that won. Depth-1 rows begin at column 0 with a tree
// connector; deeper rows are indented, so the ^ anchor keeps this to the top
// level.
var hyphenceContentTopChildPattern = regexp.MustCompile(`(?m)^(?:├──|└──)\s*([A-Za-z_][A-Za-z0-9_]*)`)

// assertParsesAsHyphenceContent requires content to match a structured
// HyphenceContent alternative — not the FreeText catch-all.
func assertParsesAsHyphenceContent(t *testing.T, langlangBin, grammarPath, content string) {
	t.Helper()

	production := matchedHyphenceContentProduction(t, langlangBin, grammarPath, content)
	if production == "" {
		t.Fatalf("content %q did not parse as hyphence-content at all", content)
	}
	if !hyphenceContentStructuredProductions[production] {
		t.Fatalf("content %q matched the %q alternative of HyphenceContent, want a structured production (DashContent/TypeContent/BlobContent); %q matches any single-line input and so asserts nothing",
			content, production, production)
	}
}

// assertRejectedAsHyphenceContent is the inverse: content must NOT reach a
// structured production. It either fails to parse outright or degrades to the
// FreeText catch-all.
func assertRejectedAsHyphenceContent(t *testing.T, langlangBin, grammarPath, content string) {
	t.Helper()

	production := matchedHyphenceContentProduction(t, langlangBin, grammarPath, content)
	if hyphenceContentStructuredProductions[production] {
		t.Fatalf("garbage %q matched structured production %q — the conformance assertion has no power if this passes", content, production)
	}
}

// matchedHyphenceContentProduction runs the langlang binary (`langlang
// -grammar <path> -disable-builtins -disable-spaces -input <tmpfile>`, both
// flags required per hyphence-content.peg's own header: the separate
// whitespace-injector pass isn't disabled by -disable-builtins alone) and
// returns the HyphenceContent alternative that matched, or "" when content
// failed to parse outright.
//
// langlang's -input mode exits 0 whether the match succeeds OR fails — a
// failed match instead prints "<input-path>:<line>:<col>: <message>" rather
// than a tree (cmd/langlang/main.go's -input branch never calls os.Exit after
// a parse error, only after a grammar-load failure). That is upstream
// behavior, not a papi choice, so outright failure is detected by that prefix
// rather than by exit code.
func matchedHyphenceContentProduction(t *testing.T, langlangBin, grammarPath, content string) string {
	t.Helper()

	inputPath := filepath.Join(t.TempDir(), "content.txt")
	if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write langlang input file: %v", err)
	}

	cmd := exec.Command(langlangBin,
		"-grammar", grammarPath,
		"-disable-builtins", "-disable-spaces",
		"-input", inputPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("langlang invocation failed: %v\n%s", err, out)
	}

	plain := ansiSGRPattern.ReplaceAllString(string(out), "")
	if strings.HasPrefix(plain, inputPath+":") {
		return ""
	}

	match := hyphenceContentTopChildPattern.FindStringSubmatch(plain)
	if match == nil {
		t.Fatalf("could not find the matched HyphenceContent alternative in langlang's output for %q:\n%s", content, plain)
	}

	return match[1]
}
