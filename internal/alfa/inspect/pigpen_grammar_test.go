//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPigpenGrammarConformance feeds every metadata line of a real,
// SignPigpen-shaped pigpen document (papi#54, RFC-0001 §14) through
// langlang's parse of hyphence's OWN canonical content grammar
// (linenisgreat/hyphence docs/rfcs/hyphence-content.peg) and asserts each
// line's content parses. Papi deliberately vendors no grammar of its own for
// this (papi#60): a pigpen document IS a hyphence-content document — every
// `-`/`!` line papi's producer emits is a markl-id or bare identifier, a pure
// subset of hyphence-content's DashContent/TypeContent productions, so the
// single source of truth is hyphence's own grammar file, not a papi copy.
//
// Best-effort and non-hermetic: SKIPs (never fails) when the sibling
// hyphence/langlang checkouts this shells out to aren't present. Neither is
// wired as a flake input yet — papi#58 (langlang) and papi#60 (hyphence's
// .peg) track making this hermetic.
func TestPigpenGrammarConformance(t *testing.T) {
	grammarPath := filepath.Join(siblingCheckout(t, "PAPI_HYPHENCE_CHECKOUT", "hyphence"), "docs", "rfcs", "hyphence-content.peg")
	if _, err := os.Stat(grammarPath); err != nil {
		t.Skipf("hyphence-content.peg not found at %s (papi#60): %v", grammarPath, err)
	}
	langlangGoDir := filepath.Join(siblingCheckout(t, "PAPI_LANGLANG_CHECKOUT", "langlang"), "go")
	if _, err := os.Stat(langlangGoDir); err != nil {
		t.Skipf("langlang checkout not found at %s (papi#58): %v", langlangGoDir, err)
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
			assertParsesAsHyphenceContent(t, langlangGoDir, grammarPath, l.Value)
		})
	}
}

// siblingCheckout resolves a sibling repo checkout directory: envVar
// overrides for a non-default location, else it's assumed to sit alongside
// papi under the operator's home directory (~/eng/repos/<name>), matching
// papi#58's own convention for reaching the langlang checkout.
func siblingCheckout(t *testing.T, envVar, name string) string {
	t.Helper()
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory to locate sibling checkout %q: %v", name, err)
	}
	return filepath.Join(home, "eng", "repos", name)
}

// assertParsesAsHyphenceContent shells out to langlang (`go run
// ./cmd/langlang -grammar <path> -disable-builtins -disable-spaces -input
// <tmpfile>`, both flags required per hyphence-content.peg's own header: the
// separate whitespace-injector pass isn't disabled by -disable-builtins
// alone) to parse content against hyphence-content.peg's combined
// HyphenceContent entry rule (DashContent/TypeContent/BlobContent/FreeText,
// EOF-anchored per alternative).
//
// langlang's -input mode exits 0 whether the match succeeds OR fails — a
// failed match instead prints "<input-path>:<line>:<col>: <message>" to
// stdout (cmd/langlang/main.go's -input branch never calls os.Exit after a
// parse error, only after a grammar-load failure). This is upstream
// behavior, not a papi choice, so failure is detected by that stdout prefix
// rather than by exit code.
func assertParsesAsHyphenceContent(t *testing.T, langlangGoDir, grammarPath, content string) {
	t.Helper()

	inputPath := filepath.Join(t.TempDir(), "content.txt")
	if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write langlang input file: %v", err)
	}

	cmd := exec.Command("go", "run", "./cmd/langlang",
		"-grammar", grammarPath,
		"-disable-builtins", "-disable-spaces",
		"-input", inputPath)
	cmd.Dir = langlangGoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("langlang invocation failed: %v\n%s", err, out)
	}
	if strings.HasPrefix(string(out), inputPath+":") {
		t.Fatalf("content %q did not parse as hyphence-content:\n%s", content, out)
	}
}
