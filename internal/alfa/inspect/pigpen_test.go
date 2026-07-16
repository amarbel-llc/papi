//go:build !wasip1 && !(js && wasm)

package inspect

import "testing"

func TestParsePigpenMetadataLines(t *testing.T) {
	const doc = "---\n" +
		"- piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqqquk3lm\n" +
		"! pigpen-v1\n" +
		"---\n"
	lines, err := parsePigpenMetadataLines([]byte(doc))
	if err != nil {
		t.Fatalf("parsePigpenMetadataLines: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 metadata lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Prefix != '-' || lines[1].Prefix != '!' {
		t.Errorf("unexpected prefixes: %+v", lines)
	}
	if lines[1].Value != "pigpen-v1" {
		t.Errorf("want type line value %q, got %q", "pigpen-v1", lines[1].Value)
	}
}
