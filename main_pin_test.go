package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinFlagsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(path, []byte("246810\r\nignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	pin, err := pinFlags{file: path}.resolve(&warn)
	if err != nil || pin != "246810" {
		t.Fatalf("resolve = %q, %v; want the first line without its line ending", pin, err)
	}
	if warn.Len() != 0 {
		t.Errorf("--pin-file should not warn, got %q", warn.String())
	}
}

func TestPinFlagsValueWarns(t *testing.T) {
	var warn bytes.Buffer
	pin, err := pinFlags{value: "246810"}.resolve(&warn)
	if err != nil || pin != "246810" {
		t.Fatalf("resolve = %q, %v", pin, err)
	}
	if !strings.Contains(warn.String(), "--pin-file") {
		t.Errorf("--pin should warn and point at --pin-file, got %q", warn.String())
	}
}

func TestPinFlagsRejects(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]pinFlags{
		"both":       {value: "1", file: empty},
		"empty file": {file: empty},
		"missing":    {file: filepath.Join(t.TempDir(), "nope")},
	} {
		if _, err := p.resolve(&bytes.Buffer{}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if pin, err := (pinFlags{}).resolve(&bytes.Buffer{}); err != nil || pin != "" {
		t.Errorf("no flags = %q, %v; want empty (piggy asks)", pin, err)
	}
}
