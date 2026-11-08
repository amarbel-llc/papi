package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestPinFlagsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(path, []byte("246810\r\nignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := pinFlags{file: path}.resolve()
	if err != nil || pin != "246810" {
		t.Fatalf("resolve = %q, %v; want the first line without its line ending", pin, err)
	}
}

func TestPinFlagsRejects(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]pinFlags{
		"empty file": {file: empty},
		"missing":    {file: filepath.Join(t.TempDir(), "nope")},
	} {
		if _, err := p.resolve(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if pin, err := (pinFlags{}).resolve(); err != nil || pin != "" {
		t.Errorf("no flag = %q, %v; want empty (piggy asks)", pin, err)
	}
}

// papi takes no PIN as a value: an argument is readable by every user on the
// host through /proc/<pid>/cmdline (papi#22, circus#414).
func TestNoCommandTakesAPINValue(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("pin") != nil || c.PersistentFlags().Lookup("pin") != nil {
			t.Errorf("%q has a --pin flag; the PIN may only come from --pin-file or piggy's prompt", c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRootCmd())
}
