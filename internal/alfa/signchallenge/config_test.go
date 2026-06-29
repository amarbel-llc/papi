package signchallenge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileConfigDecodes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oracle.toml")
	body := `
addr = "0.0.0.0:8088"
domain = "linenisgreat.com"
origin = "http://localhost:8080"
target = "https://api.linenisgreat.com"
signer = "agent"
log_format = "json"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("LoadFileConfig: %v", err)
	}
	if c.Addr != "0.0.0.0:8088" || c.Domain != "linenisgreat.com" || c.Origin != "http://localhost:8080" ||
		c.Target != "https://api.linenisgreat.com" || c.Signer != "agent" || c.LogFormat != "json" {
		t.Errorf("decoded config = %+v", c)
	}
}

func TestLoadFileConfigAbsentIsZeroNoError(t *testing.T) {
	c, err := LoadFileConfig(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err != nil {
		t.Errorf("absent file should not error, got %v", err)
	}
	if (c != FileConfig{}) {
		t.Errorf("absent file should yield zero FileConfig, got %+v", c)
	}
}

func TestLoadFileConfigMalformedErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("this is = not [valid toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileConfig(path); err == nil {
		t.Error("malformed TOML should error")
	}
}

func TestResolvePrecedence(t *testing.T) {
	// explicit flag wins over file
	if got := Resolve(true, "flag", "file"); got != "flag" {
		t.Errorf("changed flag = %q, want flag", got)
	}
	// unset flag → non-empty file wins over the flag default
	if got := Resolve(false, "default", "file"); got != "file" {
		t.Errorf("unset flag with file = %q, want file", got)
	}
	// unset flag + empty file → the flag default
	if got := Resolve(false, "default", ""); got != "default" {
		t.Errorf("unset flag, empty file = %q, want default", got)
	}
	// explicit flag wins even over a non-empty file
	if got := Resolve(true, "flag", ""); got != "flag" {
		t.Errorf("changed flag, empty file = %q, want flag", got)
	}
}
