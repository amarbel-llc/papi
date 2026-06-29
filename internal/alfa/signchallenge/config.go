package signchallenge

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// FileConfig is the optional TOML config for `papi sign-challenge-serve`, mirroring
// the identity subsystem's file pattern (internal/0/identity, papi#38). Every field
// maps to a serve flag of the same name; an explicitly-set flag overrides the file
// value (see Resolve and the serve command). PIN is intentionally absent — a deployed
// oracle signs via the agent (no PIN), and a plaintext PIN does not belong in a
// config file.
type FileConfig struct {
	Addr      string `toml:"addr"`
	Domain    string `toml:"domain"`
	Origin    string `toml:"origin"`
	Target    string `toml:"target"`
	GUID      string `toml:"guid"`
	Signer    string `toml:"signer"`
	LogFormat string `toml:"log_format"`
}

// LoadFileConfig decodes the TOML config at path. An absent file is NOT an error — it
// returns the zero FileConfig so the caller's flags/defaults apply (mirroring
// identity.Lookup's absent-file contract). An unreadable or malformed file is an error.
func LoadFileConfig(path string) (FileConfig, error) {
	var c FileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, nil
}

// Resolve picks the effective config value with the precedence the serve command
// uses: an explicitly-set flag wins; otherwise a non-empty file value; otherwise the
// flag's default (which flagVal already carries when the flag was not set). Splitting
// it out keeps the precedence rule unit-testable independent of cobra.
func Resolve(flagChanged bool, flagVal, fileVal string) string {
	if flagChanged || fileVal == "" {
		return flagVal
	}
	return fileVal
}
