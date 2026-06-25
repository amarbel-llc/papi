package installer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultStateDir is the root-owned run-state location (RFC-0003 §7). Tests and
// unprivileged runs override it via --state-dir.
const DefaultStateDir = "/var/lib/papi-installer"

// Stamp records that a phase completed, for frequency-based idempotency
// (RFC-0003 §6).
type Stamp struct {
	Phase     string `json:"phase"`
	Frequency string `json:"frequency"`
	Boot      string `json:"boot,omitempty"` // boot id, for per-boot stamps
}

// RunState is the persisted run state (RFC-0003 §7): per-phase stamps, the
// resolved platform, the selected profile, and the persisted binary path used to
// resume after a reboot. It survives across reboots so a resumed run skips the
// phases already satisfied (§6).
type RunState struct {
	dir        string
	Platform   Platform         `json:"platform,omitempty"`
	Profile    string           `json:"profile,omitempty"`
	BinaryPath string           `json:"binary_path,omitempty"`
	Stamps     map[string]Stamp `json:"stamps"`
}

func stateFile(dir string) string { return filepath.Join(dir, "run-state.json") }

// LoadState reads the run state from dir, returning a fresh (empty) state if none
// exists yet.
func LoadState(dir string) (*RunState, error) {
	s := &RunState{dir: dir, Stamps: map[string]Stamp{}}
	b, err := os.ReadFile(stateFile(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read run-state: %w", err)
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("run-state is corrupt: %w", err)
	}
	if s.Stamps == nil {
		s.Stamps = map[string]Stamp{}
	}
	s.dir = dir
	return s, nil
}

// Save persists the run state (dir 0700, file 0600 — root-owned, not group- or
// world-writable per RFC-0003 §7).
func (s *RunState) Save() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile(s.dir), append(b, '\n'), 0o600)
}

// Satisfied reports whether phase p need not run again given its frequency and the
// recorded stamps (RFC-0003 §6). A per-boot phase is satisfied only by a stamp
// from the current boot.
func (s *RunState) Satisfied(p Phase, boot string) bool {
	st, ok := s.Stamps[p.ID]
	if !ok {
		return false
	}
	switch p.frequency() {
	case FrequencyOnce, FrequencyPerInstance:
		return true
	case FrequencyPerBoot:
		return st.Boot == boot
	default:
		return false
	}
}

// Record stamps phase p as completed for the current boot.
func (s *RunState) Record(p Phase, boot string) {
	s.Stamps[p.ID] = Stamp{Phase: p.ID, Frequency: p.frequency(), Boot: boot}
}
