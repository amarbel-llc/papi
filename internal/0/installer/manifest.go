package installer

import (
	"encoding/json"
	"fmt"
)

// Phase frequency values (RFC-0003 §6). An empty Frequency defaults to
// FrequencyPerInstance.
const (
	FrequencyOnce        = "once"
	FrequencyPerInstance = "per-instance"
	FrequencyPerBoot     = "per-boot"
)

// Phase is one entry of the RFC-0003 §3 phase manifest: phase content bound to a
// canonical stage.
type Phase struct {
	ID             string   `json:"id"`
	Stage          string   `json:"stage"`
	Hook           string   `json:"hook"`
	Platforms      []string `json:"platforms,omitempty"`
	Gates          []string `json:"gates,omitempty"`
	Frequency      string   `json:"frequency,omitempty"`
	RequiresReboot bool     `json:"requires_reboot,omitempty"`
}

// frequency returns the effective frequency (empty defaults to per-instance).
func (p Phase) frequency() string {
	if p.Frequency == "" {
		return FrequencyPerInstance
	}
	return p.Frequency
}

// Manifest is the RFC-0003 §3 phase manifest: the canonical stage set plus the
// phases bound to it.
type Manifest struct {
	Stages []string `json:"stages"`
	Phases []Phase  `json:"phases"`
}

// Parse decodes a v0 phase manifest. RFC-0003 leaves the serialization
// unfinalized; v0 uses JSON (the repo's lingua franca). Parse does not check
// semantics — call Validate.
func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	return m, nil
}

// Validate enforces the RFC-0003 §3 MUSTs: the stage set is exactly the canonical
// set, phase ids are unique and non-empty, each stage token is canonical, each
// hook is non-empty, each frequency is understood, every gate references a known
// phase id, and the gate graph is acyclic. A violation is a hard error — the
// installer fails the run rather than execute a partial or reordered set.
func (m Manifest) Validate() error {
	if !isCanonicalStages(m.Stages) {
		return fmt.Errorf("manifest stages %v are not the canonical stage set %v (RFC-0003 §3/§5)", m.Stages, CanonicalStages)
	}
	ids := make(map[string]bool, len(m.Phases))
	for _, p := range m.Phases {
		if p.ID == "" {
			return fmt.Errorf("phase with empty id")
		}
		if ids[p.ID] {
			return fmt.Errorf("duplicate phase id %q", p.ID)
		}
		ids[p.ID] = true
		if stageIndex(p.Stage) < 0 {
			return fmt.Errorf("phase %q: unknown stage %q", p.ID, p.Stage)
		}
		if p.Hook == "" {
			return fmt.Errorf("phase %q: empty hook", p.ID)
		}
		switch p.frequency() {
		case FrequencyOnce, FrequencyPerInstance, FrequencyPerBoot:
		default:
			return fmt.Errorf("phase %q: unknown frequency %q", p.ID, p.Frequency)
		}
	}
	for _, p := range m.Phases {
		for _, g := range p.Gates {
			if !ids[g] {
				return fmt.Errorf("phase %q: gate references unknown phase %q", p.ID, g)
			}
		}
	}
	return checkAcyclic(m.Phases)
}

// checkAcyclic detects a cycle in the gate graph via a three-color DFS.
func checkAcyclic(phases []Phase) error {
	gates := make(map[string][]string, len(phases))
	for _, p := range phases {
		gates[p.ID] = p.Gates
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(phases))
	var visit func(id string) error
	visit = func(id string) error {
		color[id] = gray
		for _, dep := range gates[id] {
			switch color[dep] {
			case gray:
				return fmt.Errorf("gate cycle through phase %q", dep)
			case white:
				if err := visit(dep); err != nil {
					return err
				}
			}
		}
		color[id] = black
		return nil
	}
	for _, p := range phases {
		if color[p.ID] == white {
			if err := visit(p.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
