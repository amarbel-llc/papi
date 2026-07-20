package installer

import (
	"errors"
	"sort"

	"code.linenisgreat.com/crap/go-crap/v2/crap"
)

// ErrResumeRequired is returned by Run after a requires_reboot phase completes:
// the run state is persisted and the host should reboot — re-invoking against the
// same state dir resumes at the next phase (RFC-0003 §7). The actual reboot and
// the boot-anchored re-exec unit are a seam for a later increment.
var ErrResumeRequired = errors.New("reboot required to continue; re-run against the same --state-dir to resume")

// Runner executes a manifest's phases against a resolved platform and run state.
type Runner struct {
	platform Platform
	state    *RunState
	hooks    map[string]HookFunc
}

// RunOpts configures one Run invocation.
type RunOpts struct {
	Context RunContext // Platform is overwritten from the runner's resolved platform
	Boot    string     // current boot id (for per-boot stamps); "" is a valid sentinel
}

// NewRunner builds a runner for a resolved platform, run state, and hook set.
func NewRunner(platform Platform, state *RunState, hooks map[string]HookFunc) *Runner {
	return &Runner{platform: platform, state: state, hooks: hooks}
}

// orderedPhases returns the platform-applicable phases in execution order: by
// canonical stage index, then declared order within a stage, then a stable
// topological sort honoring gates (RFC-0003 §3/§5/§6). The manifest is assumed
// validated (acyclic, canonical stages).
func (r *Runner) orderedPhases(m Manifest) []Phase {
	var applicable []Phase
	for _, p := range m.Phases {
		if appliesToPlatform(p, r.platform) {
			applicable = append(applicable, p)
		}
	}
	decl := make(map[string]int, len(applicable))
	for i, p := range applicable {
		decl[p.ID] = i
	}
	sort.SliceStable(applicable, func(a, b int) bool {
		sa, sb := stageIndex(applicable[a].Stage), stageIndex(applicable[b].Stage)
		if sa != sb {
			return sa < sb
		}
		return decl[applicable[a].ID] < decl[applicable[b].ID]
	})

	// Gate-aware stable topo pass: emit a phase once every gate that is present on
	// this platform has been emitted. A gate referencing a platform-filtered-out
	// phase is treated as satisfied (that phase does not run here).
	present := make(map[string]bool, len(applicable))
	for _, p := range applicable {
		present[p.ID] = true
	}
	emitted := make(map[string]bool, len(applicable))
	order := make([]Phase, 0, len(applicable))
	for len(order) < len(applicable) {
		progress := false
		for _, p := range applicable {
			if emitted[p.ID] {
				continue
			}
			ready := true
			for _, g := range p.Gates {
				if present[g] && !emitted[g] {
					ready = false
					break
				}
			}
			if ready {
				order = append(order, p)
				emitted[p.ID] = true
				progress = true
			}
		}
		if !progress { // unreachable on a validated (acyclic) manifest — drain in base order
			for _, p := range applicable {
				if !emitted[p.ID] {
					order = append(order, p)
					emitted[p.ID] = true
				}
			}
		}
	}
	return order
}

// Run executes the manifest as one crap Operation with a per-phase item
// (RFC-0003 §6/§8). It validates first, records the resolved platform + selected
// profile in the run state, skips phases already satisfied by their frequency
// stamp, halts on the first failure, and returns ErrResumeRequired after a
// requires_reboot phase. The run state is saved after each completed phase so an
// unexpected reboot resumes at the correct phase (§7).
func (r *Runner) Run(m Manifest, rep *crap.Reporter, opts RunOpts) error {
	if err := m.Validate(); err != nil {
		return err
	}
	rc := opts.Context
	rc.Platform = r.platform
	r.state.Platform = r.platform
	if rc.Profile != "" {
		r.state.Profile = rc.Profile
	}

	phases := r.orderedPhases(m)
	op := rep.Operation("provision", crap.OpOptions{Total: len(phases)})
	defer op.Finish()

	for _, p := range phases {
		if r.state.Satisfied(p, opts.Boot) {
			op.Skip(p.ID, "already satisfied ("+p.frequency()+")")
			continue
		}
		hook, err := resolveHook(r.hooks, p.Hook)
		if err != nil {
			op.Phase(p.ID).Fail(err)
			return err
		}
		if err := hook(rc, op.Phase(p.ID)); err != nil {
			return err // the hook already emitted its Fail verdict
		}
		r.state.Record(p, opts.Boot)
		if err := r.state.Save(); err != nil {
			return err
		}
		if p.RequiresReboot {
			return ErrResumeRequired
		}
	}
	return nil
}
