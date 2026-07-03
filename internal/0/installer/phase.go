package installer

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
)

// RunContext is the resolved run context passed to every hook (RFC-0003 §8).
type RunContext struct {
	Platform Platform
	StateDir string
	Domain   string // the subject's PAPI domain (the §5-gated datasource)
	Profile  string // selected profile id, when resolved
}

// HookFunc executes a phase's content, emitting progress on ph and returning the
// verdict: nil = success, non-nil halts the run (RFC-0003 §6/§8). A HookFunc MUST
// close ph (Done or Fail) before returning.
type HookFunc func(rc RunContext, ph *crap.Phase) error

// DefaultHooks returns the engine's built-in hook handlers. The binary
// (cmd/papi-installer) MAY add or override handlers — e.g. a real authed-read that
// links the papi client. Hook resolution (resolveHook): an exact name match, else
// the "stub:" prefix → a typed seam, else the "exec:" prefix → an external command
// (the RFC-0003 §8 exec path).
func DefaultHooks() map[string]HookFunc {
	return map[string]HookFunc{
		"detect":                  hookDetect,
		"apply-minimal-sysconfig": hookApplyMinimalSysconfig,
	}
}

// resolveHook maps a manifest hook reference to a handler.
func resolveHook(hooks map[string]HookFunc, hook string) (HookFunc, error) {
	if h, ok := hooks[hook]; ok {
		return h, nil
	}
	switch {
	case strings.HasPrefix(hook, "stub:"):
		return stubHook(strings.TrimPrefix(hook, "stub:")), nil
	case strings.HasPrefix(hook, "exec:"):
		return execHook(strings.TrimPrefix(hook, "exec:")), nil
	}
	return nil, fmt.Errorf("unknown hook %q (no builtin; not stub:/exec:)", hook)
}

// hookDetect surfaces the resolved platform (the detection itself ran before the
// run; this phase reports it, RFC-0003 §2).
func hookDetect(rc RunContext, ph *crap.Phase) error {
	ph.Output("stdout", "resolved platform: "+string(rc.Platform))
	ph.Done()
	return nil
}

// hookApplyMinimalSysconfig makes nix build-capable (RFC-0003 §5 stage 3). For
// this increment it DETECTS nix and branches, reporting what it would do — it
// never installs anything.
func hookApplyMinimalSysconfig(rc RunContext, ph *crap.Phase) error {
	if _, err := exec.LookPath("nix"); err == nil {
		ph.Output("stdout", "nix present — would apply minimal daemon settings (flakes, recursive-nix, dynamic-derivations)")
	} else {
		ph.Output("stdout", "nix absent — would install Determinate Nix, then apply minimal daemon settings")
	}
	ph.Done()
	return nil
}

// stubHook is a typed seam for a not-yet-implemented phase: it reports what the
// real phase would do and succeeds, so the engine + ordering run end to end
// (FDR-0006 first increment).
func stubHook(what string) HookFunc {
	return func(rc RunContext, ph *crap.Phase) error {
		ph.Output("stdout", "stub: would "+what+" (platform="+string(rc.Platform)+")")
		ph.Done()
		return nil
	}
}

// execHook runs an external command as the phase content (RFC-0003 §8 exec path).
// It runs the command through the shell with the run context exported as env vars,
// captures combined output, and maps the exit code to the verdict.
func execHook(command string) HookFunc {
	return func(rc RunContext, ph *crap.Phase) error {
		ph.Command(command)
		cmd := exec.Command("sh", "-c", command)
		cmd.Env = append(
			os.Environ(),
			"PAPI_INSTALLER_PLATFORM="+string(rc.Platform),
			"PAPI_INSTALLER_STATE_DIR="+rc.StateDir,
			"PAPI_INSTALLER_DOMAIN="+rc.Domain,
			"PAPI_INSTALLER_PROFILE="+rc.Profile,
		)
		out, err := cmd.CombinedOutput()
		if s := strings.TrimRight(string(out), "\n"); s != "" {
			ph.Output("stdout", s)
		}
		if err != nil {
			ph.Fail(err)
			return fmt.Errorf("hook %q failed: %w", command, err)
		}
		ph.Done()
		return nil
	}
}
