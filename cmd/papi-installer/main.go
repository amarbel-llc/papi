// Command papi-installer is the FDR-0006 staged host installer: a static binary
// that drives an RFC-0003 phase manifest to provision a host, rendering per-phase
// progress as crap (a live TUI on a terminal, ndjson-crap when piped). It links
// papi's client (the §5-gated datasource) and the crap TUI.
//
// This is the FDR-0006 first increment: the RFC-0003 phase engine + the runnable
// early phases (detect, apply-minimal-sysconfig). The host/hardware-gated phases
// (real §5 auth, nixos-rebuild apply, the reboot boot-anchored unit) are typed
// seams, and slot-9A signing is out of scope (FDR-0008). Re-invoking against the
// same --state-dir resumes a run: completed phases are skipped by their stamp
// (RFC-0003 §6/§7).
//
//	papi-installer --manifest <path> [--domain <d>] [--platform nixos|linux|darwin]
//	               [--state-dir <dir>] [--profile <id>]
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/papi/internal/0/installer"
	"github.com/amarbel-llc/papi/internal/0/papi"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("papi-installer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "path to the RFC-0003 phase manifest (JSON)")
	domain := fs.String("domain", "", "the subject's PAPI domain (the §5-gated datasource)")
	platformOvr := fs.String("platform", "", "override the detected platform (nixos|linux|darwin)")
	stateDir := fs.String("state-dir", installer.DefaultStateDir, "run-state directory (RFC-0003 §7)")
	profile := fs.String("profile", "", "select a host profile id non-interactively")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *manifestPath == "" {
		fmt.Fprintln(stderr, "papi-installer: --manifest is required")
		return 2
	}

	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintln(stderr, "papi-installer: read manifest:", err)
		return 2
	}
	m, err := installer.Parse(data)
	if err != nil {
		fmt.Fprintln(stderr, "papi-installer:", err)
		return 2
	}

	platform := installer.Detect()
	if *platformOvr != "" {
		if platform, err = installer.ParsePlatform(*platformOvr); err != nil {
			fmt.Fprintln(stderr, "papi-installer:", err)
			return 2
		}
	}

	state, err := installer.LoadState(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "papi-installer:", err)
		return 2
	}

	// Hook set: the engine builtins plus the authed-read seam, which links the papi
	// client (the RFC-0003 §4 §5-gated datasource read). Stubbed this increment.
	hooks := installer.DefaultHooks()
	hooks["authed-read"] = authedReadHook(*domain)

	runner := installer.NewRunner(platform, state, hooks)
	rc := installer.RunContext{StateDir: *stateDir, Domain: *domain, Profile: *profile}
	title := "papi-installer (" + string(platform) + ")"

	err = installer.Present(stdout, crap.ReporterOptions{Source: "papi-installer", Title: title}, title,
		func(rep *crap.Reporter) error {
			return runner.Run(m, rep, installer.RunOpts{Context: rc})
		})
	switch {
	case err == nil:
		return 0
	case errors.Is(err, installer.ErrResumeRequired):
		// A clean stop awaiting reboot/resume, not a failure.
		fmt.Fprintln(stderr, "papi-installer: reboot required; re-run against the same --state-dir to resume")
		return 0
	default:
		fmt.Fprintln(stderr, "papi-installer:", err)
		return 1
	}
}

// authedReadHook is the authed-read seam (RFC-0003 §4): it links and constructs
// papi's client from the domain and reports the §5-gated reads it WOULD perform.
// The real §5 session + the profiles[]/caches[] reads are a later increment.
func authedReadHook(domain string) installer.HookFunc {
	return func(rc installer.RunContext, ph *crap.Phase) error {
		if domain == "" {
			ph.Output("stdout", "stub: would establish a §5 session, then read profiles[] + caches[] (no --domain given)")
			ph.Done()
			return nil
		}
		c, err := papi.NewClient(domain)
		if err != nil {
			ph.Fail(err)
			return err
		}
		_ = c // the client is linked + constructed; the authenticated reads are a seam
		ph.Output("stdout", "stub: would read profiles[] + caches[] from "+domain+" over a §5 session")
		ph.Done()
		return nil
	}
}
