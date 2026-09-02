package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// Every command that can sign with the card registers the same three flags, and it
// does so in FIVE separate places (papi#79): authFlags.register, forgeTokenFlags.register,
// newPigpenSignCmd, newSignChallengeCmd and newSignChallengeServeCmd. Nothing tested
// that they all still exist, so an extraction could drop one and only a user would
// find out.
//
// This is a characterization test in service of that extraction. Two things it pins
// that are easy to get wrong:
//
//   - The card-selector flag is NOT spelled the same everywhere, deliberately. The
//     two flag-struct sites use --sign-guid, because the commands they attach to may
//     have their own --guid meaning something else (ssh-keys' key selector, for one);
//     the three standalone signing commands, which have no such collision, use plain
//     --guid. A refactor that flattens both onto one spelling is a BREAKING CLI
//     change, not a tidy-up, so it should have to edit this table to do it.
//   - --signer defaults to "auto" at every site. That default is the thing most
//     likely to drift silently if five copies become one.
//
// It deliberately does NOT assert help text: the five sites already word --signer and
// --pin three different ways, and pinning that would be pinning the mess rather than
// the contract.
func TestSignerFlagsRegisteredAtEverySite(t *testing.T) {
	sites := []struct {
		name string
		cmd  func() *cobra.Command
		// guidFlag is the site's spelling of the card selector.
		guidFlag string
	}{
		// The two shared flag-struct sites, which avoid --guid on purpose.
		{"authFlags (via validate)", newValidateCmd, "sign-guid"},
		{"forgeTokenFlags (via forge token)", newForgeTokenCmd, "sign-guid"},
		// The three standalone signing commands.
		{"pigpen sign", newPigpenSignCmd, "guid"},
		{"sign-challenge", newSignChallengeCmd, "guid"},
		{"sign-challenge-serve", newSignChallengeServeCmd, "guid"},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			cmd := site.cmd()

			// Guard against a vacuous pass: every assertion below runs through
			// flagDefault, so if it ever reported everything as present the whole
			// table would go green while checking nothing.
			if _, ok := flagDefault(cmd, "definitely-not-a-flag"); ok {
				t.Fatal("flagDefault reports a nonexistent flag as present")
			}

			signerDefault, ok := flagDefault(cmd, "signer")
			if !ok {
				t.Error("missing --signer")
			} else if signerDefault != "auto" {
				t.Errorf("--signer defaults to %q, want \"auto\" (every site agrees on this)", signerDefault)
			}
			if _, ok := flagDefault(cmd, "pin"); !ok {
				t.Error("missing --pin")
			}
			if _, ok := flagDefault(cmd, site.guidFlag); !ok {
				t.Errorf("missing --%s (this site's card selector)", site.guidFlag)
			}

			// The spellings must stay disjoint: a site offering both would be
			// ambiguous about which card it signs with.
			other := map[string]string{"guid": "sign-guid", "sign-guid": "guid"}[site.guidFlag]
			if _, ok := flagDefault(cmd, other); ok {
				t.Errorf("registers BOTH --%s and --%s; the card selector must be one or the other",
					site.guidFlag, other)
			}
		})
	}
}

// flagDefault looks a flag up in either flag set, since the sites are split between
// Flags() (the per-command sites) and PersistentFlags() (forge token, whose flags
// have to reach its subcommands).
func flagDefault(cmd *cobra.Command, name string) (string, bool) {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.DefValue, true
	}
	if f := cmd.PersistentFlags().Lookup(name); f != nil {
		return f.DefValue, true
	}
	return "", false
}
