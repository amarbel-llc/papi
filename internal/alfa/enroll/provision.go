package enroll

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/huh"
)

// flexString unmarshals a JSON value that may be a string OR a number into a
// string — piggy emits card serials as numbers today, and piggy#193 may emit
// them either way.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	*f = flexString(b)
	return nil
}

// CardState is one attached PIV card, grouped from `piggy list --format=ndjson`
// (which emits one record per populated slot, plus — per piggy#193 — a record for
// each unprovisioned card). Provisioned is true once the card carries a slot-9D
// or slot-9A key; an unprovisioned (blank) card has an all-zeros / empty GUID.
type CardState struct {
	Serial      string
	GUID        string // "" or all-zeros when unprovisioned
	Reader      string
	Provisioned bool
}

// parseCardList groups `piggy list --format=ndjson` output into one CardState per
// attached card, keyed by serial (preserving first-seen order). A record bearing
// a 9D/9A slot marks the card provisioned; an explicit state="uninitialized"
// (piggy#193) marks it blank. NOTE: blank cards only appear once piggy#193 lists
// them; against today's `piggy list` this yields only the provisioned cards.
func parseCardList(ndjson []byte) ([]CardState, error) {
	byKey := map[string]*CardState{}
	var order []string
	for _, line := range strings.Split(string(ndjson), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec piggyListRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue // tolerate a stray non-JSON line
		}
		serial := string(rec.Serial)
		key := serial
		if key == "" {
			key = rec.GUID
		}
		if key == "" {
			continue
		}
		cs, ok := byKey[key]
		if !ok {
			cs = &CardState{Serial: serial, Reader: rec.Reader}
			byKey[key] = cs
			order = append(order, key)
		}
		if cs.GUID == "" && !isZeroGUID(rec.GUID) {
			cs.GUID = rec.GUID
		}
		switch strings.ToUpper(rec.Slot) {
		case "9D", "9A":
			cs.Provisioned = true
		}
	}
	out := make([]CardState, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// findBlankCard picks the unprovisioned card to enroll: the one matching serial,
// or — when serial is empty — the sole blank card. It errors on no match, no
// blank card, or (without a serial) more than one blank card.
func findBlankCard(cards []CardState, serial string) (CardState, error) {
	var blanks []CardState
	for _, c := range cards {
		if c.Provisioned {
			continue
		}
		if serial != "" {
			if c.Serial == serial {
				return c, nil
			}
			continue
		}
		blanks = append(blanks, c)
	}
	if serial != "" {
		return CardState{}, fmt.Errorf("no unprovisioned card with serial %q attached", serial)
	}
	switch len(blanks) {
	case 0:
		return CardState{}, fmt.Errorf("no unprovisioned card attached to enroll")
	case 1:
		return blanks[0], nil
	default:
		return CardState{}, fmt.Errorf("%d unprovisioned cards attached; disambiguate with --new-serial", len(blanks))
	}
}

// isZeroGUID reports whether a card GUID is empty or all-zeros (an uninitialized
// card's CHUID GUID).
func isZeroGUID(guid string) bool {
	g := strings.TrimSpace(guid)
	if g == "" {
		return true
	}
	return strings.Trim(g, "0") == ""
}

// displayGUID renders a card's GUID for the picker, or "unprovisioned" when blank.
func displayGUID(c CardState) string {
	if c.Provisioned && c.GUID != "" {
		return c.GUID
	}
	return "unprovisioned"
}

// SelectNewCard runs an interactive huh picker over the attached cards and returns
// the chosen blank card's serial. Every card is shown — provisioned cards are
// labeled as the trusted attester and are unselectable (the select's Validate
// rejects them) — so the operator sees the full set but can only enroll a blank
// card. Errors if no unprovisioned card is attached.
func SelectNewCard(cards []CardState) (string, error) {
	var blanks int
	bySerial := make(map[string]CardState, len(cards))
	opts := make([]huh.Option[string], 0, len(cards))
	for _, c := range cards {
		bySerial[c.Serial] = c
		label := fmt.Sprintf("serial=%s   guid=%s", c.Serial, displayGUID(c))
		if c.Provisioned {
			label += "   (provisioned — trusted attester)"
		} else {
			blanks++
		}
		opts = append(opts, huh.NewOption(label, c.Serial))
	}
	if blanks == 0 {
		return "", fmt.Errorf("no unprovisioned card attached to enroll")
	}

	var serial string
	err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Select the NEW YubiKey to provision + enroll").
			Description("Provisioned cards are the trusted attester — not enrollable.").
			Options(opts...).
			Value(&serial).
			Validate(func(s string) error {
				if bySerial[s].Provisioned {
					return fmt.Errorf("serial %s is already provisioned — it's the trusted attester; pick an unprovisioned card", s)
				}
				return nil
			}),
	)).Run()
	if err != nil {
		return "", err
	}
	return serial, nil
}

// ConfirmProvision asks the operator to confirm the destructive provisioning of
// the blank card before `piggy card init` runs.
func ConfirmProvision(serial, domain string) (bool, error) {
	var ok bool
	err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("Provision card serial=%s and enroll it into %s?", serial, domain)).
			Description("This initializes the blank card (init + generate slot 9D/9A) — destructive.").
			Affirmative("Provision").
			Negative("Cancel").
			Value(&ok),
	)).Run()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// InteractiveRunner runs a command with the process's own stdio attached, so a
// child's PIN/admin-key prompt reaches the operator's terminal. The provisioning
// step uses it (rather than the capturing Runner) precisely so `piggy card init`
// can prompt; papi reads the result back afterward via `piggy list`.
type InteractiveRunner func(ctx context.Context, name string, args ...string) error

// ExecInteractive is the production InteractiveRunner: it runs name with the
// operator's terminal attached.
func ExecInteractive(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Provision provisions the blank card with the given serial via `piggy card init
// --serial <serial>` (piggy#194), run interactively so the operator enters the
// PIN/admin-key, then reads the freshly-assigned GUID back via `piggy list`. It
// DEPENDS ON piggy#194's interface and piggy#193's blank-card listing; the exact
// init flags and the post-init read-back are finalized when those ship.
func Provision(ctx context.Context, irun InteractiveRunner, list Runner, serial string) (string, error) {
	if irun == nil {
		irun = ExecInteractive
	}
	if list == nil {
		list = ExecRunner
	}
	if err := irun(ctx, "piggy", "card", "init", "--serial", serial); err != nil {
		return "", fmt.Errorf("piggy card init --serial %s: %w", serial, err)
	}
	out, err := list(ctx, nil, "piggy", "list", "--format=ndjson")
	if err != nil {
		return "", fmt.Errorf("piggy list after init: %w", err)
	}
	cards, err := parseCardList(out)
	if err != nil {
		return "", err
	}
	for _, c := range cards {
		if c.Serial == serial && c.Provisioned && c.GUID != "" {
			return c.GUID, nil
		}
	}
	return "", fmt.Errorf("card serial %s is not provisioned after init", serial)
}

// ListCards runs `piggy list --format=ndjson` and groups it into CardStates.
func ListCards(ctx context.Context, run Runner) ([]CardState, error) {
	if run == nil {
		run = ExecRunner
	}
	out, err := run(ctx, nil, "piggy", "list", "--format=ndjson")
	if err != nil {
		return nil, fmt.Errorf("piggy list: %w", err)
	}
	return parseCardList(out)
}

// ResolveNewCard determines the GUID of the new card to enroll. With newGUID set
// it is returned as-is (post-init). Otherwise papi provisions a blank card: it
// picks the card by newSerial (or, when empty, the huh selector over cards),
// confirms the destructive step, runs Provision, and returns the freshly-assigned
// GUID. cards is the current `piggy list` so it can be reused by the caller.
func ResolveNewCard(ctx context.Context, irun InteractiveRunner, run Runner, cards []CardState, newGUID, newSerial, domain string) (string, error) {
	if newGUID != "" {
		return newGUID, nil
	}
	serial := newSerial
	if serial == "" {
		var err error
		if serial, err = SelectNewCard(cards); err != nil {
			return "", err
		}
	}
	blank, err := findBlankCard(cards, serial)
	if err != nil {
		return "", err
	}
	ok, err := ConfirmProvision(blank.Serial, domain)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("provisioning cancelled")
	}
	return Provision(ctx, irun, run, blank.Serial)
}

// ResolveTrustedGUID determines the trusted attester's GUID: trustedGUID as-is,
// or the sole provisioned card when empty. It errors rather than guess among
// several provisioned cards.
func ResolveTrustedGUID(cards []CardState, trustedGUID string) (string, error) {
	if trustedGUID != "" {
		return trustedGUID, nil
	}
	var provisioned []CardState
	for _, c := range cards {
		if c.Provisioned {
			provisioned = append(provisioned, c)
		}
	}
	switch len(provisioned) {
	case 0:
		return "", fmt.Errorf("no provisioned card attached to attest; pass --trusted-guid")
	case 1:
		return provisioned[0].GUID, nil
	default:
		return "", fmt.Errorf("%d provisioned cards attached; pass --trusted-guid to choose the attester", len(provisioned))
	}
}
