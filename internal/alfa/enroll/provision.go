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
		if rec.Uninitialized { // piggy#193's explicit blank marker
			cs.Provisioned = false
		}
	}
	out := make([]CardState, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// findCardToEnroll picks the card to enroll. With a serial it returns that card —
// blank, or (only when allowReprovision) an already-provisioned one, which the
// caller will reset + re-provision. Without a serial it auto-picks the SOLE blank
// card and never an already-provisioned one: re-provisioning is destructive and
// must be chosen explicitly (the picker or --new-serial), so it is never the
// silent default even under --allow-reprovision.
func findCardToEnroll(cards []CardState, serial string, allowReprovision bool) (CardState, error) {
	if serial != "" {
		for _, c := range cards {
			if c.Serial != serial {
				continue
			}
			if c.Provisioned && !allowReprovision {
				return CardState{}, fmt.Errorf("card serial %q is already provisioned; pass --allow-reprovision to reset + re-provision it", serial)
			}
			return c, nil
		}
		return CardState{}, fmt.Errorf("no card with serial %q attached", serial)
	}
	var blanks []CardState
	for _, c := range cards {
		if !c.Provisioned {
			blanks = append(blanks, c)
		}
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
// the chosen card's serial. Blank cards are always selectable. Provisioned cards
// are selectable ONLY under allowReprovision (flagged ⚠ — choosing one resets +
// re-provisions it, destroying its keys); otherwise they are shown read-only in
// the description as the trusted attester (huh has no disabled-option support, so
// this keeps them genuinely unselectable). Errors if no card is selectable.
func SelectNewCard(cards []CardState, allowReprovision bool) (string, error) {
	opts := make([]huh.Option[string], 0, len(cards))
	var readonly []string
	for _, c := range cards {
		switch {
		case !c.Provisioned:
			opts = append(opts, huh.NewOption(fmt.Sprintf("serial=%s   guid=%s", c.Serial, displayGUID(c)), c.Serial))
		case allowReprovision:
			opts = append(opts, huh.NewOption(fmt.Sprintf("serial=%s   guid=%s   ⚠ REPROVISION (destroys keys)", c.Serial, displayGUID(c)), c.Serial))
		default:
			readonly = append(readonly, fmt.Sprintf("serial=%s guid=%s", c.Serial, displayGUID(c)))
		}
	}
	if len(opts) == 0 {
		return "", fmt.Errorf("no card available to enroll (pass --allow-reprovision to re-provision a provisioned card)")
	}

	desc := "Pick a blank card to provision + enroll."
	if allowReprovision {
		desc = "Pick a card to enroll. ⚠ choosing a provisioned card RESETS it (destroys its keys) before re-provisioning."
	}
	if len(readonly) > 0 {
		desc += "\nNot selectable (trusted attester): " + strings.Join(readonly, "; ")
	}

	var serial string
	err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("New YubiKey to enroll").
			Description(desc).
			Options(opts...).
			Value(&serial),
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

// ConfirmReprovision asks the operator to confirm RESETTING and re-provisioning an
// already-provisioned card before `piggy card reset` runs. It is the loud,
// destructive counterpart of ConfirmProvision — gated behind --allow-reprovision —
// and spells out that the card's existing keys are destroyed.
func ConfirmReprovision(serial, guid, domain string) (bool, error) {
	var ok bool
	err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("RESET + re-provision card serial=%s (guid=%s) and enroll it into %s?", serial, guid, domain)).
			Description("⚠ This FACTORY-RESETS the card: its existing slot-9D/9A keys are DESTROYED, and any recipient/auth key already published for this card becomes unusable. This cannot be undone.").
			Affirmative("Reset + reprovision").
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

// Reset factory-resets the PIV applet of the card with the given serial via `piggy
// card reset --serial <serial>` (run interactively for the admin/PIN), destroying
// its existing keys. It DEPENDS ON piggy#194's reset path (the same `piggy card`
// interface Provision's init uses); today's manual equivalent is a pivy-tool /
// ykman factory-reset.
func Reset(ctx context.Context, irun InteractiveRunner, serial string) error {
	if irun == nil {
		irun = ExecInteractive
	}
	if err := irun(ctx, "piggy", "card", "reset", "--serial", serial); err != nil {
		return fmt.Errorf("piggy card reset --serial %s: %w", serial, err)
	}
	return nil
}

// ReprovisionCard resets an already-provisioned card and then provisions it afresh
// (reset → init + generate 9d/9a), returning the freshly-assigned GUID. It is the
// --allow-reprovision path: the reset MUST precede provisioning so the new keys
// land on a clean applet.
func ReprovisionCard(ctx context.Context, irun InteractiveRunner, list Runner, serial string) (string, error) {
	if err := Reset(ctx, irun, serial); err != nil {
		return "", err
	}
	return Provision(ctx, irun, list, serial)
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
// it is returned as-is (post-init). Otherwise papi provisions a card: it picks one
// by newSerial (or, when empty, the huh selector), confirms the destructive step,
// and returns the freshly-assigned GUID. A blank card is provisioned (init);
// under allowReprovision a chosen provisioned card is reset THEN provisioned (a
// louder confirm). cards is the current `piggy list` so it can be reused.
func ResolveNewCard(ctx context.Context, irun InteractiveRunner, run Runner, cards []CardState, newGUID, newSerial, domain string, allowReprovision bool) (string, error) {
	if newGUID != "" {
		return newGUID, nil
	}
	serial := newSerial
	if serial == "" {
		var err error
		if serial, err = SelectNewCard(cards, allowReprovision); err != nil {
			return "", err
		}
	}
	card, err := findCardToEnroll(cards, serial, allowReprovision)
	if err != nil {
		return "", err
	}
	if card.Provisioned {
		// --allow-reprovision: a loud confirm, then reset + provision.
		ok, err := ConfirmReprovision(card.Serial, card.GUID, domain)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("reprovisioning cancelled")
		}
		return ReprovisionCard(ctx, irun, run, card.Serial)
	}
	ok, err := ConfirmProvision(card.Serial, domain)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("provisioning cancelled")
	}
	return Provision(ctx, irun, run, card.Serial)
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
