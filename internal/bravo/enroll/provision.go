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
// each unprovisioned card). Provisioned is true once the card carries a slot-9D or
// slot-9A key; HasAuth is true only once it carries a slot-9A auth key — so a
// half-provisioned card (a 9D but no 9A, e.g. a partially-initialized YubiKey) is
// Provisioned yet not a usable attester. An unprovisioned (blank) card has an
// all-zeros / empty GUID; a pre-5.x YubiKey has an empty Serial (piggy can't read
// its serial over PIV), so it is addressed by Reader or GUID instead.
type CardState struct {
	Serial      string
	GUID        string // "" or all-zeros when unprovisioned
	Reader      string
	Provisioned bool // carries any slot-9A/9D key
	HasAuth     bool // carries a slot-9A auth key (a usable attester)
}

// parseCardList groups `piggy list --format=ndjson` output into one CardState per
// attached card, keyed by serial (preserving first-seen order), falling back to the
// GUID when a card reports no serial (a pre-5.x YubiKey, whose serial piggy can't
// read over PIV). A 9A slot marks the card provisioned AND a usable attester; a
// 9D-only card is provisioned but not an attester; an explicit
// state="uninitialized" (piggy#193) marks it blank. NOTE: blank cards only appear
// once piggy#193 lists them; against today's `piggy list` this yields only the
// provisioned cards.
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
		case "9A":
			cs.Provisioned = true
			cs.HasAuth = true
		case "9D":
			cs.Provisioned = true
		}
		if rec.Uninitialized { // piggy#193's explicit blank marker
			cs.Provisioned = false
			cs.HasAuth = false
		}
	}
	out := make([]CardState, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// cardTarget selects which attached card to provision. At most one field is set;
// all-empty means "auto-pick the sole blank card". The three fields mirror the
// selectors piggy's `card init` accepts (--serial / --guid / --reader, piggy
// fc99b7c), so a card whose serial can't be read — a pre-5.x YubiKey — is still
// addressable by reader.
type cardTarget struct {
	Serial string
	GUID   string
	Reader string
}

func (t cardTarget) empty() bool {
	return t.Serial == "" && t.GUID == "" && t.Reader == ""
}

// findCardToEnroll picks the card to enroll. With a target it returns the matching
// card — blank, or (only when allowReprovision) an already-provisioned one, which
// the caller re-provisions. The target matches by serial, GUID, or reader (whichever
// it carries); reader is the robust selector for a serial-less card. Without a
// target it auto-picks the SOLE blank card and never an already-provisioned one:
// re-provisioning is destructive and must be chosen explicitly (the picker,
// --new-serial, or --new-reader), so it is never the silent default even under
// --allow-reprovision.
func findCardToEnroll(cards []CardState, target cardTarget, allowReprovision bool) (CardState, error) {
	if !target.empty() {
		match, err := matchCard(cards, target)
		if err != nil {
			return CardState{}, err
		}
		if match.Provisioned && !allowReprovision {
			return CardState{}, fmt.Errorf("card %s is already provisioned; pass --allow-reprovision to re-provision it (destroys its keys)", cardLabel(match))
		}
		return match, nil
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
		return CardState{}, fmt.Errorf("%d unprovisioned cards attached; disambiguate with --new-reader (or --new-serial)", len(blanks))
	}
}

// matchCard returns the single attached card matching target's set selector (serial,
// else GUID, else reader). A reader matches by exact string, or — failing that — an
// unambiguous case-insensitive substring, so an operator can pass "01 00" rather than
// the full PCSC reader name. No match, or an ambiguous reader substring, errors with
// the attached cards listed so the caller can pick a working selector.
func matchCard(cards []CardState, target cardTarget) (CardState, error) {
	switch {
	case target.Serial != "":
		for _, c := range cards {
			if c.Serial == target.Serial {
				return c, nil
			}
		}
		return CardState{}, fmt.Errorf("no card with serial %q attached%s", target.Serial, candidateList(cards))
	case target.GUID != "":
		for _, c := range cards {
			if guidEqual(c.GUID, target.GUID) {
				return c, nil
			}
		}
		return CardState{}, fmt.Errorf("no card with guid %q attached%s", target.GUID, candidateList(cards))
	default:
		want := strings.TrimSpace(target.Reader)
		for _, c := range cards {
			if readerEqual(c.Reader, want) {
				return c, nil
			}
		}
		var subs []CardState
		for _, c := range cards {
			if strings.Contains(strings.ToLower(c.Reader), strings.ToLower(want)) {
				subs = append(subs, c)
			}
		}
		switch len(subs) {
		case 1:
			return subs[0], nil
		case 0:
			return CardState{}, fmt.Errorf("no card whose reader matches %q%s", target.Reader, candidateList(cards))
		default:
			return CardState{}, fmt.Errorf("reader %q matches %d attached cards; be more specific%s", target.Reader, len(subs), candidateList(cards))
		}
	}
}

// candidateList renders the attached cards (serial/guid/reader) for a no-match or
// ambiguity error, so the operator can pick a working selector.
func candidateList(cards []CardState) string {
	if len(cards) == 0 {
		return " (no cards attached)"
	}
	var b strings.Builder
	b.WriteString("; attached cards:")
	for _, c := range cards {
		fmt.Fprintf(&b, "\n  - %s guid=%s reader=%q", cardLabel(c), displayGUID(c), c.Reader)
	}
	return b.String()
}

// cardLabel is a short human identifier for a card: its serial when it has one, else
// its reader (a serial-less pre-5.x YubiKey).
func cardLabel(c CardState) string {
	if c.Serial != "" {
		return "serial=" + c.Serial
	}
	return "reader=" + c.Reader
}

// readerEqual compares two PCSC reader names case-insensitively after trimming.
func readerEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// piggyCardSelector maps a chosen card to the single selector `piggy card init`
// needs (piggy fc99b7c: --serial / --guid / --reader are mutually exclusive). It
// prefers the serial when the card has one; otherwise the reader — the robust choice
// for a serial-less card, and the one identifier stable across the init (piggy
// reassigns the GUID, and two factory-blank cards share the all-zeros GUID). Reader
// is always present in `piggy list`, so this always yields a selector.
func piggyCardSelector(c CardState) []string {
	switch {
	case c.Serial != "":
		return []string{"--serial", c.Serial}
	case c.Reader != "":
		return []string{"--reader", c.Reader}
	case !isZeroGUID(c.GUID):
		return []string{"--guid", c.GUID}
	default:
		return nil
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
// the chosen card. Blank cards are always selectable. Provisioned cards are
// selectable ONLY under allowReprovision (flagged ⚠ — choosing one re-initializes it,
// destroying its keys); otherwise they are shown read-only in the description as the
// trusted attester (huh has no disabled-option support, so this keeps them genuinely
// unselectable). Selection is by index so serial-less cards (whose Serial is "") stay
// distinct. Errors if no card is selectable.
func SelectNewCard(cards []CardState, allowReprovision bool) (CardState, error) {
	type choice struct {
		card  CardState
		label string
	}
	var choices []choice
	var readonly []string
	for _, c := range cards {
		switch {
		case !c.Provisioned:
			choices = append(choices, choice{c, fmt.Sprintf("%s   guid=%s", cardLabel(c), displayGUID(c))})
		case allowReprovision:
			choices = append(choices, choice{c, fmt.Sprintf("%s   guid=%s   ⚠ REPROVISION (destroys keys)", cardLabel(c), displayGUID(c))})
		default:
			readonly = append(readonly, fmt.Sprintf("%s guid=%s", cardLabel(c), displayGUID(c)))
		}
	}
	if len(choices) == 0 {
		return CardState{}, fmt.Errorf("no card available to enroll (pass --allow-reprovision to re-provision a provisioned card)")
	}

	opts := make([]huh.Option[int], 0, len(choices))
	for i, ch := range choices {
		opts = append(opts, huh.NewOption(ch.label, i))
	}

	desc := "Pick a blank card to provision + enroll."
	if allowReprovision {
		desc = "Pick a card to enroll. ⚠ choosing a provisioned card RE-INITIALIZES it (destroys its keys) before re-provisioning."
	}
	if len(readonly) > 0 {
		desc += "\nNot selectable (trusted attester): " + strings.Join(readonly, "; ")
	}

	var idx int
	err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[int]().
			Title("New YubiKey to enroll").
			Description(desc).
			Options(opts...).
			Value(&idx),
	)).Run()
	if err != nil {
		return CardState{}, err
	}
	return choices[idx].card, nil
}

// ConfirmProvision asks the operator to confirm the destructive provisioning of the
// blank card before `piggy card init` runs.
func ConfirmProvision(card CardState, domain string) (bool, error) {
	var ok bool
	err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("Provision card %s and enroll it into %s?", cardLabel(card), domain)).
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

// ConfirmReprovision asks the operator to confirm re-initializing an
// already-provisioned card before `piggy card init --allow-reprovision` runs. It is
// the loud, destructive counterpart of ConfirmProvision — gated behind
// --allow-reprovision — and spells out that the card's existing keys are destroyed.
func ConfirmReprovision(card CardState, domain string) (bool, error) {
	var ok bool
	err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("RE-INITIALIZE card %s (guid=%s) and enroll it into %s?", cardLabel(card), displayGUID(card), domain)).
			Description("⚠ This re-initializes the card (piggy card init --allow-reprovision): its existing slot-9D/9A keys are DESTROYED, and any recipient/auth key already published for this card becomes unusable. This cannot be undone.").
			Affirmative("Re-initialize").
			Negative("Cancel").
			Value(&ok),
	)).Run()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// InteractiveRunner runs a command with the process's own stdio attached, so a
// child's PIN/admin-key prompt reaches the operator's terminal. The provisioning step
// uses it (rather than the capturing Runner) precisely so `piggy card init` can
// prompt; papi reads the result back afterward via `piggy list`.
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

// cardInit provisions the given card via `piggy card init [--allow-reprovision]
// <selector>` (piggy fc99b7c), run interactively so the operator enters the
// PIN/admin-key, then reads the freshly-assigned GUID back via `piggy list`. The card
// is selected by the robust identifier it carries (serial, else reader).
// allowReprovision permits re-initializing an already-provisioned card (destroying
// its keys). The CN is derived by piggy (piv-auth@<guid8> / piv-key-mgmt@<guid8>);
// `card init` has no caller CN override. Read-back matches by reader, the one
// identifier stable across the init (piggy reassigns the GUID).
func cardInit(ctx context.Context, irun InteractiveRunner, list Runner, card CardState, allowReprovision bool) (string, error) {
	if irun == nil {
		irun = ExecInteractive
	}
	if list == nil {
		list = ExecRunner
	}
	sel := piggyCardSelector(card)
	if sel == nil {
		return "", fmt.Errorf("cannot select card to provision: %s has no serial, reader, or guid", cardLabel(card))
	}
	args := []string{"card", "init"}
	if allowReprovision {
		args = append(args, "--allow-reprovision")
	}
	args = append(args, sel...)
	if err := irun(ctx, "piggy", args...); err != nil {
		return "", fmt.Errorf("piggy %s: %w", strings.Join(args, " "), err)
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
		if readerEqual(c.Reader, card.Reader) && c.Provisioned && c.GUID != "" {
			return c.GUID, nil
		}
	}
	return "", fmt.Errorf("card %s is not provisioned after init", cardLabel(card))
}

// Provision provisions a blank card (init + generate slot 9D/9A) and returns its
// freshly-assigned GUID.
func Provision(ctx context.Context, irun InteractiveRunner, list Runner, card CardState) (string, error) {
	return cardInit(ctx, irun, list, card, false)
}

// ReprovisionCard re-initializes an already-provisioned card
// (`piggy card init --allow-reprovision`), destroying its existing keys and returning
// the freshly-assigned GUID. There is no separate `piggy card reset`: piggy folds the
// reset into `card init --allow-reprovision`, which requires the card still at its
// factory-default PIN/PUK/mgmt-key.
func ReprovisionCard(ctx context.Context, irun InteractiveRunner, list Runner, card CardState) (string, error) {
	return cardInit(ctx, irun, list, card, true)
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

// ResolveNewCard determines the GUID of the new card to enroll. With newGUID set it
// is returned as-is (an already-provisioned card, skipping provisioning). Otherwise
// papi provisions a card: it picks one by newSerial or newReader (or, when both are
// empty, the huh selector), confirms the destructive step, and returns the
// freshly-assigned GUID. A blank card is provisioned (init); under allowReprovision a
// chosen provisioned card is re-initialized (a louder confirm). cards is the current
// `piggy list` so it can be reused.
func ResolveNewCard(ctx context.Context, irun InteractiveRunner, run Runner, cards []CardState, newGUID, newSerial, newReader, domain string, allowReprovision bool) (string, error) {
	if newGUID != "" {
		return newGUID, nil
	}
	target := cardTarget{Serial: newSerial, Reader: newReader}
	var card CardState
	var err error
	if target.empty() {
		if card, err = SelectNewCard(cards, allowReprovision); err != nil {
			return "", err
		}
	} else {
		if card, err = findCardToEnroll(cards, target, allowReprovision); err != nil {
			return "", err
		}
	}
	if card.Provisioned {
		ok, err := ConfirmReprovision(card, domain)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("reprovisioning cancelled")
		}
		return ReprovisionCard(ctx, irun, run, card)
	}
	ok, err := ConfirmProvision(card, domain)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("provisioning cancelled")
	}
	return Provision(ctx, irun, run, card)
}

// ResolveTrustedGUID determines the trusted attester's GUID: trustedGUID as-is, or the
// sole card carrying a usable slot-9A key when empty. A card without a slot-9A key
// cannot attest (ReadCard needs the 9A), so a 9D-only half-provisioned card is never
// eligible. Errors rather than guess among several attesters.
func ResolveTrustedGUID(cards []CardState, trustedGUID string) (string, error) {
	if trustedGUID != "" {
		return trustedGUID, nil
	}
	var attesters []CardState
	for _, c := range cards {
		if c.HasAuth {
			attesters = append(attesters, c)
		}
	}
	switch len(attesters) {
	case 0:
		return "", fmt.Errorf("no card with a slot-9A key attached to attest; pass --trusted-guid")
	case 1:
		return attesters[0].GUID, nil
	default:
		return "", fmt.Errorf("%d cards with a slot-9A key attached; pass --trusted-guid to choose the attester", len(attesters))
	}
}
