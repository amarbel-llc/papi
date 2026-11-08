package enroll

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"code.linenisgreat.com/papi/internal/0/webauthn"
	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// PINState is whether a card's PIV PIN is still the factory default.
type PINState int

const (
	PINStateUnknown PINState = iota
	PINStateDefault
	PINStateChanged
)

// PINStateReader reports a card's PIV PIN state, and why when it is unknown.
type PINStateReader func(ctx context.Context, guid string) (PINState, string)

// PIVPINStateUnavailable is the PINStateReader until piggy can report the
// state (linenisgreat/piggy#353, YubiKey GET METADATA): always unknown.
func PIVPINStateUnavailable(context.Context, string) (PINState, string) {
	return PINStateUnknown, "piggy cannot yet report whether the PIV PIN is the factory default (linenisgreat/piggy#353)"
}

// WebAuthnPhase is the enroll FIDO2 phase (amarbel-llc/circus#414): it makes
// one non-discoverable, credProtect-2 ES256 credential on the new card, checks
// on the hardware that it works with a touch alone, and returns the receipt's
// webauthn member, bound by the new card's slot-9A key.
//
// The FIDO2 PIN is set equal to the PIV PIN by the operator, at fido2-token's
// own prompt; papi never sees it. A card whose PIV PIN is still the factory
// default is refused, and so is one whose state cannot be read, unless
// AssumePINChanged says the operator has checked.
type WebAuthnPhase struct {
	FIDO2            FIDO2
	ListCards        func(ctx context.Context) ([]CardState, error)
	PINState         PINStateReader
	AssumePINChanged bool
	// CheckUV also proves the FIDO2 PIN: one more PIN entry and touch for a
	// user-verified assertion, after the touch-only one.
	CheckUV bool
	// AllowedAAGUIDs is the allowlist of authenticator models (DefaultAAGUIDs plus
	// whatever the operator adds). Hex, with or without dashes. Empty refuses
	// every model, naming the one seen.
	AllowedAAGUIDs []string
	Out            io.Writer
	// WaitForOperator shows msg and returns once the operator is ready.
	WaitForOperator func(msg string) error
}

// Run executes the phase for newCard against rpID, signing the binding claim
// with signer.
func (p WebAuthnPhase) Run(ctx context.Context, signer Signer, newCard Card, rpID string) (*papi.ReceiptWebAuthn, error) {
	if err := p.checkPIVPIN(ctx, newCard.GUID); err != nil {
		return nil, err
	}
	if err := p.WaitForOperator("FIDO2 phase: leave ONLY the new card " + newCard.GUID + " plugged in (unplug the trusted card and any other security key), then press Enter."); err != nil {
		return nil, err
	}
	dev, info, err := p.preflight(ctx, newCard.GUID)
	if err != nil {
		return nil, err
	}

	pinWasSet := info.Options["clientPin"]
	if !pinWasSet {
		fmt.Fprintln(p.Out, "Setting the FIDO2 PIN: type the SAME PIN as this card's PIV PIN.")
		if err := p.FIDO2.SetPIN(ctx, dev); err != nil {
			return nil, err
		}
	}

	fmt.Fprintln(p.Out, "Making the credential: enter the FIDO2 PIN (the PIV PIN), then touch the key.")
	cdh := papi.WebAuthnClientDataHash(rpID, newCard.GUID, newCard.SSHID)
	made, err := p.FIDO2.MakeCredential(ctx, dev, rpID, "papi-"+guid8(newCard.GUID), cdh)
	if err != nil {
		if pinWasSet {
			return nil, fmt.Errorf("%w (if the FIDO2 PIN differs from the PIV PIN, change it with `fido2-token -C %s` and run enroll again; never reset the FIDO2 applet, which destroys its credentials)", err, dev)
		}
		return nil, err
	}

	reg, err := webauthn.NewRegistration(made.Fmt, made.AuthData)
	if err != nil {
		return nil, fmt.Errorf("webauthn registration: %w", err)
	}
	cred, err := reg.Credential(rpID, webauthn.EnrollPolicy)
	if err != nil {
		return nil, fmt.Errorf("webauthn registration: %w", err)
	}
	fmt.Fprintln(p.Out, "Checking the credential works with a touch alone: touch the key (no PIN).")
	if err := p.FIDO2.AssertTouchOnly(ctx, dev, cred); err != nil {
		return nil, err
	}
	if p.CheckUV {
		fmt.Fprintln(p.Out, "Checking the FIDO2 PIN: enter it, then touch the key.")
		if err := p.FIDO2.AssertWithPIN(ctx, dev, cred); err != nil {
			return nil, err
		}
	}
	return BuildWebAuthnBlock(ctx, signer, newCard, rpID, made)
}

// DefaultAAGUIDs is the YubiKey 5 series AAGUID allowlist papi ships, pinned in
// source and changed only by a reviewed commit (operator ruling on
// amarbel-llc/circus#414). `--webauthn-aaguid` adds to it at run time.
//
// ONE ENTRY, deliberately: the values should be copied from Yubico's published
// list ("YubiKey Hardware FIDO2 AAGUIDs", support.yubico.com), which no session
// has been able to read (web fetch was denied). An AAGUID typed from memory
// would be an unverified trust anchor, so the only entry is one OBSERVED by the
// operator: 2fc0579f-8113-47ea-b116-bb5a8db9202a, printed by `fido2-token -I`
// on the operator's own key on 2026-11-08 (device version 5.2.7 as printed),
// NOT copied from Yubico's page. Other YubiKey 5 variants still need a reviewed
// copy of that list (a commit citing the page and its date); until then enroll
// refuses them and names the AAGUID it saw, so the operator passes
// --webauthn-aaguid.
var DefaultAAGUIDs = []string{"2fc0579f-8113-47ea-b116-bb5a8db9202a"}

// NormalizeAAGUID lowercases an AAGUID and drops dashes, so the dashed UUID form
// Yubico publishes and the bare hex fido2-token prints compare equal.
func NormalizeAAGUID(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

// RequireAddable checks that a card already enrolled on the domain may be
// given a WebAuthn credential (`--add-webauthn`, plan Q3): its slot-9A key must
// already be published on the domain's /papi/piggy-ids, and the card that will
// attest must be a different one, since a card cannot attest its own reach.
func RequireAddable(ctx context.Context, c *papi.Client, newCard Card, trustedGUID string) error {
	if guidEqual(newCard.GUID, trustedGUID) {
		return fmt.Errorf("--add-webauthn needs a different, already-trusted card to attest (--trusted-guid); a card cannot attest its own credential")
	}
	body, status, err := c.PiggyIDs(ctx)
	if err != nil {
		return fmt.Errorf("--add-webauthn: read the domain's /papi/piggy-ids: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("--add-webauthn: /papi/piggy-ids returned HTTP %d", status)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == newCard.SSHID {
			return nil
		}
	}
	return fmt.Errorf("--add-webauthn: card %s's slot-9A key is not published on the domain; enroll it first (without --add-webauthn)", newCard.GUID)
}

// checkPIVPIN refuses a card still on the factory PIV PIN, and one whose state
// is unknown unless AssumePINChanged.
func (p WebAuthnPhase) checkPIVPIN(ctx context.Context, guid string) error {
	read := p.PINState
	if read == nil {
		read = PIVPINStateUnavailable
	}
	state, why := read(ctx, guid)
	switch {
	case state == PINStateDefault:
		return fmt.Errorf("card %s still has the factory-default PIV PIN; change it before adding a WebAuthn credential", guid)
	case state == PINStateUnknown && !p.AssumePINChanged:
		return fmt.Errorf("cannot tell whether card %s still has the factory-default PIV PIN: %s; check it yourself and pass --assume-pin-changed", guid, why)
	case state == PINStateUnknown:
		fmt.Fprintf(p.Out, "warning: %s; continuing because --assume-pin-changed was given\n", why)
	}
	return nil
}

// preflight insists on exactly one PIV card (the new one) and exactly one FIDO
// device, so the credential cannot land on a different key, then checks the
// device's model and options.
func (p WebAuthnPhase) preflight(ctx context.Context, newGUID string) (string, FIDOInfo, error) {
	cards, err := p.ListCards(ctx)
	if err != nil {
		return "", FIDOInfo{}, err
	}
	if len(cards) != 1 || !guidEqual(cards[0].GUID, newGUID) {
		return "", FIDOInfo{}, fmt.Errorf("FIDO2 phase needs exactly one card attached, the new card %s; found %d (unplug the others)", newGUID, len(cards))
	}
	devs, err := p.FIDO2.ListDevices(ctx)
	if err != nil {
		return "", FIDOInfo{}, err
	}
	if len(devs) != 1 {
		return "", FIDOInfo{}, fmt.Errorf("FIDO2 phase needs exactly one FIDO device attached; found %d (unplug the others)", len(devs))
	}
	dev := devs[0].Path
	info, err := p.FIDO2.Info(ctx, dev)
	if err != nil {
		return "", FIDOInfo{}, err
	}
	allowed := make([]string, len(p.AllowedAAGUIDs))
	for i, a := range p.AllowedAAGUIDs {
		allowed[i] = NormalizeAAGUID(a)
	}
	switch {
	case !slices.Contains(allowed, info.AAGUID):
		return "", FIDOInfo{}, fmt.Errorf("FIDO device %s (%s) has AAGUID %s, which is not allowlisted; check it is a YubiKey 5 against Yubico's published AAGUIDs, then pass --webauthn-aaguid %s", dev, devs[0].Label, info.AAGUID, info.AAGUID)
	case info.Options["alwaysUv"]:
		return "", FIDOInfo{}, fmt.Errorf("FIDO device %s has alwaysUv enabled, which makes the touch-only tier impossible", dev)
	}
	if _, supported := info.Options["clientPin"]; !supported {
		return "", FIDOInfo{}, fmt.Errorf("FIDO device %s does not support a client PIN", dev)
	}
	return dev, info, nil
}
