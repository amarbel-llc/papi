package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/0/webauthn"
)

const testAAGUID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" // testAuthDataFor's AAGUID

// The lines below are the shapes libfido2 1.17.0's tools print (tools/token.c).
const (
	fakeDeviceList = "/dev/hidraw3: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n"
	fakeInfoNoPIN  = "proto: 0x02\nversion strings: U2F_V2, FIDO_2_0, FIDO_2_1\naaguid: " + testAAGUID + "\n" +
		"options: rk, up, noplat, credMgmt, noclientPin, credentialMgmtPreview, noalwaysUv\npin retries: 8\n"
	fakeInfoPINSet = "aaguid: " + testAAGUID + "\noptions: rk, up, noplat, clientPin, noalwaysUv\n"
)

func TestParseFIDODeviceList(t *testing.T) {
	devs := parseFIDODeviceList([]byte(fakeDeviceList + "\n"))
	if len(devs) != 1 || devs[0].Path != "/dev/hidraw3" || !strings.Contains(devs[0].Label, "Yubico") {
		t.Fatalf("devices = %+v", devs)
	}
}

func TestParseFIDOInfo(t *testing.T) {
	info, err := parseFIDOInfo([]byte(fakeInfoNoPIN))
	if err != nil {
		t.Fatal(err)
	}
	if info.AAGUID != testAAGUID {
		t.Errorf("aaguid = %q", info.AAGUID)
	}
	want := map[string]bool{"rk": true, "up": true, "plat": false, "credMgmt": true, "clientPin": false, "alwaysUv": false}
	for k, v := range want {
		if got, ok := info.Options[k]; !ok || got != v {
			t.Errorf("option %s = %v (present %v), want %v", k, got, ok, v)
		}
	}
	if _, err := parseFIDOInfo([]byte("options: up\n")); err == nil {
		t.Error("an info block without an aaguid should be an error")
	}
}

// fakeAuthenticator plays fido2-token, fido2-cred and fido2-assert against one
// in-memory credential key, reading -i and writing -o like the real tools.
type fakeAuthenticator struct {
	t         *testing.T
	info      string
	priv      *ecdsa.PrivateKey
	credID    []byte
	regFlags  byte
	assertUP  bool
	calls     []string
	failMake  bool
	pinWasSet bool
}

func newFakeAuthenticator(t *testing.T, info string) *fakeAuthenticator {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAuthenticator{t: t, info: info, priv: priv, credID: []byte("fake-credential-id"), regFlags: regFlags, assertUP: true}
}

func (a *fakeAuthenticator) run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	a.calls = append(a.calls, name+" "+strings.Join(args, " "))
	switch {
	case name == "fido2-token" && len(args) == 1 && args[0] == "-L":
		return []byte(fakeDeviceList), nil
	case name == "fido2-token" && len(args) == 2 && args[0] == "-I":
		return []byte(a.info), nil
	}
	return nil, fmt.Errorf("fake: unexpected %s %v", name, args)
}

func flagValue(args []string, flag string) string {
	for i := range len(args) - 1 {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func cborByteString(b []byte) []byte {
	var h []byte
	switch {
	case len(b) < 24:
		h = []byte{0x40 | byte(len(b))}
	case len(b) < 256:
		h = []byte{0x58, byte(len(b))}
	default:
		h = []byte{0x59, byte(len(b) >> 8), byte(len(b))}
	}
	return append(h, b...)
}

func (a *fakeAuthenticator) irun(_ context.Context, name string, args ...string) error {
	a.calls = append(a.calls, name+" "+strings.Join(args, " "))
	b64 := base64.StdEncoding.EncodeToString
	switch name {
	case "fido2-token":
		if len(args) == 2 && args[0] == "-S" {
			a.pinWasSet = true
			return nil
		}
	case "fido2-cred":
		if a.failMake {
			return errors.New("fido2-cred: FIDO_ERR_PIN_INVALID")
		}
		in := a.readLines(flagValue(args, "-i"))
		authData := testAuthDataFor(a.priv, in[1], a.regFlags, 2, a.credID)
		out := []string{in[0], in[1], "packed", b64(cborByteString(authData)), b64(a.credID), b64([]byte("att-sig")), b64([]byte("x5c-der"))}
		return os.WriteFile(flagValue(args, "-o"), []byte(strings.Join(out, "\n")+"\n"), 0o600)
	case "fido2-assert":
		in := a.readLines(flagValue(args, "-i"))
		cdh, err := base64.StdEncoding.DecodeString(in[0])
		if err != nil {
			return err
		}
		var ad bytes.Buffer
		rp := sha256.Sum256([]byte(in[1]))
		ad.Write(rp[:])
		var flags byte
		if a.assertUP {
			flags = webauthn.FlagUP
		}
		ad.WriteByte(flags)
		_ = binary.Write(&ad, binary.BigEndian, uint32(7))
		digest := sha256.Sum256(append(append([]byte{}, ad.Bytes()...), cdh...))
		sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
		if err != nil {
			return err
		}
		out := []string{in[0], in[1], b64(cborByteString(ad.Bytes())), b64(sig)}
		return os.WriteFile(flagValue(args, "-o"), []byte(strings.Join(out, "\n")+"\n"), 0o600)
	}
	return fmt.Errorf("fake: unexpected interactive %s %v", name, args)
}

func (a *fakeAuthenticator) readLines(path string) []string {
	a.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		a.t.Fatalf("fake: read %s: %v", path, err)
	}
	return nonEmptyLines(b)
}

func (a *fakeAuthenticator) fido2() FIDO2 {
	return FIDO2{Run: a.run, IRun: a.irun, TempDir: a.t.TempDir()}
}

func knownPINChanged(context.Context, string) (PINState, string) { return PINStateChanged, "" }

func (f v2Fixture) phase(a *fakeAuthenticator, cards ...CardState) WebAuthnPhase {
	if cards == nil {
		cards = []CardState{{GUID: f.card.GUID, Provisioned: true}}
	}
	return WebAuthnPhase{
		FIDO2:           a.fido2(),
		ListCards:       func(context.Context) ([]CardState, error) { return cards, nil },
		PINState:        knownPINChanged,
		AllowedAAGUIDs:  []string{testAAGUID},
		Out:             io.Discard,
		WaitForOperator: func(string) error { return nil },
	}
}

// The whole phase against a fake device: sets the FIDO2 PIN on a fresh key,
// makes the credential with the flags enroll needs, checks a touch-only
// assertion, and the resulting v2 receipt verifies.
func TestWebAuthnPhaseEndToEnd(t *testing.T) {
	f := newV2Fixture(t)
	a := newFakeAuthenticator(t, fakeInfoNoPIN)
	wa, err := f.phase(a).Run(context.Background(), f.signer, f.card, testRPID)
	if err != nil {
		t.Fatalf("Run: %v\ncalls: %v", err, a.calls)
	}
	if !a.pinWasSet {
		t.Error("a key with no FIDO2 PIN should get one set (fido2-token -S)")
	}
	var mk string
	for _, c := range a.calls {
		if strings.HasPrefix(c, "fido2-cred ") {
			mk = c
		}
	}
	for _, want := range []string{"-M", "-v", "-c 2", "es256"} {
		if !strings.Contains(mk, want) {
			t.Errorf("fido2-cred call %q lacks %q", mk, want)
		}
	}
	if strings.Contains(mk, " -r") || strings.Contains(mk, " -h") {
		t.Errorf("fido2-cred call %q must not ask for a resident key or hmac-secret", mk)
	}
	raw, err := BuildReceiptWithWebAuthn(context.Background(), f.signer, f.card, testRPID, f.trusted.guid, f.trusted.keyID, 1750000000, wa)
	if err != nil {
		t.Fatal(err)
	}
	if res := f.verify(t, raw); !res.OK {
		t.Fatalf("v2 receipt from the phase did not verify: %+v", res.Checks)
	}
}

func TestWebAuthnPhaseRefusals(t *testing.T) {
	f := newV2Fixture(t)
	cases := map[string]func(*WebAuthnPhase, *fakeAuthenticator){
		"default PIV PIN": func(p *WebAuthnPhase, _ *fakeAuthenticator) {
			p.PINState = func(context.Context, string) (PINState, string) { return PINStateDefault, "" }
		},
		"unknown PIV PIN state":  func(p *WebAuthnPhase, _ *fakeAuthenticator) { p.PINState = nil },
		"AAGUID not allowlisted": func(p *WebAuthnPhase, _ *fakeAuthenticator) { p.AllowedAAGUIDs = nil },
		"alwaysUv": func(_ *WebAuthnPhase, a *fakeAuthenticator) {
			a.info = "aaguid: " + testAAGUID + "\noptions: up, clientPin, alwaysUv\n"
		},
		"two cards": func(p *WebAuthnPhase, _ *fakeAuthenticator) {
			p.ListCards = func(context.Context) ([]CardState, error) {
				return []CardState{{GUID: f.card.GUID}, {GUID: f.trusted.guid}}, nil
			}
		},
		"wrong card": func(p *WebAuthnPhase, _ *fakeAuthenticator) {
			p.ListCards = func(context.Context) ([]CardState, error) { return []CardState{{GUID: f.trusted.guid}}, nil }
		},
		"no UV at creation": func(_ *WebAuthnPhase, a *fakeAuthenticator) {
			a.regFlags = webauthn.FlagUP | webauthn.FlagAT | webauthn.FlagED
		},
		"touch check fails":    func(_ *WebAuthnPhase, a *fakeAuthenticator) { a.assertUP = false },
		"make fails (PIN set)": func(_ *WebAuthnPhase, a *fakeAuthenticator) { a.info, a.failMake = fakeInfoPINSet, true },
	}
	for name, mutate := range cases {
		a := newFakeAuthenticator(t, fakeInfoNoPIN)
		p := f.phase(a)
		mutate(&p, a)
		if _, err := p.Run(context.Background(), f.signer, f.card, testRPID); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

// --assume-pin-changed lets an unknown PIN state through, and a key whose PIN
// is already set is not asked to set one.
func TestWebAuthnPhaseAssumePINChanged(t *testing.T) {
	f := newV2Fixture(t)
	a := newFakeAuthenticator(t, fakeInfoPINSet)
	p := f.phase(a)
	p.PINState, p.AssumePINChanged = nil, true
	if _, err := p.Run(context.Background(), f.signer, f.card, testRPID); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if a.pinWasSet {
		t.Error("a key that already has a FIDO2 PIN must not be asked to set one")
	}
}
