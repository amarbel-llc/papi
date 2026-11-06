package enroll

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"code.linenisgreat.com/papi/internal/0/webauthn"
)

// FIDO2 drives libfido2's command-line tools (fido2-token, fido2-cred,
// fido2-assert) for the enroll WebAuthn phase. papi never holds the FIDO2 PIN:
// the tools that need it are run with the operator's terminal attached and ask
// for it there (fido2-cred(1): "If a tty is available, fido2-cred will use it to
// obtain the PIN"). Parameters go in, and results come out, through files in
// TempDir, so stdin and stdout stay the terminal's.
//
// Output formats are those of libfido2 1.17.0's tools (read from its man pages
// and tools/token.c); they are not checked against a real device here.
type FIDO2 struct {
	Run     Runner            // capturing runner, for read-only fido2-token calls
	IRun    InteractiveRunner // terminal-attached runner, for PIN and touch prompts
	TempDir string            // where parameter and output files go ("" = os.TempDir)
}

// FIDODevice is one line of `fido2-token -L`.
type FIDODevice struct {
	Path  string
	Label string // "vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)"
}

// FIDOInfo is the slice of `fido2-token -I <dev>` the phase reads.
type FIDOInfo struct {
	AAGUID  string          // lowercase hex
	Options map[string]bool // e.g. "clientPin": a PIN is set; absent: not supported
}

func (f FIDO2) run() Runner {
	if f.Run == nil {
		return ExecRunner
	}
	return f.Run
}

func (f FIDO2) irun() InteractiveRunner {
	if f.IRun == nil {
		return ExecInteractive
	}
	return f.IRun
}

// ListDevices runs `fido2-token -L`.
func (f FIDO2) ListDevices(ctx context.Context) ([]FIDODevice, error) {
	out, err := f.run()(ctx, nil, "fido2-token", "-L")
	if err != nil {
		return nil, fmt.Errorf("fido2-token -L: %w", err)
	}
	return parseFIDODeviceList(out), nil
}

// parseFIDODeviceList parses `<path>: vendor=0x…, product=0x… (<mfr> <product>)`
// lines (tools/token.c token_list).
func parseFIDODeviceList(out []byte) []FIDODevice {
	var devs []FIDODevice
	for _, line := range strings.Split(string(out), "\n") {
		path, label, ok := strings.Cut(strings.TrimSpace(line), ": vendor=")
		if !ok || path == "" {
			continue
		}
		devs = append(devs, FIDODevice{Path: path, Label: "vendor=" + label})
	}
	return devs
}

// Info runs `fido2-token -I <dev>`.
func (f FIDO2) Info(ctx context.Context, dev string) (FIDOInfo, error) {
	out, err := f.run()(ctx, nil, "fido2-token", "-I", dev)
	if err != nil {
		return FIDOInfo{}, fmt.Errorf("fido2-token -I %s: %w", dev, err)
	}
	return parseFIDOInfo(out)
}

var hexOnly = regexp.MustCompile(`^[0-9a-f]+$`)

// parseFIDOInfo reads the `aaguid: <hex>` and `options: a, nob, …` lines of
// `fido2-token -I` (tools/token.c: an option prints as its name when true and
// as "no"+name when false).
func parseFIDOInfo(out []byte) (FIDOInfo, error) {
	info := FIDOInfo{Options: map[string]bool{}}
	for _, line := range strings.Split(string(out), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ": ")
		if !ok {
			continue
		}
		switch key {
		case "aaguid":
			info.AAGUID = strings.ToLower(strings.TrimSpace(val))
		case "options":
			// No CTAP option name starts with "no", so the prefix is unambiguous.
			for _, opt := range strings.Split(val, ",") {
				opt = strings.TrimSpace(opt)
				if name, neg := strings.CutPrefix(opt, "no"); neg && name != "" {
					info.Options[name] = false
				} else if opt != "" {
					info.Options[opt] = true
				}
			}
		}
	}
	if len(info.AAGUID) != 32 || !hexOnly.MatchString(info.AAGUID) {
		return FIDOInfo{}, fmt.Errorf("fido2-token -I: no 16-byte aaguid in its output")
	}
	return info, nil
}

// SetPIN runs `fido2-token -S <dev>` on the terminal: the operator types the
// new FIDO2 PIN (and its confirmation) there.
func (f FIDO2) SetPIN(ctx context.Context, dev string) error {
	if err := f.irun()(ctx, "fido2-token", "-S", dev); err != nil {
		return fmt.Errorf("fido2-token -S %s: %w", dev, err)
	}
	return nil
}

// MakeCredential runs `fido2-cred -M -v -c 2 <dev> es256` on the terminal (the
// operator enters the FIDO2 PIN and touches the key): a non-discoverable
// (no -r), UV-verified, credProtect-2 ES256 credential for rpID.
func (f FIDO2) MakeCredential(ctx context.Context, dev, rpID, userName string, clientDataHash []byte) (MadeCredential, error) {
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return MadeCredential{}, err
	}
	b64 := base64.StdEncoding.EncodeToString
	in := strings.Join([]string{b64(clientDataHash), rpID, userName, b64(userID)}, "\n") + "\n"
	out, err := f.withFiles(in, func(inPath, outPath string) error {
		return f.irun()(ctx, "fido2-cred", "-M", "-v", "-c", "2", "-i", inPath, "-o", outPath, dev, "es256")
	})
	if err != nil {
		return MadeCredential{}, fmt.Errorf("fido2-cred -M: %w", err)
	}
	made, err := parseMadeCredential(out)
	if err != nil {
		return MadeCredential{}, err
	}
	made.ClientDataHash = clientDataHash
	return made, nil
}

// parseMadeCredential reads fido2-cred(1)'s make output: client data hash, rp
// id, format, CBOR-wrapped authData, credential id, attestation signature,
// then an optional attestation certificate.
func parseMadeCredential(out []byte) (MadeCredential, error) {
	lines := nonEmptyLines(out)
	if len(lines) < 6 {
		return MadeCredential{}, fmt.Errorf("fido2-cred -M: %d output lines, want at least 6", len(lines))
	}
	dec := func(i int, what string) ([]byte, error) {
		b, err := decodeB64(lines[i])
		if err != nil {
			return nil, fmt.Errorf("fido2-cred -M: %s is not base64: %w", what, err)
		}
		return b, nil
	}
	wrapped, err := dec(3, "authenticator data")
	if err != nil {
		return MadeCredential{}, err
	}
	authData, err := webauthn.UnwrapByteString(wrapped)
	if err != nil {
		return MadeCredential{}, fmt.Errorf("fido2-cred -M: authenticator data: %w", err)
	}
	credID, err := dec(4, "credential id")
	if err != nil {
		return MadeCredential{}, err
	}
	sig, err := dec(5, "attestation signature")
	if err != nil {
		return MadeCredential{}, err
	}
	made := MadeCredential{Fmt: lines[2], AuthData: authData, CredentialID: credID, AttSig: sig}
	if len(lines) > 6 {
		if made.X5C, err = dec(6, "attestation certificate"); err != nil {
			return MadeCredential{}, err
		}
	}
	return made, nil
}

// AssertTouchOnly runs `fido2-assert -G -t up=true -t uv=false -t pin=false` for
// credID on the terminal (the operator touches the key, no PIN) and verifies
// the result as a tier-1 assertion. It proves on the hardware that the
// credential is usable with a touch alone when its id is supplied.
func (f FIDO2) AssertTouchOnly(ctx context.Context, dev string, cred webauthn.Credential) error {
	cdh := make([]byte, 32)
	if _, err := rand.Read(cdh); err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString
	in := strings.Join([]string{b64(cdh), cred.RPID, b64(cred.ID)}, "\n") + "\n"
	out, err := f.withFiles(in, func(inPath, outPath string) error {
		return f.irun()(ctx, "fido2-assert", "-G", "-t", "up=true", "-t", "uv=false", "-t", "pin=false", "-i", inPath, "-o", outPath, dev)
	})
	if err != nil {
		return fmt.Errorf("fido2-assert -G: %w", err)
	}
	authData, sig, err := parseAssertion(out)
	if err != nil {
		return err
	}
	if _, got, err := webauthn.VerifyAssertion(cred, authData, cdh, sig); err != nil {
		return fmt.Errorf("touch-only self-check: %w", err)
	} else if got < webauthn.AssuranceTouch {
		return fmt.Errorf("touch-only self-check: assurance %d, want at least touch", got)
	}
	return nil
}

// parseAssertion reads fido2-assert(1)'s output: client data hash, rp id,
// CBOR-wrapped authData, signature.
func parseAssertion(out []byte) (authData, sig []byte, err error) {
	lines := nonEmptyLines(out)
	if len(lines) < 4 {
		return nil, nil, fmt.Errorf("fido2-assert -G: %d output lines, want at least 4", len(lines))
	}
	wrapped, err := decodeB64(lines[2])
	if err != nil {
		return nil, nil, fmt.Errorf("fido2-assert -G: authenticator data is not base64: %w", err)
	}
	if authData, err = webauthn.UnwrapByteString(wrapped); err != nil {
		return nil, nil, fmt.Errorf("fido2-assert -G: authenticator data: %w", err)
	}
	if sig, err = decodeB64(lines[3]); err != nil {
		return nil, nil, fmt.Errorf("fido2-assert -G: signature is not base64: %w", err)
	}
	return authData, sig, nil
}

// withFiles writes in to a fresh parameter file, runs fn with it and an output
// path, and returns what fn wrote there. Both files are removed afterwards.
func (f FIDO2) withFiles(in string, fn func(inPath, outPath string) error) ([]byte, error) {
	dir, err := os.MkdirTemp(f.TempDir, "papi-fido2-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	inPath, outPath := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.WriteFile(inPath, []byte(in), 0o600); err != nil {
		return nil, err
	}
	if err := fn(inPath, outPath); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

func nonEmptyLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// decodeB64 accepts standard base64 with or without padding (libfido2's tools
// print padded standard base64).
func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
