package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs an external command with stdin and returns its stdout — the single
// exec seam, so the card primitives parse real piggy/pivy-tool output in
// production and canned output in tests. name/args are the program and its
// arguments (no shell).
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) (stdout []byte, err error)

// ExecRunner is the production Runner: it execs name with args, feeding stdin and
// capturing stdout, and surfaces stderr in the error.
func ExecRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errBuf.String()); msg != "" {
			return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out.Bytes(), nil
}

// PiggySignBytesSigner implements Signer via `piggy sign-bytes --slot 9a --guid
// <guid> --format raw [-P <pin>]` (piggy#190) — the papi-agnostic, fibby-verified
// slot-9A byte-signer. piggy hashes SHA-256 intrinsically and returns the raw
// 64-byte r‖s, exactly the markl ecdsa_p256_sig payload (no DER/SSH-wire framing
// to parse). It is direct-PCSC (no agent) and GUID-selectable, so it signs both
// the new card's self_proof and the operator-presented trusted card's attestation.
type PiggySignBytesSigner struct {
	Run Runner // defaults to ExecRunner when nil
	PIN string // optional; passed as -P (slot-9A PIN policy may require it)
}

// SignSlot9A signs msg with the slot-9A key of the card identified by guid and
// returns the raw 64-byte r‖s. msg is the bare bytes (piggy hashes SHA-256).
func (p PiggySignBytesSigner) SignSlot9A(ctx context.Context, guid string, msg []byte) ([]byte, error) {
	run := p.Run
	if run == nil {
		run = ExecRunner
	}
	args := make([]string, 0, 9)
	args = append(args, "sign-bytes", "--slot", "9a", "--format", "raw")
	if guid != "" {
		args = append(args, "--guid", guid)
	}
	if p.PIN != "" {
		args = append(args, "-P", p.PIN)
	}
	rs, err := run(ctx, msg, "piggy", args...)
	if err != nil {
		return nil, fmt.Errorf("piggy sign-bytes --slot 9a (guid %q): %w", guid, err)
	}
	if len(rs) != 64 {
		return nil, fmt.Errorf("piggy sign-bytes --slot 9a (guid %q): got %d bytes, want 64 raw r‖s", guid, len(rs))
	}
	return rs, nil
}

// ReadCard reads the slot-9D + slot-9A identity material of the card identified by
// guid back off the card (read-only, PIN-free), via piggy's neutral enumeration
// primitives: `piggy list --format=ndjson` (the markl recipient + auth ids),
// `piggy list --format=ssh` (the slot-9A authorized_keys line), and
// `age-plugin-piggy generate --guid <guid>` (the age recipient). It is the
// read-back leg of FDR-0001's three piggy primitives; generation is upstream
// (piggy/pivy-tool), not papi's.
func ReadCard(ctx context.Context, run Runner, guid string) (Card, error) {
	if run == nil {
		run = ExecRunner
	}
	if guid == "" {
		return Card{}, fmt.Errorf("ReadCard needs a card guid")
	}

	ndjson, err := run(ctx, nil, "piggy", "list", "--format=ndjson")
	if err != nil {
		return Card{}, fmt.Errorf("piggy list --format=ndjson: %w", err)
	}
	recipientID, sshID, cn, err := parsePiggyIdentity(ndjson, guid)
	if err != nil {
		return Card{}, err
	}

	sshOut, err := run(ctx, nil, "piggy", "list", "--format=ssh")
	if err != nil {
		return Card{}, fmt.Errorf("piggy list --format=ssh: %w", err)
	}
	sshLine, err := parsePiggySSHLine(sshOut, guid)
	if err != nil {
		return Card{}, err
	}

	ageOut, err := run(ctx, nil, "age-plugin-piggy", "generate", "--guid", guid)
	if err != nil {
		return Card{}, fmt.Errorf("age-plugin-piggy generate: %w", err)
	}
	ageRecipient, err := parseAgeRecipient(ageOut)
	if err != nil {
		return Card{}, err
	}

	return Card{
		GUID:         guid,
		RecipientID:  recipientID,
		SSHID:        sshID,
		SSHLine:      sshLine,
		AgeRecipient: ageRecipient,
		CN:           cn,
	}, nil
}

// piggyListRecord is one `piggy list --format=ndjson` record. piggy emits one per
// populated slot (and, per piggy#193, one per unprovisioned card). Lenient: extra
// fields ignored. Serial/Reader/Uninitialized feed the card-state grouping
// (provision.go).
type piggyListRecord struct {
	ID            string     `json:"id"`
	GUID          string     `json:"guid"`
	Slot          string     `json:"slot"`
	CN            string     `json:"cn"`
	Serial        flexString `json:"serial"` // piggy emits this as a number today
	Reader        string     `json:"reader"`
	Uninitialized bool       `json:"uninitialized"` // piggy#193: blank-card marker
}

// parsePiggyIdentity pulls the slot-9D recipient id and slot-9A auth id for guid
// out of `piggy list --format=ndjson` output (one JSON record per line). The
// slot-9D record's id is the markl encryption recipient; the slot-9A record's id
// is the markl auth key.
func parsePiggyIdentity(ndjson []byte, guid string) (recipientID, sshID, cn string, err error) {
	for _, line := range strings.Split(string(ndjson), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec piggyListRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue // tolerate non-JSON (e.g. a stray human line)
		}
		if !guidEqual(rec.GUID, guid) {
			continue
		}
		switch strings.ToUpper(rec.Slot) {
		case "9D":
			recipientID = rec.ID
		case "9A":
			sshID = rec.ID
			if rec.CN != "" {
				cn = rec.CN
			}
		}
	}
	if recipientID == "" {
		return "", "", "", fmt.Errorf("piggy list: no slot-9D recipient for guid %q", guid)
	}
	if sshID == "" {
		return "", "", "", fmt.Errorf("piggy list: no slot-9A auth key for guid %q", guid)
	}
	return recipientID, sshID, cn, nil
}

// parsePiggySSHLine returns the slot-9A authorized_keys line for guid from
// `piggy list --format=ssh` output, identified by its `slot=9A` and `guid=<guid>`
// annotations (RFC-0001 §12.1).
func parsePiggySSHLine(out []byte, guid string) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.Contains(line, "slot=9A") {
			continue
		}
		if g, ok := sshAnnotation(line, "guid"); ok && guidEqual(g, guid) {
			return strings.TrimSpace(line), nil
		}
	}
	return "", fmt.Errorf("piggy list --format=ssh: no slot-9A line for guid %q", guid)
}

// sshAnnotation extracts a `key=value` annotation from an authorized_keys line's
// trailing comment field (e.g. guid=… / cn=…).
func sshAnnotation(line, key string) (string, bool) {
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// parseAgeRecipient extracts the age recipient (age1piggy…) from
// `age-plugin-piggy generate` output, which prints a `# recipient: age1…` comment
// line followed by the identity. The identity (AGE-PLUGIN-PIGGY-…) is a private
// key and is deliberately NOT returned.
func parseAgeRecipient(out []byte) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "# recipient:"); ok {
			if r := strings.TrimSpace(v); r != "" {
				return r, nil
			}
		}
		if strings.HasPrefix(line, "age1") {
			return line, nil
		}
	}
	return "", fmt.Errorf("age-plugin-piggy generate: no age recipient in output")
}

// guidEqual compares two card GUIDs case-insensitively after trimming, since
// piggy/pivy-tool may print either case.
func guidEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// RegisterGitHubKey adds the card's slot-9A public key to the authenticated
// GitHub account as BOTH an authentication key (git-over-SSH) and a signing key
// (SSH commit-signature verification), via `gh ssh-key add` (run by name; the nix
// build wraps gh onto papi's PATH). The key material is identical; GitHub tracks
// the two uses as separate keys. pubkey is the OpenSSH authorized_keys line (the
// card's published slot-9A key); title labels the keys on GitHub.
func RegisterGitHubKey(ctx context.Context, run Runner, pubkey, title string) error {
	if run == nil {
		run = ExecRunner
	}
	for _, t := range []struct{ kind, suffix string }{
		{"authentication", ""},
		{"signing", " (signing)"},
	} {
		if _, err := run(ctx, []byte(pubkey+"\n"), "gh", "ssh-key", "add", "--title", title+t.suffix, "--type", t.kind); err != nil {
			return fmt.Errorf("gh ssh-key add --type %s: %w", t.kind, err)
		}
	}
	return nil
}

// GitHubKey is one SSH key on the authenticated GitHub account: its GitHub title,
// its kind ("authentication" or "signing"), and the raw OpenSSH public key string.
type GitHubKey struct {
	Title string
	Kind  string
	Key   string
}

// GitHubKeySet is the result of listing one kind of GitHub SSH key: the keys, or
// the error that prevented listing them. The two GitHub key kinds sit behind
// SEPARATE OAuth scopes (authentication keys need admin:public_key, signing keys
// need admin:ssh_signing_key — or the read: variants), so a per-kind error
// (typically a missing scope) is captured here rather than failing the whole
// call, letting a caller degrade: check the kinds it can and skip the rest.
type GitHubKeySet struct {
	Kind string // "authentication" or "signing"
	Keys []GitHubKey
	Err  error // non-nil if this kind couldn't be listed (e.g. a missing scope)
}

// ListGitHubKeys returns one GitHubKeySet per kind (authentication via
// GET /user/keys, signing via GET /user/ssh_signing_keys) from `gh api`. It is the
// read counterpart of RegisterGitHubKey, for reconciling GitHub against a domain's
// published slot-9A keys. It never returns a top-level error — a failed kind is
// reported in its set's Err.
func ListGitHubKeys(ctx context.Context, run Runner) []GitHubKeySet {
	if run == nil {
		run = ExecRunner
	}
	defs := []struct{ path, kind string }{
		{"user/keys", "authentication"},
		{"user/ssh_signing_keys", "signing"},
	}
	out := make([]GitHubKeySet, 0, len(defs))
	for _, ep := range defs {
		set := GitHubKeySet{Kind: ep.kind}
		raw, err := run(ctx, nil, "gh", "api", ep.path)
		if err != nil {
			set.Err = fmt.Errorf("gh api %s: %w", ep.path, err)
			out = append(out, set)
			continue
		}
		var keys []struct {
			Key   string `json:"key"`
			Title string `json:"title"`
		}
		if err := json.Unmarshal(raw, &keys); err != nil {
			set.Err = fmt.Errorf("parse gh api %s: %w", ep.path, err)
			out = append(out, set)
			continue
		}
		for _, k := range keys {
			set.Keys = append(set.Keys, GitHubKey{Title: k.Title, Kind: ep.kind, Key: k.Key})
		}
		out = append(out, set)
	}
	return out
}
