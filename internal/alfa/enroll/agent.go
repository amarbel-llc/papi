package enroll

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// slot9ACommentTag is the substring piggy-agent puts in a slot-9A identity's
// comment (e.g. "PIV_slot_9A A1B2C3D4"). The agent-backed signer selects the auth
// key by this tag because the SSH-agent protocol carries comments, not PIV slot
// numbers — the comment convention is the only handle available. This couples to
// piggy-agent's comment format; if that changes, selectSlot9AKey stops finding the
// key and SignSlot9A returns a clear error rather than signing with the wrong key.
const slot9ACommentTag = "SLOT_9A"

// AgentSignBytesSigner implements the slot-9A byte-signer (the enroll.Signer /
// signchallenge.Signer seam) via a forwarded SSH agent instead of direct PCSC. It
// is the path for hosts that reach the card through piggy-agent over a forwarded
// $SSH_AUTH_SOCK rather than a local pcscd — cloud, CI, and dev boxes where the
// card physically lives on another machine. The agent signs SHA-256(msg) with the
// slot-9A ecdsa-sha2-nistp256 key (identical hashing to `piggy sign-bytes` and the
// card itself), and SignSlot9A reframes the SSH ecdsa signature blob {mpint r,
// mpint s} into the raw 64-byte r‖s the §10.4 markl ecdsa_p256_sig payload requires.
//
// Contrast PiggySignBytesSigner, which shells out to `piggy sign-bytes` (direct
// PCSC, no agent) and therefore needs a local card + a running pcscd.
type AgentSignBytesSigner struct {
	// SocketPath is the SSH agent socket to dial; defaults to $SSH_AUTH_SOCK.
	SocketPath string
}

// SignSlot9A dials the SSH agent, selects the slot-9A ecdsa key (disambiguated by
// guid when more than one card is present), signs msg, and returns the raw 64-byte
// r‖s. msg is the bare bytes to sign — the agent hashes SHA-256 for an
// ecdsa-nistp256 key, so the caller passes the §5.2 preimage, NOT a pre-hash.
func (a AgentSignBytesSigner) SignSlot9A(ctx context.Context, guid string, msg []byte) ([]byte, error) {
	sock := a.SocketPath
	if sock == "" {
		sock = os.Getenv("SSH_AUTH_SOCK")
	}
	if sock == "" {
		return nil, fmt.Errorf("SSH agent signer: no socket ($SSH_AUTH_SOCK unset and SocketPath empty)")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("SSH agent signer: dial %s: %w", sock, err)
	}
	defer conn.Close()
	return signSlot9AWithAgent(agent.NewClient(conn), guid, msg)
}

// signSlot9AWithAgent is the agent-protocol core, split out so tests drive it with
// an in-memory agent.Keyring — no socket, no card.
func signSlot9AWithAgent(ag agent.Agent, guid string, msg []byte) ([]byte, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("SSH agent signer: list identities: %w", err)
	}
	key, err := selectSlot9AKey(keys, guid)
	if err != nil {
		return nil, err
	}
	sig, err := ag.Sign(key, msg)
	if err != nil {
		return nil, fmt.Errorf("SSH agent signer: sign with slot-9A key: %w", err)
	}
	if sig.Format != ssh.KeyAlgoECDSA256 {
		return nil, fmt.Errorf("SSH agent signer: slot-9A key signed as %q, want %s", sig.Format, ssh.KeyAlgoECDSA256)
	}
	// An ecdsa SSH signature blob is two mpints (r, s); ssh.Unmarshal maps each to a
	// *big.Int. This is the same decode x/crypto/ssh uses to verify ecdsa signatures.
	var ecdsaSig struct{ R, S *big.Int }
	if err := ssh.Unmarshal(sig.Blob, &ecdsaSig); err != nil {
		return nil, fmt.Errorf("SSH agent signer: parse ecdsa signature blob: %w", err)
	}
	if ecdsaSig.R == nil || ecdsaSig.S == nil {
		return nil, fmt.Errorf("SSH agent signer: ecdsa signature missing r/s")
	}
	// Raw fixed-width r‖s (P-256 → 32+32 bytes) — the §10.4 markl ecdsa_p256_sig
	// payload, no DER and no SSH-wire framing. FillBytes left-pads each scalar,
	// matching the card path; no low-S normalization (standard ECDSA verify, which
	// the server uses, accepts either parity).
	rs := make([]byte, 64)
	ecdsaSig.R.FillBytes(rs[:32])
	ecdsaSig.S.FillBytes(rs[32:])
	return rs, nil
}

// selectSlot9AKey picks the slot-9A ecdsa-sha2-nistp256 identity from the agent's
// keys by piggy-agent's comment tag, disambiguated by guid (matched against the
// comment's hex prefix) when several cards are attached. It errors rather than
// guess among multiple matches.
func selectSlot9AKey(keys []*agent.Key, guid string) (*agent.Key, error) {
	guidUpper := strings.ToUpper(guid)
	if len(guidUpper) > 8 {
		guidUpper = guidUpper[:8] // agent comments carry only the 8-hex GUID prefix
	}
	var matches []*agent.Key
	for _, k := range keys {
		if k.Format != ssh.KeyAlgoECDSA256 {
			continue
		}
		up := strings.ToUpper(k.Comment)
		if !strings.Contains(up, slot9ACommentTag) {
			continue
		}
		if guidUpper != "" && !strings.Contains(up, guidUpper) {
			continue
		}
		matches = append(matches, k)
	}
	switch len(matches) {
	case 0:
		if guid != "" {
			return nil, fmt.Errorf("SSH agent signer: no slot-9A ecdsa key for guid %q in the agent", guid)
		}
		return nil, fmt.Errorf("SSH agent signer: no slot-9A ecdsa key in the agent ($SSH_AUTH_SOCK)")
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("SSH agent signer: %d slot-9A keys in the agent; pass --guid to disambiguate", len(matches))
	}
}
