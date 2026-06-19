package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/amarbel-llc/papi/internal/papi"
)

// Options configures the authenticated tier of Run. With an empty Recipient the
// handshake is skipped and only the public tier (plus the card-free §5.3
// unknown-session check) runs.
type Options struct {
	Recipient  string // a piggy recipient id to authenticate as (§5.1)
	DecryptCmd string // shell command: reads ebox_b64 on stdin, writes the nonce on stdout (the card boundary)
}

// unknownSessionPoint checks §5.3: presenting an unknown session MUST resolve to
// the anonymous principal (public projection), not an error. Card-free.
func unknownSessionPoint(ctx context.Context, c *papi.Client) point {
	resp, err := c.FetchAuthed(ctx, "/papi", "papi-validate-unknown-session-probe")
	if err != nil {
		return skip("conformance: unknown session -> anonymous (§5.3)", "GET /papi failed: "+err.Error())
	}
	if resp.Status != http.StatusOK {
		return mustFail("conformance: unknown session -> anonymous, not an error (§5.3)",
			map[string]any{"status": resp.Status})
	}
	var env struct {
		Meta map[string]any `json:"meta"`
	}
	_ = json.Unmarshal(resp.Body, &env)
	if v, _ := env.Meta["visibility"].(string); v != "" && v != "public" {
		return mustFail("conformance: unknown session -> public projection (§5.3)",
			map[string]any{"meta.visibility": v})
	}
	return ok("conformance: unknown session -> anonymous/public projection (§5.3)")
}

// Sentinel errors from Handshake, so callers can distinguish "the tier isn't
// live here" (a skip) from "the handshake is broken" (a hard failure).
var (
	// ErrNoBoxBackend is the §5.1 `503` — the server cannot encrypt a challenge.
	ErrNoBoxBackend = errors.New("auth tier unavailable (no box backend, §5.1 503)")
	// ErrRecipientUnregistered is the §5.1 `403` — recipient not in the registry.
	ErrRecipientUnregistered = errors.New("recipient not registered (§5.1 403)")
	// ErrNoDecryptCmd is returned when the challenge is minted but no DecryptCmd
	// was supplied to recover the nonce (the card boundary is missing).
	ErrNoDecryptCmd = errors.New("no decrypt-cmd to recover the challenge nonce")
)

// Session is the product of a completed §5 handshake plus the response payload
// that produced it (retained so a caller can replay-test it, §5.2).
type Session struct {
	ID        string // the minted session id, presented as `PiggySession <id>` (§5.3)
	Principal string // the principal the session is bound to (§5.2)
	respBody  []byte // the consumed /papi/auth/response request body, for the replay check
}

// Handshake runs the §5 challenge/response handshake as opts.Recipient: POST the
// challenge, recover the nonce via opts.DecryptCmd (the operator's card boundary),
// POST the response, and return the minted Session. It returns a sentinel error
// (ErrNoBoxBackend / ErrRecipientUnregistered / ErrNoDecryptCmd) for the expected
// "tier not live here" cases and a plain error for a broken handshake. This is the
// shared core: `papi validate`'s conformance checks and `papi person`'s authed
// fetch both drive it rather than reimplementing the flow.
func Handshake(ctx context.Context, c *papi.Client, opts Options) (Session, error) {
	chBody, _ := json.Marshal(map[string]string{"recipient": opts.Recipient})
	ch, err := c.Post(ctx, "/papi/auth/challenge", chBody)
	if err != nil {
		return Session{}, fmt.Errorf("POST /papi/auth/challenge: %w", err)
	}
	switch ch.Status {
	case http.StatusServiceUnavailable:
		return Session{}, ErrNoBoxBackend
	case http.StatusForbidden:
		return Session{}, fmt.Errorf("%w: %q", ErrRecipientUnregistered, opts.Recipient)
	case http.StatusOK:
		// proceed
	default:
		return Session{}, fmt.Errorf("challenge: want 200/403/503, got %d (§5.1)", ch.Status)
	}

	var chJSON struct {
		ChallengeID string `json:"challenge_id"`
		EboxB64     string `json:"ebox_b64"`
	}
	if json.Unmarshal(ch.Body, &chJSON) != nil || chJSON.ChallengeID == "" || chJSON.EboxB64 == "" {
		return Session{}, fmt.Errorf("challenge body lacks challenge_id + ebox_b64 (§5.1)")
	}

	if opts.DecryptCmd == "" {
		return Session{}, ErrNoDecryptCmd
	}
	nonce, err := runDecrypt(ctx, opts.DecryptCmd, chJSON.EboxB64)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt ebox via --decrypt-cmd (§5.2): %w", err)
	}

	respBody, _ := json.Marshal(map[string]string{"challenge_id": chJSON.ChallengeID, "nonce": nonce})
	rs, err := c.Post(ctx, "/papi/auth/response", respBody)
	if err != nil {
		return Session{}, fmt.Errorf("POST /papi/auth/response: %w", err)
	}
	if rs.Status != http.StatusOK {
		return Session{}, fmt.Errorf("response: want 200 with the correct nonce, got %d (§5.2)", rs.Status)
	}
	var session struct {
		Session   string `json:"session"`
		Principal string `json:"principal"`
	}
	if json.Unmarshal(rs.Body, &session) != nil || session.Session == "" {
		return Session{}, fmt.Errorf("response body lacks session (§5.2)")
	}
	return Session{ID: session.Session, Principal: session.Principal, respBody: respBody}, nil
}

// authenticatedChecks runs the §5 handshake via Handshake and verifies the scoped
// projection, mapping the handshake's sentinel errors onto the right conformance
// verdicts (skip vs MUST-fail).
func authenticatedChecks(ctx context.Context, c *papi.Client, opts Options) []point {
	sess, err := Handshake(ctx, c, opts)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoBoxBackend):
			return []point{skip("auth: challenge/response handshake (§5)", "503 — auth tier unavailable (no box backend)")}
		case errors.Is(err, ErrRecipientUnregistered):
			return []point{skip("auth: challenge/response handshake (§5)",
				fmt.Sprintf("recipient %q not registered (403); pass a registered --recipient", opts.Recipient))}
		case errors.Is(err, ErrNoDecryptCmd):
			return []point{skip("auth: challenge/response handshake (§5)",
				"challenge minted, but no --decrypt-cmd to recover the nonce (need the card)")}
		default:
			return []point{mustFail("auth: challenge/response handshake (§5)", map[string]any{"error": err.Error()})}
		}
	}

	pts := []point{ok(fmt.Sprintf("auth: handshake -> session as principal %q (§5)", sess.Principal))}

	if authed, err := c.FetchAuthed(ctx, "/papi", sess.ID); err != nil {
		pts = append(pts, mustFail("auth: GET /papi (authed)", map[string]any{"error": err.Error()}))
	} else {
		pts = append(pts, scopedPoints(authed)...)
	}

	// One-time: re-submitting the consumed challenge MUST be rejected (§5.2).
	if replay, err := c.Post(ctx, "/papi/auth/response", sess.respBody); err == nil {
		pts = append(pts, statusPoint("auth: replayed challenge -> 401 one-time (§5.2)", replay.Status, http.StatusUnauthorized))
	}
	return pts
}

// scopedPoints checks the authenticated /papi response: meta.visibility scoped
// (§4.2) and acl STILL stripped under auth (§2.6 HARD FAIL).
func scopedPoints(resp *papi.Response) []point {
	if resp.Status != http.StatusOK {
		return []point{mustFail("auth: /papi (authed) status 200", map[string]any{"got": resp.Status})}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
		Meta map[string]any  `json:"meta"`
	}
	_ = json.Unmarshal(resp.Body, &env)

	var pts []point
	if v, _ := env.Meta["visibility"].(string); v != "scoped" {
		pts = append(pts, mustFail("auth: /papi meta.visibility==scoped for authed principal (§4.2)", map[string]any{"got": v}))
	} else {
		pts = append(pts, ok("auth: /papi meta.visibility==scoped (§4.2)"))
	}

	var v any
	if json.Unmarshal(env.Data, &v) == nil {
		if at := findACL(v); at != "" {
			pts = append(pts, mustFail("auth: /papi leaks an acl key under auth — HARD FAIL (§2.6)", map[string]any{"at": at}))
		} else {
			pts = append(pts, ok("auth: /papi strips acl even under auth (§2.6)"))
		}
	}
	return pts
}

// runDecrypt pipes eboxB64 to the operator's decrypt command (sh -c cmd) and
// returns the recovered nonce. The command is the card boundary — e.g. a wrapper
// around `pivy-box stream decrypt` against the slot-9D key.
func runDecrypt(ctx context.Context, cmd, eboxB64 string) (string, error) {
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Stdin = strings.NewReader(eboxB64)
	var out, errBuf bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errBuf
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	nonce := strings.TrimRight(out.String(), "\r\n")
	if nonce == "" {
		return "", fmt.Errorf("decrypt command produced no nonce")
	}
	return nonce, nil
}
