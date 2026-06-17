package inspect

import (
	"bytes"
	"context"
	"encoding/json"
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

// authenticatedChecks runs the §5 challenge/response handshake as opts.Recipient
// and verifies the scoped projection. The nonce is recovered from the challenge
// ebox by opts.DecryptCmd (the operator's card/decryptor).
func authenticatedChecks(ctx context.Context, c *papi.Client, opts Options) []point {
	chBody, _ := json.Marshal(map[string]string{"recipient": opts.Recipient})
	ch, err := c.Post(ctx, "/papi/auth/challenge", chBody)
	if err != nil {
		return []point{mustFail("auth: POST /papi/auth/challenge", map[string]any{"error": err.Error()})}
	}
	switch ch.Status {
	case http.StatusServiceUnavailable:
		return []point{skip("auth: challenge/response handshake (§5)", "503 — auth tier unavailable (no box backend)")}
	case http.StatusForbidden:
		return []point{skip("auth: challenge/response handshake (§5)",
			fmt.Sprintf("recipient %q not registered (403); pass a registered --recipient", opts.Recipient))}
	case http.StatusOK:
		// proceed
	default:
		return []point{mustFail("auth: challenge -> 200/403/503 (§5.1)", map[string]any{"got": ch.Status})}
	}

	var chJSON struct {
		ChallengeID string `json:"challenge_id"`
		EboxB64     string `json:"ebox_b64"`
	}
	if json.Unmarshal(ch.Body, &chJSON) != nil || chJSON.ChallengeID == "" || chJSON.EboxB64 == "" {
		return []point{mustFail("auth: challenge body has challenge_id + ebox_b64 (§5.1)", nil)}
	}

	if opts.DecryptCmd == "" {
		return []point{skip("auth: challenge/response handshake (§5)",
			"challenge minted, but no --decrypt-cmd to recover the nonce (need the card)")}
	}
	nonce, err := runDecrypt(ctx, opts.DecryptCmd, chJSON.EboxB64)
	if err != nil {
		return []point{mustFail("auth: decrypt ebox via --decrypt-cmd (§5.2)", map[string]any{"error": err.Error()})}
	}

	respBody, _ := json.Marshal(map[string]string{"challenge_id": chJSON.ChallengeID, "nonce": nonce})
	rs, err := c.Post(ctx, "/papi/auth/response", respBody)
	if err != nil {
		return []point{mustFail("auth: POST /papi/auth/response", map[string]any{"error": err.Error()})}
	}
	if rs.Status != http.StatusOK {
		return []point{mustFail("auth: response -> 200 with the correct nonce (§5.2)", map[string]any{"got": rs.Status})}
	}
	var session struct {
		Session   string `json:"session"`
		Principal string `json:"principal"`
	}
	if json.Unmarshal(rs.Body, &session) != nil || session.Session == "" {
		return []point{mustFail("auth: response body has session (§5.2)", nil)}
	}

	pts := []point{ok(fmt.Sprintf("auth: handshake -> session as principal %q (§5)", session.Principal))}

	if authed, err := c.FetchAuthed(ctx, "/papi", session.Session); err != nil {
		pts = append(pts, mustFail("auth: GET /papi (authed)", map[string]any{"error": err.Error()}))
	} else {
		pts = append(pts, scopedPoints(authed)...)
	}

	// One-time: re-submitting the consumed challenge MUST be rejected (§5.2).
	if replay, err := c.Post(ctx, "/papi/auth/response", respBody); err == nil {
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
