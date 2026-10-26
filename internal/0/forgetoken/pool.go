package forgetoken

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A pool is a set of tokens minted in one sitting under ONE credential — so one card
// interaction — for consumers that will need them later, when the card is not there
// to sign (papi#80). Each token is still an ordinary per-repo, per-session token:
// named by TokenName, revocable by its session alone, and reaped by Sweep at its
// deadline.
//
// A pool session is chosen by the operator up front, not by the consumer that later
// takes the token. That is the answer to "spawn branch names are not known in
// advance": the token's session is an opaque key that only has to be unique, and a
// consumer that takes a pool token records which key it took and revokes by that key.
// The binding is a local record on the consumer's side, so it needs no card and no
// forge call, where renaming the token on the forge would need the minting
// credential (the card) again.

// ManifestName is the pool's index file. It lists every token minted into the pool
// with its session, repository, forge id, deadline and secret file, and NEVER a
// secret, so it can be read, logged or diffed freely.
const ManifestName = "manifest.json"

// PoolRow is one token to mint: the repository it confines write to and the session
// that names it.
type PoolRow struct {
	Repo    RepoTarget
	Session string
}

// PoolEntry is one minted token as the manifest records it.
type PoolEntry struct {
	Session  string `json:"session"`
	Repo     string `json:"repo"`               // owner/name, resolved
	ID       int64  `json:"id"`                 // forge token id, for `revoke --id`
	Deadline string `json:"deadline,omitempty"` // RFC 3339; absent = never swept
	File     string `json:"file"`               // secret file, relative to the pool dir
}

// PoolManifest is the pool's manifest.json.
type PoolManifest struct {
	Version int         `json:"version"`
	Forge   string      `json:"forge"`
	User    string      `json:"user"`
	Tokens  []PoolEntry `json:"tokens"`
}

// ParsePoolRows reads the batch file: one `<repo> <session>` pair per line, blank
// lines and `#` comments skipped. A session may appear only once, because
// RevokeSession revokes every token of a session and a pool slot must be revocable
// on its own.
func ParsePoolRows(r io.Reader) ([]PoolRow, error) {
	var rows []PoolRow
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("batch line %d: want `<repo> <session>`, got %d field(s)", n, len(fields))
		}
		repo, err := ParseRepo(fields[0])
		if err != nil {
			return nil, fmt.Errorf("batch line %d: %w", n, err)
		}
		if prev, dup := seen[fields[1]]; dup {
			return nil, fmt.Errorf("batch line %d: session %q already used on line %d", n, fields[1], prev)
		}
		seen[fields[1]] = n
		rows = append(rows, PoolRow{Repo: repo, Session: fields[1]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("batch has no rows")
	}
	return rows, nil
}

// MintPool mints one token per row into dir, which it creates mode 0700 and which
// must not already exist. Each secret goes to its own mode-0600 file named after the
// escaped session; the manifest is rewritten after every mint so it is accurate even
// if the run dies part-way.
//
// Everything checkable without minting is checked first — every repository
// resolves, no row's session already has a papi token on the account (it would then
// share the session's revoke), and the directory can be created — so a bad batch
// fails with no token minted. A mint that fails mid-batch stops the run; the tokens
// already minted stay in the manifest and the returned one, since they exist on the
// forge.
func (c *Client) MintPool(ctx context.Context, dir string, rows []PoolRow, deadline time.Time, scopes []string) (PoolManifest, error) {
	m := PoolManifest{Version: 1, Forge: c.BaseURL, User: c.User}
	if err := c.mustMint(); err != nil {
		return m, err
	}
	if dir == "" {
		return m, errors.New("pool directory is required")
	}

	resolved := make([]RepoTarget, len(rows))
	cache := map[RepoTarget]RepoTarget{}
	for i, row := range rows {
		r, ok := cache[row.Repo]
		if !ok {
			var err error
			if r, err = c.ResolveRepo(ctx, row.Repo); err != nil {
				return m, err
			}
			cache[row.Repo] = r
		}
		resolved[i] = r
	}

	existing, err := c.Managed(ctx)
	if err != nil {
		return m, err
	}
	taken := map[string]bool{}
	for _, e := range existing {
		taken[e.Session] = true
	}
	for _, row := range rows {
		if taken[row.Session] {
			return m, fmt.Errorf("session %q already has a papi token on the account; "+
				"a pool slot must be the only token of its session", row.Session)
		}
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		return m, fmt.Errorf("create pool directory (it must not exist yet): %w", err)
	}
	// Mkdir's mode is filtered by the umask; the pool's mode is not up to the umask.
	if err := os.Chmod(dir, 0o700); err != nil {
		return m, err
	}

	var deadlineText string
	if !deadline.IsZero() {
		deadlineText = deadline.UTC().Format(time.RFC3339)
	}
	for i, row := range rows {
		tok, err := c.Mint(ctx, MintRequest{
			Session:  row.Session,
			Deadline: deadline,
			Scopes:   scopes,
			Repos:    []RepoTarget{resolved[i]},
		})
		if err != nil {
			return m, fmt.Errorf("mint %q: %w (%d minted, not minted: %s)",
				row.Session, err, len(m.Tokens), sessionList(rows[i:]))
		}
		file := escapeSession(row.Session) + ".token"
		if err := writeSecretFile(filepath.Join(dir, file), tok.Secret); err != nil {
			// The secret is unrecoverable once dropped, so the token is useless: revoke
			// it rather than leave a live credential nobody holds.
			if rerr := c.DeleteByID(ctx, tok.ID); rerr != nil {
				err = fmt.Errorf("%w; revoking the unsaved token (id %d) also failed: %v", err, tok.ID, rerr)
			}
			return m, fmt.Errorf("save %q: %w (not minted: %s)", row.Session, err, sessionList(rows[i+1:]))
		}
		m.Tokens = append(m.Tokens, PoolEntry{
			Session:  row.Session,
			Repo:     resolved[i].String(),
			ID:       tok.ID,
			Deadline: deadlineText,
			File:     file,
		})
		if err := writeManifest(dir, m); err != nil {
			return m, err
		}
	}
	return m, nil
}

func sessionList(rows []PoolRow) string {
	if len(rows) == 0 {
		return "none"
	}
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Session
	}
	return strings.Join(names, ", ")
}

// writeSecretFile creates path exclusively at mode 0600 and writes the secret on one
// line, the shape `mint` prints on stdout.
func writeSecretFile(path, secret string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := io.WriteString(f, secret+"\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeManifest replaces the manifest atomically, so a reader never sees a torn one.
func writeManifest(dir string, m PoolManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ManifestName+".tmp")
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ManifestName))
}
