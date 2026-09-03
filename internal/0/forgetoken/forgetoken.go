// Package forgetoken mints, lists, and revokes FINE-GRAINED Forgejo access tokens
// scoped to a single repository — the issuer half of spinclass's per-session push
// credential (papi#73; consumer design in spinclass FDR-0028).
//
// Two constraints shape everything here, both verified against Forgejo v15.0.7:
//
//   - Minting MUST go through the API, never `forgejo admin user
//     generate-access-token`. That CLI hardcodes ResourceAllRepos=true ("maintain
//     legacy behaviour ... not fine-grained"), so it can only ever produce
//     user-wide tokens. Per-repo narrowing lives on v15's orthogonal token
//     RESOURCES axis, reachable only from the web UI and this API.
//   - Token SCOPES are category-wide: "write:repository" means write to every repo
//     the owner can touch. The per-repo promise comes entirely from the resource
//     rows, which downgrade unlisted-public repos to read-only and make
//     unlisted-private ones invisible. Scopes alone confine nothing.
//
// The API gates token creation and deletion behind ReqBasicOrRevProxyAuth — an
// access token can LIST tokens but can neither mint nor revoke them. See
// Credential for what that means for callers.
package forgetoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// maxBody caps a forge API response. Token listings are small; the cap exists so a
// misrouted request (an nginx error page, a login redirect) cannot stream forever.
const maxBody = 4 << 20

// Credential authenticates papi to the forge's token-management API.
//
// Forgejo deliberately refuses to let an access token mint or revoke tokens
// (routers/api/v1/api.go gates POST and DELETE on /users/{username}/tokens behind
// ReqBasicOrRevProxyAuth, which passes only for real password basic-auth or for a
// trusted reverse proxy asserting the user). So BasicCredential is the credential
// that can drive the full lifecycle; TokenCredential reaches only the read paths.
type Credential interface {
	// apply attaches the credential to an outgoing request.
	apply(*http.Request)
	// canMint reports whether the forge will accept this credential KIND on the
	// mint and revoke routes. It is known statically, so the client refuses before
	// making a request the forge is certain to reject.
	canMint() bool
}

// ErrCredentialCannotMint is returned before any request when the credential in hand
// could never mint or revoke. It exists because the forge's own answer is misleading:
// the token-scope gate runs first and reports a missing write:user scope, so a caller
// widening the token's scopes to satisfy that would only uncover the auth-method
// rejection underneath.
var ErrCredentialCannotMint = errors.New(
	"this credential kind cannot mint or revoke forge tokens: the forge accepts only " +
		"password basic-auth or a trusted reverse proxy on those routes, whatever an " +
		"access token's scopes are",
)

func (c *Client) mustMint() error {
	if !c.Cred.canMint() {
		return ErrCredentialCannotMint
	}
	return nil
}

// BasicCredential authenticates as a forge account with its password. This is the
// only credential Forgejo accepts for minting and revoking. OTP carries a TOTP code
// in the X-Forgejo-OTP header for accounts with TOTP enrolled; accounts with
// WebAuthn keys enrolled cannot use basic auth at all.
type BasicCredential struct {
	User     string
	Password string
	OTP      string
}

func (c BasicCredential) apply(r *http.Request) {
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(c.User+":"+c.Password),
	))
	if c.OTP != "" {
		r.Header.Set("X-Forgejo-OTP", c.OTP)
	}
}

func (c BasicCredential) canMint() bool { return true }

// TokenCredential authenticates with an existing access token. Sufficient for
// List (with read:user scope) but rejected by the forge for Mint and Delete — it
// is here so read-only callers need no password.
type TokenCredential struct{ Token string }

func (c TokenCredential) apply(r *http.Request) {
	r.Header.Set("Authorization", "token "+c.Token)
}

func (c TokenCredential) canMint() bool { return false }

// SecretFromCommand runs a shell command and returns its FIRST output line with only
// the line ending removed — the papi convention for keeping a secret out of argv and
// the environment. The canonical value is a piggy read, e.g.
// `piggy pass show forge/krone-password`.
//
// Those two rules are deliberate and shared with inspect.runDecrypt, the §5
// --decrypt-cmd runner, which reads its output identically (papi#78). Taking the
// first line respects the pass-store convention of a secret on line one with notes
// below. Stripping ONLY the line ending — not surrounding space — is what stops a
// secret with significant leading or trailing whitespace being silently corrupted,
// which an earlier TrimSpace here did. A first line that is empty is an error; one
// that is entirely spaces is not, because that is a secret this function has no
// business second-guessing.
func SecretFromCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(bytes.TrimSpace(ee.Stderr)) > 0 {
			return "", fmt.Errorf("secret command %q: %w: %s", command, err, bytes.TrimSpace(ee.Stderr))
		}
		return "", fmt.Errorf("secret command %q: %w", command, err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return "", fmt.Errorf("secret command %q produced no output", command)
	}
	return line, nil
}

// Client talks to one forge's token-management API as one account.
type Client struct {
	HTTP    *http.Client
	BaseURL string // scheme://host[:port], no trailing slash
	User    string // the forge account whose tokens are managed
	Cred    Credential
}

// NewClient builds a client for host (a bare hostname or a URL, defaulting to
// https) managing user's tokens with cred.
func NewClient(host, user string, cred Credential) (*Client, error) {
	if user == "" {
		return nil, errors.New("forge account is required")
	}
	if cred == nil {
		return nil, errors.New("credential is required")
	}
	base, err := normalizeBase(host)
	if err != nil {
		return nil, err
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: base,
		User:    user,
		Cred:    cred,
	}, nil
}

func normalizeBase(host string) (string, error) {
	raw := strings.TrimSpace(host)
	if raw == "" {
		return "", errors.New("forge host is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("forge host %q: %w", host, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("forge host %q has no host component", host)
	}
	return u.Scheme + "://" + u.Host, nil
}

// RepoTarget names one repository on the forge. Owner may be empty before
// ResolveRepo fills it — spinclass's SPINCLASS_FORGE_REPO is owner-less on the
// fleet's vanity remotes (`git@host:<name>.git`).
type RepoTarget struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func (r RepoTarget) String() string {
	if r.Owner == "" {
		return r.Name
	}
	return r.Owner + "/" + r.Name
}

// ParseRepo accepts "owner/name" or a bare "name" (owner left empty for
// ResolveRepo), tolerating a leading slash and a ".git" suffix.
func ParseRepo(s string) (RepoTarget, error) {
	s = strings.TrimSuffix(strings.Trim(strings.TrimSpace(s), "/"), ".git")
	if s == "" {
		return RepoTarget{}, errors.New("repository is required")
	}
	owner, name, found := strings.Cut(s, "/")
	if !found {
		return RepoTarget{Name: owner}, nil
	}
	if owner == "" || name == "" || strings.Contains(name, "/") {
		return RepoTarget{}, fmt.Errorf("repository %q is not owner/name", s)
	}
	return RepoTarget{Owner: owner, Name: name}, nil
}

// Token is a forge access token as the API reports it. Secret carries the token
// itself and is populated ONLY by Mint — the forge shows it exactly once, at
// creation, and never again.
type Token struct {
	ID           int64       `json:"id"`
	Name         string      `json:"name"`
	Secret       string      `json:"sha1"`
	LastEight    string      `json:"token_last_eight"`
	Scopes       []string    `json:"scopes"`
	Repositories []TokenRepo `json:"repositories"`
}

// TokenRepo is one resource row on a token — a repository the token is confined to
// for write. A nil Repositories means the token is user-wide (ResourceAllRepos).
type TokenRepo struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

// FineGrained reports whether the token carries resource rows, i.e. whether its
// write access is confined to specific repositories rather than every repo the
// account can reach.
func (t Token) FineGrained() bool { return len(t.Repositories) > 0 }

// APIError is a non-2xx response from the forge API, carrying the status and the
// server's own message so callers can distinguish the cases that matter (404 on a
// delete = already gone; 401 = the credential is not allowed to mint).
type APIError struct {
	Method  string
	Path    string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, msg)
}

// IsNotFound reports whether err is a 404 — what the forge returns for a token
// that is already gone, which every revoke path treats as success.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// IsAuthMethod reports whether err is the forge refusing the CREDENTIAL KIND
// rather than the caller's identity: ReqBasicOrRevProxyAuth rejects an access
// token on the mint and revoke routes even when the token's scopes are ample.
// Callers use it to explain that a password (or reverse-proxy auth) is required.
func IsAuthMethod(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnauthorized
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rdr *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(encoded)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	c.Cred.apply(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: apiMessage(raw)}
	}
	return raw, nil
}

// apiMessage pulls the forge's {"message": ...} out of an error body, falling back
// to a trimmed prefix of whatever was returned (an nginx error page, say).
func apiMessage(raw []byte) string {
	var envelope struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Message != "" {
		return envelope.Message
	}
	msg := strings.TrimSpace(string(raw))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// createTokenBody is the POST /users/{user}/tokens payload.
//
// Repositories is the single most dangerous field in this package, and the reason
// it carries no `omitempty`. Forgejo reads it as absent-vs-present, not
// empty-vs-non-empty: an OMITTED `repositories` means ResourceAllRepos=true — a
// user-wide token, write to every repo the account can reach — while a PRESENT one
// means ResourceAllRepos=false. `omitempty` would drop an empty list and silently
// mint exactly the user-wide token this feature exists to avoid. Mint refuses an
// empty target set, so the field is always non-empty and always on the wire.
type createTokenBody struct {
	Name         string       `json:"name"`
	Scopes       []string     `json:"scopes"`
	Repositories []RepoTarget `json:"repositories"`
}

// MintRequest describes one token to create.
//
// It carries the session and deadline rather than a rendered name so that the naming
// scheme cannot be bypassed: a token minted under a name this package did not build
// would be invisible to RevokeSession and Sweep, which decode names to find their
// work — an orphan by construction.
type MintRequest struct {
	Session  string       // the session the token belongs to; encoded in its name
	Deadline time.Time    // when Sweep may reap it; zero means never
	Scopes   []string     // category scopes, e.g. write:repository (implies read)
	Repos    []RepoTarget // the repositories to confine write access to; MUST be non-empty
}

// Mint creates a fine-grained token and returns it with Secret populated — the one
// and only time the forge reveals it.
//
// The returned token is confined to Repos: those get full per-scope access, other
// PUBLIC repos degrade to read-only, and other private repos are invisible. Note
// the asymmetry — write is confined to the listed set, read is not.
//
// Mint refuses an empty Repos rather than falling back to a user-wide token, so
// there is no input to this package that can accidentally produce one.
func (c *Client) Mint(ctx context.Context, req MintRequest) (Token, error) {
	if err := c.mustMint(); err != nil {
		return Token{}, err
	}
	if req.Session == "" {
		return Token{}, errors.New("session is required: it names the token so it can be revoked later")
	}
	if len(req.Scopes) == 0 {
		return Token{}, errors.New("at least one scope is required")
	}
	if len(req.Repos) == 0 {
		return Token{}, errors.New(
			"at least one repository is required: an empty target set would mint a user-wide token",
		)
	}
	for _, r := range req.Repos {
		if r.Owner == "" || r.Name == "" {
			return Token{}, fmt.Errorf("repository %q is missing an owner; resolve it first", r)
		}
	}
	raw, err := c.do(ctx, http.MethodPost, c.tokensPath(), createTokenBody{
		Name:         TokenName(req.Session, req.Deadline),
		Scopes:       req.Scopes,
		Repositories: req.Repos,
	})
	if err != nil {
		return Token{}, err
	}
	var tok Token
	if err := json.Unmarshal(raw, &tok); err != nil {
		return Token{}, fmt.Errorf("decode minted token: %w", err)
	}
	if tok.Secret == "" {
		return Token{}, errors.New("forge returned no token value")
	}
	return tok, nil
}

// List returns every access token on the account, including each token's resource
// rows. This is the read path a token credential can drive.
func (c *Client) List(ctx context.Context) ([]Token, error) {
	raw, err := c.do(ctx, http.MethodGet, c.tokensPath(), nil)
	if err != nil {
		return nil, err
	}
	var tokens []Token
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return nil, fmt.Errorf("decode token list: %w", err)
	}
	return tokens, nil
}

// DeleteByID revokes one token. A token that is already gone (404) is reported as
// success, so every revoke path is safely repeatable — spinclass retries a failed
// revoke from its orphan sweep, and a non-idempotent delete would loop forever.
//
// Deleting by numeric id rather than by name is deliberate: the by-name route
// fails with 422 when several tokens share a name, and a repeated session key
// could produce exactly that.
func (c *Client) DeleteByID(ctx context.Context, id int64) error {
	if err := c.mustMint(); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodDelete, c.tokensPath()+"/"+strconv.FormatInt(id, 10), nil)
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

func (c *Client) tokensPath() string {
	return "/api/v1/users/" + url.PathEscape(c.User) + "/tokens"
}

// ResolveRepo fills in a missing owner by searching the forge for a repository of
// that name. spinclass derives SPINCLASS_FORGE_REPO from the remote URL path, so on
// the fleet's owner-less vanity remotes (`git@host:<name>.git`) it arrives bare;
// the resource row needs a real owner/name pair.
//
// An ambiguous name is an error naming the candidates rather than a guess — picking
// the wrong one would mint a token for the wrong repository.
func (c *Client) ResolveRepo(ctx context.Context, target RepoTarget) (RepoTarget, error) {
	if target.Name == "" {
		return RepoTarget{}, errors.New("repository name is required")
	}
	if target.Owner != "" {
		return target, nil
	}
	raw, err := c.do(ctx, http.MethodGet,
		"/api/v1/repos/search?limit=50&q="+url.QueryEscape(target.Name), nil)
	if err != nil {
		return RepoTarget{}, fmt.Errorf("resolve owner for repository %q: %w", target.Name, err)
	}
	var found struct {
		Data []struct {
			Name  string `json:"name"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return RepoTarget{}, fmt.Errorf("decode repository search: %w", err)
	}
	var matches []RepoTarget
	for _, r := range found.Data {
		// The search is substring-based; only an exact name match identifies the
		// repository the caller meant.
		if strings.EqualFold(r.Name, target.Name) && r.Owner.Login != "" {
			matches = append(matches, RepoTarget{Owner: r.Owner.Login, Name: r.Name})
		}
	}
	switch len(matches) {
	case 0:
		return RepoTarget{}, fmt.Errorf(
			"no repository named %q is visible to this credential; pass an explicit owner/name", target.Name,
		)
	case 1:
		return matches[0], nil
	default:
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.String()
		}
		return RepoTarget{}, fmt.Errorf(
			"repository name %q is ambiguous (%s); pass an explicit owner/name",
			target.Name, strings.Join(names, ", "),
		)
	}
}
