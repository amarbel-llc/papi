// Package papi is a client for the Personal API (PAPI) wire format (RFC-0001):
// it fetches and decodes the discovery document and the projected document.
// Entry shapes are kept lenient so introspection tolerates reference-impl
// variance — unknown members are ignored and missing members decode to zero.
package papi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxBody caps a single response read so a hostile or runaway endpoint cannot
// exhaust memory.
const maxBody = 8 << 20

// Client fetches PAPI resources. BaseURL is the identity base — where
// /.well-known/papi lives. serving is the API base for /papi/* requests,
// resolved once from the discovery document's resources[] (RFC §8.1), since the
// serving host may differ from the identity domain (e.g. example.com →
// api.example.com). resolveOnce guards that one-time lookup.
type Client struct {
	HTTP        *http.Client
	BaseURL     string // identity base: scheme://host[:port], no trailing slash
	serving     string // API base for /papi/*; resolved from discovery, else == BaseURL
	resolveOnce sync.Once
}

// NewClient resolves target (a bare domain or a URL) into a base URL, defaulting
// to https when no scheme is given.
func NewClient(target string) (*Client, error) {
	base, err := normalizeBase(target)
	if err != nil {
		return nil, err
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		BaseURL: base,
	}, nil
}

func normalizeBase(target string) (string, error) {
	u, err := parseTarget(target)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// parseTarget normalizes target (a bare domain or a URL) to a *url.URL,
// defaulting to https when no scheme is given, and erroring on empty input or a
// missing host. It is the single normalization codepath behind normalizeBase and
// NormalizeBaseHost.
func parseTarget(target string) (*url.URL, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, fmt.Errorf("empty domain")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", target, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("no host in %q", target)
	}
	return u, nil
}

// NormalizeBaseHost returns just the host[:port] of a bare-domain-or-URL target,
// with scheme, path, and query stripped (https assumed for scheme inference). It
// is the stable identity papi ssh-sync derives a managed-file name from, so the
// same domain maps to the same file regardless of how the caller spelled it
// (example.com, https://example.com, https://example.com/foo all → example.com).
func NormalizeBaseHost(target string) (string, error) {
	u, err := parseTarget(target)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

// Response is a raw PAPI HTTP response captured for conformance checks that must
// inspect the wire bytes and headers directly.
type Response struct {
	Path        string
	Status      int
	ContentType string
	Body        []byte
}

func (c *Client) get(ctx context.Context, path string) ([]byte, int, error) {
	resp, err := c.Fetch(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.Status, nil
}

// Fetch performs GET path and returns the raw response (status, Content-Type,
// body) without decoding.
func (c *Client) Fetch(ctx context.Context, path string) (*Response, error) {
	return c.do(ctx, http.MethodGet, path, "", nil, "")
}

// FetchAuthed performs GET path presenting a PiggySession (§5.3) and returns the
// raw response.
func (c *Client) FetchAuthed(ctx context.Context, path, session string) (*Response, error) {
	return c.do(ctx, http.MethodGet, path, "", nil, session)
}

// Post performs POST path with a JSON request body and returns the raw response.
func (c *Client) Post(ctx context.Context, path string, jsonBody []byte) (*Response, error) {
	return c.do(ctx, http.MethodPost, path, "application/json", jsonBody, "")
}

func (c *Client) do(ctx context.Context, method, path, contentType string, reqBody []byte, session string) (*Response, error) {
	return c.doAt(ctx, c.servingBase(ctx), method, path, contentType, reqBody, session)
}

// doAt performs the HTTP request against an explicit base, bypassing discovery
// resolution. It serves both the resolved serving base (for /papi/* requests) and
// the identity base (to fetch /.well-known/papi without recursing into
// servingBase).
func (c *Client) doAt(ctx context.Context, base, method, path, contentType string, reqBody []byte, session string) (*Response, error) {
	var rdr io.Reader
	if reqBody != nil {
		rdr = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if session != "" {
		req.Header.Set("Authorization", "PiggySession "+session)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	return &Response{Path: path, Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: body}, nil
}

// servingBase returns the API base for /papi/* requests, resolving it once from
// the discovery document (RFC §8.1): it GETs <identity>/.well-known/papi and
// derives the base from its resources[] URLs. It falls back to the identity base
// when discovery is absent, unreachable, or carries no usable resources — so a
// same-host or pre-discovery server behaves exactly as before, while a split-host
// server (identity domain ≠ serving host) is followed correctly.
func (c *Client) servingBase(ctx context.Context) string {
	c.resolveOnce.Do(func() {
		c.serving = c.BaseURL
		resp, err := c.doAt(ctx, c.BaseURL, http.MethodGet, "/.well-known/papi", "", nil, "")
		if err != nil || resp.Status != http.StatusOK {
			return
		}
		d, err := decodeDiscovery(resp.Body)
		if err != nil {
			return
		}
		if base := servingBaseFromResources(d.Resources); base != "" {
			c.serving = base
		}
	})
	return c.serving
}

// resourceSuffixes are the §4 endpoint paths a discovery resources[] URL ends
// with, ordered so a longer path is tried before the bare "/papi". They let
// servingBaseFromResources recover the API base from any resource URL by
// stripping the known suffix — key-name-agnostic, and tolerant of a path prefix.
var resourceSuffixes = []string{
	"/papi/ssh-authorized-keys", "/papi/organizations", "/papi/piggy-ids",
	"/papi/templates", "/papi/sitemap", "/papi/forges", "/papi/proofs",
	"/papi/caches", "/papi/repos", "/papi",
}

// servingBaseFromResources derives the API base (scheme://host[/prefix]) from the
// discovery resources[] map: it parses each absolute URL and, on the first whose
// path ends with a known §4 endpoint suffix, strips that suffix. Returns "" when
// no resource yields a base (the caller keeps the identity base).
func servingBaseFromResources(resources map[string]string) string {
	for _, raw := range resources {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		for _, suf := range resourceSuffixes {
			if strings.HasSuffix(u.Path, suf) {
				return strings.TrimRight(u.Scheme+"://"+u.Host+strings.TrimSuffix(u.Path, suf), "/")
			}
		}
	}
	return ""
}

// Envelope is the {data, meta} response envelope (RFC-0001 §4.2). The reference
// implementation wraps even the discovery document this way.
type Envelope struct {
	Data json.RawMessage `json:"data"`
	Meta map[string]any  `json:"meta"`
}

// Discovery is the GET /.well-known/papi document (RFC-0001 §4.1).
type Discovery struct {
	Version   string            `json:"version"`
	Handle    string            `json:"handle"`
	Resources map[string]string `json:"resources"`
	Auth      *DiscoveryAuth    `json:"auth"`
}

// DiscoveryAuth is the discovery doc's auth block (RFC-0001 §4.1).
type DiscoveryAuth struct {
	Scheme           string `json:"scheme"`
	Challenge        string `json:"challenge"`
	Response         string `json:"response"`
	PresentSessionAs string `json:"present_session_as"`
}

// Discovery fetches and decodes GET /.well-known/papi, accepting both the bare
// object and the reference impl's {data, meta} envelope.
func (c *Client) Discovery(ctx context.Context) (*Discovery, int, error) {
	// Discovery always lives at the identity base, so it bypasses serving
	// resolution (doAt) — fetching it here is also what servingBase consumes.
	resp, err := c.doAt(ctx, c.BaseURL, http.MethodGet, "/.well-known/papi", "", nil, "")
	if err != nil {
		return nil, 0, err
	}
	if resp.Status != http.StatusOK {
		return nil, resp.Status, fmt.Errorf("discovery returned HTTP %d", resp.Status)
	}
	d, err := decodeDiscovery(resp.Body)
	return d, resp.Status, err
}

// ServingDiscovery fetches and decodes GET /.well-known/papi from the API serving
// base (§8.1) — the canonical discovery for a split-host domain, where the identity
// domain may host only a static stub that points here. Because the serving host is
// the one that implements the auth endpoints, its discovery carries the
// authoritative `auth` block (§4.1, §5); the identity-domain stub can advertise a
// stale scheme. A client selecting a §5 scheme MUST read it from this document. When
// the domain is not split (serving base == identity base), this is the same document
// as Discovery.
func (c *Client) ServingDiscovery(ctx context.Context) (*Discovery, int, error) {
	base := c.servingBase(ctx)
	resp, err := c.doAt(ctx, base, http.MethodGet, "/.well-known/papi", "", nil, "")
	if err != nil {
		return nil, 0, err
	}
	if resp.Status != http.StatusOK {
		return nil, resp.Status, fmt.Errorf("serving discovery returned HTTP %d", resp.Status)
	}
	d, err := decodeDiscovery(resp.Body)
	return d, resp.Status, err
}

func decodeDiscovery(body []byte) (*Discovery, error) {
	var d Discovery
	if err := json.Unmarshal(body, &d); err == nil && (d.Version != "" || len(d.Resources) > 0) {
		return &d, nil
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("discovery is not JSON: %w", err)
	}
	if len(env.Data) == 0 {
		return nil, fmt.Errorf("discovery lacks version/resources and carries no data envelope")
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return nil, fmt.Errorf("discovery data: %w", err)
	}
	return &d, nil
}

// Document is the projected full PAPI document from GET /papi (RFC-0001 §1).
type Document struct {
	Version       string                     `json:"version"`
	Person        *Person                    `json:"person"`
	Piggy         *Piggy                     `json:"piggy"`
	Forges        []Forge                    `json:"forges"`
	Organizations []Organization             `json:"organizations"`
	Sitemap       map[string]json.RawMessage `json:"sitemap"`
	Templates     []Template                 `json:"templates"`
	Proofs        []Proof                    `json:"proofs"`
	CoLocation    []CoLocation               `json:"co_location"`
	Caches        []Cache                    `json:"caches"`
	Profiles      []Profile                  `json:"profiles"`
	Signatures    []Signature                `json:"signatures"`
	Signature     *Signature                 `json:"signature"`
}

// Proof is an identity-ownership proof entry (RFC-0001 §9.1).
type Proof struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
	Claim     string `json:"claim"`
	ProofURI  string `json:"proof_uri"`
	Service   string `json:"service"`
	Fmt       string `json:"fmt"`
}

// CoLocation is a key-co-location proof entry (RFC-0001 §9.6): it binds a
// published slot-9D recipient to a published slot-9A key at a recorded assurance
// Level ("soft", "co-control", or "attested"). Claim is the exact signed statement
// and Sig is the slot-9A signature (a papi-proof-sig-v1 markl-id) over it.
type CoLocation struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
	Key       string `json:"key"`
	Level     string `json:"level"`
	Claim     string `json:"claim"`
	Sig       string `json:"sig"`
}

// Signature is a detached document signature entry (RFC-0001 §10.1). It serves
// both forms: the Amendment 9 `signatures[]` entry, where Key and Sig are
// markl-ids and Alg is absent; and the legacy singular `signature`, where
// Alg is "ssh-9a", Key is an OpenSSH line, and Sig is base64.
type Signature struct {
	Alg     string `json:"alg"`
	Key     string `json:"key"`
	Sig     string `json:"sig"`
	Created int64  `json:"created"`
}

// Person is the document's subject block (RFC-0001 §1). DisplayName mirrors the
// reference impl's `display_name`; Contact is the ACL-gated `person.contact`
// node (§2, §6) that the anonymous tier strips and the §5 authenticated tier
// reveals. Lenient as ever: unknown members ignored, missing → zero.
type Person struct {
	Handle      string   `json:"handle"`
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Domains     []string `json:"domains"`
	Contact     *Contact `json:"contact"`
}

// Contact is the gated contact node nested under person (RFC-0001 §6). It is
// present only when the principal satisfies the node's acl.
type Contact struct {
	Email string `json:"email"`
}

// Piggy carries the encryption recipients and SSH keys (RFC-0001 §1). Entry
// shapes are kept as raw messages because the wire shape is reference-impl
// defined; introspection reports counts, which are always accurate.
type Piggy struct {
	EncryptionRecipients []json.RawMessage `json:"encryption_recipients"`
	SSHAuthorizedKeys    []json.RawMessage `json:"ssh_authorized_keys"`
}

// Forge is a forge identity with its repos (RFC-0001 §1.1).
type Forge struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Repos []json.RawMessage `json:"repos"`
}

// Organization is an org account with its repos (RFC-0001 §1).
type Organization struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Repos []json.RawMessage `json:"repos"`
}

// Template is an advertised flake template (RFC-0001 §7.1).
type Template struct {
	ID          string `json:"id"`
	Flakeref    string `json:"flakeref"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
}

// Cache is an advertised nix binary cache / substituter (RFC-0001 §11.1).
// TrustedPublicKeys is an array — not a single key — so a cache mid-rotation can
// publish both its outgoing and incoming keys.
type Cache struct {
	ID                string   `json:"id"`
	URL               string   `json:"url"`
	TrustedPublicKeys []string `json:"trusted_public_keys"`
	Priority          int      `json:"priority"`
	Kind              string   `json:"kind"`
}

// Repo is a flattened, provenance-annotated repository entry from the
// GET /papi/repos endpoint (RFC-0001 §1.1, §4). Lenient: unknown members are
// ignored, missing ones default to zero.
type Repo struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	Owner         string `json:"owner"`
	Forge         string `json:"forge"`
	Kind          string `json:"kind"`
	Visibility    string `json:"visibility"`
	DefaultBranch string `json:"default_branch"`
	Description   string `json:"description"`
	Canonical     bool   `json:"canonical,omitempty"`
}

// Profile is a host-profile entry from the GET /papi/profiles endpoint (RFC-0001
// §13.1, Amendments 11–12): a flakeref a staged installer activates. On a
// `nixos-configuration` entry, HomeFlakeref names the host's standalone
// homeConfiguration (applied via standalone home-manager). Lenient: unknown
// members ignored, missing ones default to zero.
type Profile struct {
	ID           string `json:"id"`
	Flakeref     string `json:"flakeref"`
	HomeFlakeref string `json:"home_flakeref"`
	Description  string `json:"description"`
	Platform     string `json:"platform"`
	Kind         string `json:"kind"`
}

// DecodeEnvelope unwraps a {data, meta} response body (RFC-0001 §4.2), returning
// the data bytes and the meta block. Every JSON endpoint MUST wrap its payload in
// the envelope (§4.2; only the text/plain endpoints are exempt, and the discovery
// document is decoded separately as a spec-literal bare object, §4.1), so a body
// with no `data` member is non-conformant and rejected rather than read at the top
// level. A lenient fallback here is precisely what let the auth-handshake client
// read responses off the wrong nesting level undetected. It is the pure,
// network-free core the fetching Client methods and the wasm client (FDR-0007)
// share.
func DecodeEnvelope(body []byte) (json.RawMessage, map[string]any, error) {
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, fmt.Errorf("not JSON: %w", err)
	}
	if len(env.Data) == 0 {
		return nil, env.Meta, fmt.Errorf("response is not the §4.2 {data,meta} envelope: no \"data\" member")
	}
	return env.Data, env.Meta, nil
}

// DecodeDocument decodes a GET /papi body into the projected Document plus the raw
// meta block (RFC-0001 §1). Pure / network-free (FDR-0007).
func DecodeDocument(body []byte) (*Document, map[string]any, error) {
	data, meta, err := DecodeEnvelope(body)
	if err != nil {
		return nil, nil, err
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, meta, fmt.Errorf("/papi data: %w", err)
	}
	return &doc, meta, nil
}

// DecodeRepos decodes a GET /papi/repos body into the flattened repository list.
func DecodeRepos(body []byte) ([]Repo, error) {
	data, _, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var repos []Repo
	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, fmt.Errorf("/papi/repos data: %w", err)
	}
	return repos, nil
}

// DecodeProfiles decodes a GET /papi/profiles body into the host-profile list
// (RFC-0001 §13).
func DecodeProfiles(body []byte) ([]Profile, error) {
	data, _, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var profiles []Profile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, fmt.Errorf("/papi/profiles data: %w", err)
	}
	return profiles, nil
}

// DecodeCaches decodes a GET /papi/caches body into the nix binary-cache list
// (RFC-0001 §11).
func DecodeCaches(body []byte) ([]Cache, error) {
	data, _, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var caches []Cache
	if err := json.Unmarshal(data, &caches); err != nil {
		return nil, fmt.Errorf("/papi/caches data: %w", err)
	}
	return caches, nil
}

// DecodeDiscovery decodes a GET /.well-known/papi body into the Discovery document
// (RFC-0001 §4.1), accepting both the bare object and the {data, meta} envelope.
func DecodeDiscovery(body []byte) (*Discovery, error) { return decodeDiscovery(body) }

// envelope GETs path, requires 200, and returns the unwrapped {data,meta} data
// bytes plus the meta block via DecodeEnvelope.
func (c *Client) envelope(ctx context.Context, path string) (json.RawMessage, map[string]any, int, error) {
	body, status, err := c.get(ctx, path)
	if err != nil {
		return nil, nil, status, err
	}
	if status != http.StatusOK {
		return nil, nil, status, fmt.Errorf("%s returned HTTP %d", path, status)
	}
	data, meta, err := DecodeEnvelope(body)
	if err != nil {
		return nil, nil, status, fmt.Errorf("%s: %w", path, err)
	}
	return data, meta, status, nil
}

// Document fetches GET /papi and returns the projected document (unwrapping the
// envelope when present) plus the raw meta block.
func (c *Client) Document(ctx context.Context) (*Document, map[string]any, int, error) {
	body, status, err := c.get(ctx, "/papi")
	if err != nil {
		return nil, nil, status, err
	}
	if status != http.StatusOK {
		return nil, nil, status, fmt.Errorf("/papi returned HTTP %d", status)
	}
	doc, meta, err := DecodeDocument(body)
	return doc, meta, status, err
}

// Repos fetches GET /papi/repos and returns the flattened repository list,
// unwrapping the {data,meta} envelope.
func (c *Client) Repos(ctx context.Context) ([]Repo, int, error) {
	body, status, err := c.get(ctx, "/papi/repos")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("/papi/repos returned HTTP %d", status)
	}
	repos, err := DecodeRepos(body)
	return repos, status, err
}

// Profiles fetches GET /papi/profiles and returns the projected host-profile list,
// unwrapping the {data,meta} envelope (RFC-0001 §13.3). Host profiles are commonly
// §5-gated; an unauthenticated fetch returns only the anonymous-visible set
// (possibly empty).
func (c *Client) Profiles(ctx context.Context) ([]Profile, int, error) {
	body, status, err := c.get(ctx, "/papi/profiles")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("/papi/profiles returned HTTP %d", status)
	}
	profiles, err := DecodeProfiles(body)
	return profiles, status, err
}

// Forges fetches GET /papi/forges and returns its projected array as a generic JSON
// value, unwrapping the {data,meta} envelope. Deliberately generic (not the typed
// Forge): RFC-0001 §1.1 forge entries carry id/kind/base_url/identity/repos[] and the
// server MAY add fields (e.g. ssh_clone) that clients MUST pass through unchanged — a
// clone consumer reads a forge's clone channel from them. Unauthenticated → only public
// forges; the CLI's --recipient fetches the full scoped set.
func (c *Client) Forges(ctx context.Context) (any, int, error) {
	data, _, status, err := c.envelope(ctx, "/papi/forges")
	if err != nil {
		return nil, status, err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, status, fmt.Errorf("/papi/forges data: %w", err)
	}
	return v, status, nil
}

// RawDocument fetches GET /papi and returns its projected data as a generic JSON
// value (map/slice/scalar), unwrapping the envelope — for ad-hoc querying over
// the whole document (the `papi query` facility).
func (c *Client) RawDocument(ctx context.Context) (any, int, error) {
	data, _, status, err := c.envelope(ctx, "/papi")
	if err != nil {
		return nil, status, err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, status, fmt.Errorf("/papi data: %w", err)
	}
	return v, status, nil
}

// RecipientPrefix is the slot-9D encryption-recipient id prefix (RFC-0001 §5.1:
// `piggy-recipient-v1@pivy_ecdh_p256_pub-…`). Slot-9A SSH auth ids carry a
// different prefix (`piggy-piv_auth-v1@…`) and are not encryption recipients.
const RecipientPrefix = "piggy-recipient-v1@"

// PiggyIDs fetches GET /papi/piggy-ids and returns the raw text/plain body — the
// piggy-ids file (comment lines, then one piggy id per line). It is not
// enveloped (RFC-0001 §4.2).
func (c *Client) PiggyIDs(ctx context.Context) (body []byte, status int, err error) {
	body, status, err = c.get(ctx, "/papi/piggy-ids")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("/papi/piggy-ids returned HTTP %d", status)
	}
	return body, status, nil
}

// SSHAuthorizedKeys fetches GET /papi/ssh-authorized-keys and returns the raw
// text/plain body — one OpenSSH authorized_keys line per visible slot-9A key,
// each annotated with `guid=<HEX>` and `cn=<name>` (RFC-0001 §4.2). It is not
// enveloped.
func (c *Client) SSHAuthorizedKeys(ctx context.Context) (body []byte, status int, err error) {
	body, status, err = c.get(ctx, "/papi/ssh-authorized-keys")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("/papi/ssh-authorized-keys returned HTTP %d", status)
	}
	return body, status, nil
}

// Bootstrap fetches GET /papi/bootstrap and returns the raw text/plain body — the
// self-bootstrap shim a cold, YubiKey-provisioned host runs to provision itself
// against eng (RFC-0001 §4.2). The shim's contents are owned and version-
// controlled in eng (bin/provision.sh); PAPI only hosts them. Public (no
// auth at fetch — gating it behind §5 would be circular) and optional per-domain;
// it is not enveloped.
func (c *Client) Bootstrap(ctx context.Context) (body []byte, status int, err error) {
	body, status, err = c.get(ctx, "/papi/bootstrap")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("/papi/bootstrap returned HTTP %d", status)
	}
	return body, status, nil
}

// FilterRecipients returns the bare encryption-recipient ids of a piggy-ids file
// — the first token of each line whose id begins with RecipientPrefix — dropping
// comment lines, slot-9A auth ids, and any trailing `  # <label>`. This is
// exactly piggy's encrypt-to set: its RecipientFile parser keys on the bare id
// (the label is cosmetic), so a bare-id list feeds the encryptor cleanly.
func FilterRecipients(body []byte) []string {
	var recipients []string
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, RecipientPrefix) {
			continue
		}
		recipients = append(recipients, strings.Fields(trimmed)[0])
	}
	return recipients
}
