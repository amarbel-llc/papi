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
	"time"
)

// maxBody caps a single response read so a hostile or runaway endpoint cannot
// exhaust memory.
const maxBody = 8 << 20

// Client fetches PAPI resources from a single base URL.
type Client struct {
	HTTP    *http.Client
	BaseURL string // scheme://host[:port], no trailing slash
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
	t := strings.TrimSpace(target)
	if t == "" {
		return "", fmt.Errorf("empty domain")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", target, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("no host in %q", target)
	}
	return u.Scheme + "://" + u.Host, nil
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
	return c.do(ctx, http.MethodGet, path, "", nil)
}

// Post performs POST path with a JSON request body and returns the raw response.
func (c *Client) Post(ctx context.Context, path string, jsonBody []byte) (*Response, error) {
	return c.do(ctx, http.MethodPost, path, "application/json", jsonBody)
}

func (c *Client) do(ctx context.Context, method, path, contentType string, reqBody []byte) (*Response, error) {
	var rdr io.Reader
	if reqBody != nil {
		rdr = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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
	body, status, err := c.get(ctx, "/.well-known/papi")
	if err != nil {
		return nil, status, err
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("discovery returned HTTP %d", status)
	}
	d, err := decodeDiscovery(body)
	return d, status, err
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
}

// Person is the document's subject block (RFC-0001 §1).
type Person struct {
	Handle  string   `json:"handle"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
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
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, status, fmt.Errorf("/papi is not JSON: %w", err)
	}
	data := env.Data
	if len(data) == 0 {
		data = body // tolerate an un-enveloped document
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, env.Meta, status, fmt.Errorf("/papi data: %w", err)
	}
	return &doc, env.Meta, status, nil
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
