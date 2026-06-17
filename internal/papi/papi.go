// Package papi is a client for the Personal API (PAPI) wire format (RFC-0001):
// it fetches and decodes the discovery document and the projected document.
// Entry shapes are kept lenient so introspection tolerates reference-impl
// variance — unknown members are ignored and missing members decode to zero.
package papi

import (
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

func (c *Client) get(ctx context.Context, path string) (body []byte, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
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
