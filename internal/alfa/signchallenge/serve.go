package signchallenge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amarbel-llc/papi/internal/alfa/authproxy"
)

// maxBody caps a request/response body the oracle reads. Challenges and sessions
// are a few small fields; 64 KiB is generous slack, not a real limit.
const maxBody = 64 << 10

// ServeConfig configures the loopback/tailnet card oracle served by Handler.
type ServeConfig struct {
	// Signer is the slot-9A byte-signer (enroll.PiggySignBytesSigner or
	// enroll.AgentSignBytesSigner). Required.
	Signer Signer
	// GUID selects the card; empty lets the signer pick when only one is present.
	GUID string
	// Domain is the PAPI identity domain the §5.2 signature binds to — fixed here,
	// never read from the request (the challenge never echoes it; relay defense).
	Domain string
	// Origin is the single browser origin CORS is pinned to (for /sign and /login).
	Origin string
	// Target is the PAPI base URL (e.g. https://api.linenisgreat.com) the /login and
	// /authorize flows call server-side. When empty, only /sign is served.
	Target string
	// HTTPClient is used for the broker's PAPI calls; defaults to a 20s client.
	HTTPClient *http.Client
	// Logger receives per-request and error logs; defaults to slog.Default().
	Logger *slog.Logger

	// --- Attestation (the /authorize browser flow → the FDR-0014 auth-proxy
	// verifier). When AttestKey is set (plus Target + AuthKeyID), /authorize is
	// served: a browser navigation runs the §5 card login with THIS host's card and
	// redirects to a verifier callback with an Ed25519-signed attestation. ---

	// AttestKey is the oracle's Ed25519 PRIVATE key; it signs attestations. Held only
	// on the card machine.
	AttestKey ed25519.PrivateKey
	// AuthKeyID is this card's published slot-9A id, used as the §5 challenge subject
	// in the /authorize flow (the browser supplies none).
	AuthKeyID string
	// AllowCallbacks is the exact set of verifier callback URLs /authorize may attest
	// to — the guard that stops a malicious page from coaxing a card attestation for
	// an attacker's audience.
	AllowCallbacks []string
}

// Handler is the card oracle for the RFC-0001 §5.2 sign-challenge handshake
// (papi#36). Routes:
//
//   - POST /sign  — signing oracle: a §5.1 challenge JSON in → the §5.2
//     {challenge_id, signature} body out (the backend/plugin seam).
//   - POST /login — handshake broker (when Target is set): {auth_key_id} in → the
//     minted session out, running discovery→challenge→sign→response server-side.
//   - GET  /authorize — attest flow (when AttestKey+Target+AuthKeyID are set): a
//     browser navigation runs the §5 card login with this host's card and 302s to a
//     verifier callback with an Ed25519 attestation (FDR-0014, client-side signing).
//
// Security envelope: card + PIN gate every signature. /sign and /login pin CORS to
// Origin. /authorize is a top-level navigation (no CORS) but only attests to an
// allowlisted callback. When bound beyond loopback, treat the host as the card
// machine on a trusted network.
func Handler(cfg ServeConfig) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", withLogging(logger, "/sign", signHandler(cfg)))
	if cfg.Target != "" {
		mux.HandleFunc("/login", withLogging(logger, "/login", loginHandler(cfg, logger)))
	}
	if cfg.AttestKey != nil && cfg.Target != "" && cfg.AuthKeyID != "" {
		mux.HandleFunc("/authorize", withLogging(logger, "/authorize", authorizeHandler(cfg, logger)))
	}
	return mux
}

// statusRecorder captures the response status so the logging middleware can report
// it (net/http exposes no read-back of the written code).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// withLogging logs one line per request — route, method, status, duration, remote —
// at a level keyed to the status class (Info <400, Warn 4xx, Error 5xx).
func withLogging(logger *slog.Logger, route string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case rec.status >= 400:
			level = slog.LevelWarn
		}
		logger.LogAttrs(r.Context(), level, "request",
			slog.String("route", route),
			slog.String("method", r.Method),
			slog.Int("status", rec.status),
			slog.Duration("dur", time.Since(start)),
			slog.String("remote", r.RemoteAddr),
		)
	}
}

// signHandler is the POST /sign signing oracle: §5.1 challenge JSON in → §5.2
// {challenge_id, signature} out.
func signHandler(cfg ServeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w, cfg.Origin)
		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
		default:
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			http.Error(w, "read challenge body: "+err.Error(), http.StatusBadRequest)
			return
		}
		ch, err := ParseChallenge(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := Sign(r.Context(), cfg.Signer, cfg.GUID, cfg.Domain, ch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// loginHandler is the POST /login broker: {auth_key_id} in → the minted session out.
func loginHandler(cfg ServeConfig, logger *slog.Logger) http.HandlerFunc {
	httpc := brokerClient(cfg)
	base := strings.TrimRight(cfg.Target, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w, cfg.Origin)
		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
		default:
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AuthKeyID string `json:"auth_key_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
			http.Error(w, "decode request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.AuthKeyID == "" {
			http.Error(w, "auth_key_id required", http.StatusBadRequest)
			return
		}
		sess, leg, err := runHandshake(r.Context(), httpc, base, cfg, req.AuthKeyID)
		if err != nil {
			logger.LogAttrs(r.Context(), slog.LevelError, "login leg failed",
				slog.String("leg", leg), slog.String("err", err.Error()))
			http.Error(w, leg+": "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(sess)
	}
}

// authorizeHandler is the GET /authorize attest flow: validate the verifier callback
// (allowlist), run the §5 card login with this host's card, and 302 to the callback
// with an Ed25519 attestation the verifier can check against the oracle's public key.
func authorizeHandler(cfg ServeConfig, logger *slog.Logger) http.HandlerFunc {
	httpc := brokerClient(cfg)
	base := strings.TrimRight(cfg.Target, "/")
	allowed := make(map[string]bool, len(cfg.AllowCallbacks))
	for _, c := range cfg.AllowCallbacks {
		allowed[c] = true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		callback, state, nonce := q.Get("callback"), q.Get("state"), q.Get("nonce")
		if callback == "" || state == "" || nonce == "" {
			http.Error(w, "callback, state, and nonce are required", http.StatusBadRequest)
			return
		}
		if !allowed[callback] {
			logger.Warn("authorize: callback not in allowlist", "callback", callback)
			http.Error(w, "callback not allowed", http.StatusForbidden)
			return
		}
		aud, err := originOf(callback)
		if err != nil {
			http.Error(w, "bad callback: "+err.Error(), http.StatusBadRequest)
			return
		}
		raw, leg, err := runHandshake(r.Context(), httpc, base, cfg, cfg.AuthKeyID)
		if err != nil {
			logger.LogAttrs(r.Context(), slog.LevelError, "authorize leg failed",
				slog.String("leg", leg), slog.String("err", err.Error()))
			http.Error(w, leg+": "+err.Error(), http.StatusBadGateway)
			return
		}
		var sess struct {
			Principal string   `json:"principal"`
			Groups    []string `json:"groups"`
			ExpiresAt int64    `json:"expires_at"`
		}
		if err := json.Unmarshal(raw, &sess); err != nil {
			http.Error(w, "session decode: "+err.Error(), http.StatusBadGateway)
			return
		}
		att, err := authproxy.MintAttest(cfg.AttestKey, authproxy.AttestClaims{
			Principal:  sess.Principal,
			Groups:     sess.Groups,
			Nonce:      nonce,
			Aud:        aud,
			SessionExp: sess.ExpiresAt,
			Exp:        time.Now().Add(2 * time.Minute).Unix(),
		})
		if err != nil {
			http.Error(w, "attest: "+err.Error(), http.StatusInternalServerError)
			return
		}
		u, _ := url.Parse(callback)
		cq := u.Query()
		cq.Set("att", att)
		cq.Set("state", state)
		u.RawQuery = cq.Encode()
		logger.Info("authorize: attested", "principal", sess.Principal, "aud", aud)
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

// runHandshake runs the §5 broker login (discovery → challenge → sign → response)
// for authKeyID and returns the unwrapped session JSON. On failure it names the leg
// (discovery/challenge/sign/response) so callers can report/log it.
func runHandshake(ctx context.Context, httpc *http.Client, base string, cfg ServeConfig, authKeyID string) (session []byte, leg string, err error) {
	auth, err := fetchDiscoveryAuth(ctx, httpc, base)
	if err != nil {
		return nil, "discovery", err
	}
	chRaw, err := postJSON(ctx, httpc, auth.Challenge, map[string]string{"auth_key_id": authKeyID})
	if err != nil {
		return nil, "challenge", err
	}
	ch, err := ParseChallenge(unwrapData(chRaw))
	if err != nil {
		return nil, "challenge", err
	}
	resp, err := Sign(ctx, cfg.Signer, cfg.GUID, cfg.Domain, ch)
	if err != nil {
		return nil, "sign", err
	}
	sessRaw, err := postJSON(ctx, httpc, auth.Response, resp)
	if err != nil {
		return nil, "response", err
	}
	return unwrapData(sessRaw), "", nil
}

func brokerClient(cfg ServeConfig) *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// originOf returns the scheme://host of a URL (the attestation audience).
func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("not an absolute URL: %q", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// discoveryAuth is the §4.1 discovery doc's auth block — the challenge/response URLs
// the broker posts to.
type discoveryAuth struct {
	Scheme    string `json:"scheme"`
	Challenge string `json:"challenge"`
	Response  string `json:"response"`
}

// fetchDiscoveryAuth GETs <base>/.well-known/papi and returns its auth block,
// accepting both the bare object and the reference impl's {data, meta} envelope.
func fetchDiscoveryAuth(ctx context.Context, httpc *http.Client, base string) (discoveryAuth, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/papi", nil)
	if err != nil {
		return discoveryAuth{}, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := httpc.Do(req)
	if err != nil {
		return discoveryAuth{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return discoveryAuth{}, fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var env struct {
		Data *struct {
			Auth discoveryAuth `json:"auth"`
		} `json:"data"`
		Auth *discoveryAuth `json:"auth"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return discoveryAuth{}, fmt.Errorf("decode discovery: %w", err)
	}
	auth := discoveryAuth{}
	switch {
	case env.Data != nil:
		auth = env.Data.Auth
	case env.Auth != nil:
		auth = *env.Auth
	}
	if auth.Challenge == "" || auth.Response == "" {
		return discoveryAuth{}, fmt.Errorf("discovery advertises no §5 auth challenge/response URLs")
	}
	return auth, nil
}

// postJSON POSTs body as JSON to url and returns the raw response body, erroring on
// a non-2xx status (with the status and body for diagnosis).
func postJSON(ctx context.Context, httpc *http.Client, url string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(rb)))
	}
	return rb, nil
}

// unwrapData returns the inner object of a {"data": …, "meta": …} envelope — the
// reference server's response shape for /papi/auth/challenge and /papi/auth/response
// (and discovery) — or the body unchanged when there is no such envelope.
func unwrapData(raw []byte) []byte {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data) > 0 {
		return env.Data
	}
	return raw
}

// setCORS pins the response to the configured origin and advertises the methods and
// headers the §5 calls use. Access-Control-Allow-Private-Network answers Chrome's
// PNA preflight for an HTTPS/remote page reaching this oracle.
func setCORS(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Allow-Private-Network", "true")
	h.Add("Vary", "Origin")
}
