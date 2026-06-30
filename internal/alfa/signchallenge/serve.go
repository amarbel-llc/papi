package signchallenge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
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
	// Domain is the PAPI identity domain the §5.2 signature binds to for /sign and
	// /login — fixed here, never read from the request (relay defense).
	Domain string
	// Origin is the single browser origin CORS is pinned to (for /sign and /login).
	Origin string
	// Target is the PAPI base URL the /login broker calls server-side. When empty,
	// /login is not served.
	Target string
	// HTTPClient is used for the broker's PAPI calls; defaults to a 20s client.
	HTTPClient *http.Client
	// Logger receives per-request and error logs; defaults to slog.Default().
	Logger *slog.Logger

	// AllowCallbacks is the exact set of forward-auth verifier callback URLs the
	// /authorize flow may sign for. When non-empty, /authorize is served: a browser
	// navigation card-signs the §5.2 preimage bound to the callback's host and the
	// verifier's nonce, then 302s to the callback. The allowlist (and binding the
	// signature to the callback's host) stops a malicious page from coaxing a card
	// signature for someone else's verifier.
	AllowCallbacks []string
}

// Handler is the card oracle for the RFC-0001 §5.2 sign-challenge handshake
// (papi#36). Routes:
//
//   - POST /sign  — signing oracle: a §5.1 challenge JSON in → the §5.2
//     {challenge_id, signature} body out (the backend/plugin seam).
//   - POST /login — handshake broker (when Target is set): {auth_key_id} in → the
//     minted session out, running discovery→challenge→sign→response server-side.
//   - GET  /authorize — forward-auth login (when AllowCallbacks is set): a browser
//     navigation card-signs Preimage(<callback host>, nonce) and 302s to the
//     verifier callback with the signature. The verifier (FDR-0014) checks it
//     against the registered slot-9A keys. No PAPI-server call; the card is the
//     only thing that signs.
//
// /sign and /login pin CORS to Origin. /authorize is a top-level navigation (no
// CORS) that only signs for an allowlisted callback.
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
	if len(cfg.AllowCallbacks) > 0 {
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

// authorizeHandler is the GET /authorize forward-auth login: validate the verifier
// callback (allowlist), card-sign the §5.2 preimage bound to the callback's host and
// the verifier's nonce, and 302 to the callback with the signature. The card is the
// only signer; no PAPI-server call.
func authorizeHandler(cfg ServeConfig, logger *slog.Logger) http.HandlerFunc {
	allowed := make(map[string]bool, len(cfg.AllowCallbacks))
	for _, c := range cfg.AllowCallbacks {
		allowed[c] = true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		callback, nonce, state := q.Get("callback"), q.Get("nonce"), q.Get("state")
		if callback == "" || nonce == "" || state == "" {
			http.Error(w, "callback, nonce, and state are required", http.StatusBadRequest)
			return
		}
		if !allowed[callback] {
			logger.Warn("authorize: callback not in allowlist", "callback", callback)
			http.Error(w, "callback not allowed", http.StatusForbidden)
			return
		}
		domain, err := hostOf(callback)
		if err != nil {
			http.Error(w, "bad callback: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Card-sign the §5.2 preimage bound to the verifier's host + nonce. The
		// ChallengeID field is unused by the verifier (it has the nonce in its state).
		resp, err := Sign(r.Context(), cfg.Signer, cfg.GUID, domain, Challenge{ChallengeID: nonce, Nonce: nonce})
		if err != nil {
			logger.LogAttrs(r.Context(), slog.LevelError, "authorize card-sign failed", slog.String("err", err.Error()))
			http.Error(w, "sign: "+err.Error(), http.StatusBadGateway)
			return
		}
		u, _ := url.Parse(callback)
		cq := u.Query()
		cq.Set("sig", resp.Signature)
		cq.Set("state", state)
		u.RawQuery = cq.Encode()
		logger.Info("authorize: card-signed", "domain", domain)
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

// runHandshake runs the §5 broker login (discovery → challenge → sign → response)
// for authKeyID and returns the unwrapped session JSON. On failure it names the leg.
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

// hostOf returns the host[:port] of a URL — the §5.2 domain the /authorize signature
// binds to (the verifier's host).
func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("not an absolute URL: %q", raw)
	}
	return u.Host, nil
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
// reference server's response shape — or the body unchanged when there is none.
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
// headers the §5 calls use.
func setCORS(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Allow-Private-Network", "true")
	h.Add("Vary", "Origin")
}
