package signchallenge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	// Domain is the PAPI identity domain the §5.2 signature binds to — fixed here,
	// never read from the request (the challenge never echoes it; relay defense).
	Domain string
	// Origin is the single browser origin CORS is pinned to.
	Origin string
	// Target is the PAPI base URL (e.g. https://api.linenisgreat.com) the /login
	// broker calls server-side. When empty, only /sign is served (no broker).
	Target string
	// HTTPClient is used for the broker's PAPI calls; defaults to a 20s client.
	HTTPClient *http.Client
	// Logger receives per-request and error logs; defaults to slog.Default().
	Logger *slog.Logger
}

// Handler is the card oracle for the RFC-0001 §5.2 sign-challenge handshake
// (papi#36). It performs the one card-bound step a browser cannot do itself (no
// PCSC in a page), exposed over HTTP. Two routes:
//
//   - POST /sign  — the signing oracle: the caller posts a §5.1 challenge JSON and
//     gets back the §5.2 {challenge_id, signature} response body. The caller still
//     runs the network handshake. This is the seam a backend (e.g. a Better Auth
//     plugin) uses: it already holds the challenge and only needs it signed.
//
//   - POST /login — the handshake broker (only when cfg.Target is set): the caller
//     posts {auth_key_id} and the oracle does discovery → challenge → sign →
//     response against cfg.Target **server-side** (where CORS does not apply),
//     returning the minted session. This is for a browser with no backend of its
//     own (the demo topology, incl. a remote tailnet browser): the browser talks
//     only to this oracle, never cross-origin to the PAPI server.
//
// Security envelope: card + PIN gate every signature. CORS pins browsers to one
// origin. When bound beyond loopback (a tailnet interface), /login becomes a
// card-gated "log me in" endpoint any peer on that network can reach — adequate
// for cardholders-only personal use, but state it; production hardening is out of
// scope for this spike.
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
// at a level keyed to the status class (Info <400, Warn 4xx, Error 5xx). The broker
// additionally logs which upstream leg failed.
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

// loginHandler is the POST /login broker: {auth_key_id} in → the minted session
// out, running the whole §5 handshake against cfg.Target server-side.
func loginHandler(cfg ServeConfig, logger *slog.Logger) http.HandlerFunc {
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 20 * time.Second}
	}
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
		// fail logs which upstream leg broke and returns the same "{leg}: {err}" body.
		fail := func(leg string, err error, code int) {
			logger.LogAttrs(r.Context(), slog.LevelError, "login leg failed",
				slog.String("leg", leg), slog.Int("status", code), slog.String("err", err.Error()))
			http.Error(w, leg+": "+err.Error(), code)
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
		ctx := r.Context()
		auth, err := fetchDiscoveryAuth(ctx, httpc, base)
		if err != nil {
			fail("discovery", err, http.StatusBadGateway)
			return
		}
		chRaw, err := postJSON(ctx, httpc, auth.Challenge, map[string]string{"auth_key_id": req.AuthKeyID})
		if err != nil {
			fail("challenge", err, http.StatusBadGateway)
			return
		}
		ch, err := ParseChallenge(unwrapData(chRaw))
		if err != nil {
			fail("challenge", err, http.StatusBadGateway)
			return
		}
		resp, err := Sign(ctx, cfg.Signer, cfg.GUID, cfg.Domain, ch)
		if err != nil {
			fail("sign", err, http.StatusBadGateway)
			return
		}
		sessRaw, err := postJSON(ctx, httpc, auth.Response, resp)
		if err != nil {
			fail("response", err, http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(unwrapData(sessRaw))
	}
}

// unwrapData returns the inner object of a {"data": …, "meta": …} envelope — the
// reference server's response shape for /papi/auth/challenge and /papi/auth/response
// (and discovery) — or the body unchanged when there is no such envelope (a bare
// object). Lets the broker parse the challenge and pass the session through
// regardless of which framing the server uses.
func unwrapData(raw []byte) []byte {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data) > 0 {
		return env.Data
	}
	return raw
}

// discoveryAuth is the §4.1 discovery doc's auth block — the challenge/response
// URLs the broker posts to.
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

// setCORS pins the response to the configured origin and advertises the methods and
// headers the §5 calls use. Access-Control-Allow-Private-Network answers Chrome's
// PNA preflight for an HTTPS/remote page reaching this oracle. Vary: Origin keeps
// caches from serving the pinned header to a different origin.
func setCORS(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Allow-Private-Network", "true")
	h.Add("Vary", "Origin")
}
