package authproxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultCookieName is the verifier's session cookie name.
const DefaultCookieName = "__papi_session"

// maxVerifySigBody caps the /auth/verify-signature request body: a signature markl
// plus a domain plus a nonce are a few hundred bytes, so 16 KiB is generous slack.
const maxVerifySigBody = 16 << 10

// VerifierConfig configures the FDR-0014 forward-auth verifier. It is a §5.2
// sign-challenge verifier: it holds the verifier-only cookie HMAC key and the
// registry of accepted slot-9A keys (the papi-ssh-sync fragment). No signing key —
// only the YubiKey signs; the verifier checks the card signature.
type VerifierConfig struct {
	// CookieKey is the verifier-only HMAC key for the session cookie + login state.
	CookieKey []byte
	// Registry is the set of registered slot-9A keys (any of which may auth).
	Registry *Registry
	// EnableVerifySignature mounts POST /auth/verify-signature: the FDR-0013
	// app-native verify oracle — a card §5.2 signature plus the domain and nonce it
	// was signed over in, the verified principal out — for consumers that mint their
	// own session instead of taking the verifier's cookie. It is stateless and needs
	// only Registry (no CookieKey/OracleLogin/ExternalURL), so a verifier with just
	// this enabled runs as a standalone verify oracle with none of the forward-auth
	// (cookie/oracle) machinery.
	EnableVerifySignature bool
	// OracleLogin is the card-machine oracle's /authorize URL the login redirects to.
	OracleLogin string
	// ExternalURL is the verifier's externally-reachable base (scheme://host). Its
	// host is the §5.2 domain the card signature must bind to (relay defense).
	ExternalURL string
	// AllowPrincipals optionally narrows which registered identities may auth (by the
	// cn=/guid= principal). Empty AllowPrincipals AND empty AllowGroups → any registered
	// card (the operator's "any registered YubiKey").
	AllowPrincipals map[string]bool
	// AllowGroups is reserved: the slot-9A registry carries no group membership yet, so
	// no login is ever assigned groups and a non-empty AllowGroups currently matches
	// nothing. Setting it WITHOUT AllowPrincipals denies every login. Sourcing groups
	// (a registry annotation or a principal→groups map) is tracked as a follow-up.
	AllowGroups map[string]bool
	// CookieName defaults to DefaultCookieName. CookieSecure/CookieDomain set the
	// cookie attributes.
	CookieName   string
	CookieSecure bool
	CookieDomain string
	// SessionTTL is how long a minted cookie lasts before a re-card (default 12h).
	SessionTTL time.Duration
	// StateTTL bounds the login round-trip (default 5m).
	StateTTL time.Duration
	Logger   *slog.Logger

	domain string           // host of ExternalURL; the §5.2 binding domain
	now    func() time.Time // overridable in tests
}

// VerifierHandler serves /auth/verify (the nginx auth_request target), /auth/login
// (start a card login), and /auth/callback (verify the card §5.2 signature → mint
// the cookie).
func VerifierHandler(cfg VerifierConfig) http.Handler {
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultCookieName
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.StateTTL == 0 {
		cfg.StateTTL = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if u, err := url.Parse(cfg.ExternalURL); err == nil {
		cfg.domain = u.Host
	}
	mux := http.NewServeMux()
	// The forward-auth routes all turn on the cookie key — /auth/verify parses the
	// session cookie, /auth/login and /auth/callback mint one — so they mount only
	// when a cookie key is configured. A verify-signature-only verifier (FDR-0013)
	// has none and mounts just the verify oracle below.
	if len(cfg.CookieKey) > 0 {
		mux.HandleFunc("/auth/verify", cfg.handleVerify)
		mux.HandleFunc("/auth/login", cfg.handleLogin)
		mux.HandleFunc("/auth/callback", cfg.handleCallback)
	}
	if cfg.EnableVerifySignature {
		mux.HandleFunc("/auth/verify-signature", cfg.handleVerifySignature)
	}
	return mux
}

// handleVerify is the auth_request target: a valid, allowlisted session cookie → 200
// + identity headers (nginx maps Remote-User → X-WEBAUTH-USER for Forgejo); anything
// else → 401. No PAPI call (validate-at-mint).
func (cfg VerifierConfig) handleVerify(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(cfg.CookieName)
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	c, err := ParseSession(cfg.CookieKey, ck.Value, cfg.now())
	if err != nil || !cfg.allowed(c.Principal, c.Groups) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Remote-User", c.Principal)
	w.Header().Set("Remote-Groups", strings.Join(c.Groups, ","))
	w.WriteHeader(http.StatusOK)
}

// handleLogin mints a signed state (nonce + post-login redirect) and redirects the
// browser to the oracle's /authorize for the card sign.
func (cfg VerifierConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	if !safeRedirect(rd) {
		rd = "/"
	}
	nonce := randNonce()
	state, err := MintState(cfg.CookieKey, StateClaims{
		Nonce: nonce, RD: rd, Exp: cfg.now().Add(cfg.StateTTL).Unix(),
	})
	if err != nil {
		cfg.Logger.Error("authproxy: mint state", "err", err)
		http.Error(w, "login init failed", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(cfg.OracleLogin)
	if err != nil {
		http.Error(w, "misconfigured oracle url", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("callback", cfg.ExternalURL+"/auth/callback")
	q.Set("nonce", nonce)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleCallback verifies the card §5.2 signature against the registry over the login
// nonce, then mints the session cookie as the matched principal.
func (cfg VerifierConfig) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, err := ParseState(cfg.CookieKey, q.Get("state"), cfg.now())
	if err != nil {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	entry, err := cfg.Registry.VerifyLogin(cfg.domain, st.Nonce, q.Get("sig"))
	if err != nil {
		cfg.Logger.Warn("authproxy: login signature rejected", "err", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if !cfg.allowed(entry.Principal, nil) {
		cfg.Logger.Warn("authproxy: principal not allowed", "principal", entry.Principal)
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}
	exp := cfg.now().Add(cfg.SessionTTL).Unix()
	cookie, err := MintSession(cfg.CookieKey, SessionClaims{Principal: entry.Principal, Exp: exp})
	if err != nil {
		http.Error(w, "cookie mint failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    cookie,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		Expires:  time.Unix(exp, 0),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	rd := st.RD
	if !safeRedirect(rd) {
		rd = "/"
	}
	cfg.Logger.Info("authproxy: login", "principal", entry.Principal)
	http.Redirect(w, r, rd, http.StatusFound)
}

// verifySigRequest is the POST /auth/verify-signature body: a card §5.2 signature
// markl and the domain + nonce it was signed over. The caller owns the nonce
// lifecycle (mint, single-use, TTL, replay guard) — the verifier keeps no state.
// domain MUST be the exact host the signature is bound to (the oracle signs over
// hostOf(callback), host[:port], byte-exact), or the ECDSA check fails.
type verifySigRequest struct {
	Signature string `json:"signature"`
	Domain    string `json:"domain"`
	Nonce     string `json:"nonce"`
}

// verifySigResponse is the 200 body: the principal (cn=, falling back to guid=) of
// the registered slot-9A key that verified. A per-card key_id — the auth_key_id
// markl (RFC-0001 §5.1: piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…) — is a reserved
// future additive field; v1 is principal-only.
type verifySigResponse struct {
	Principal string `json:"principal"`
}

// handleVerifySignature is the FDR-0013 app-native verify oracle: POST a card §5.2
// signature plus the domain and nonce it was signed over, get back the principal of
// the registered slot-9A key that verifies it (200), or a JSON error (401). It is the
// server-to-server JSON sibling of handleCallback with the state-parse and cookie-mint
// stripped out — pure, stateless verification over the registry. "No registered key
// verifies" and "verified but the principal is not allowlisted" both return 401 (a
// generic body), so the endpoint never reveals that an unlisted card IS registered and
// a caller can treat any non-200 as "denied".
func (cfg VerifierConfig) handleVerifySignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req verifySigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxVerifySigBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "decode request: "+err.Error())
		return
	}
	if req.Signature == "" || req.Domain == "" || req.Nonce == "" {
		writeJSONError(w, http.StatusBadRequest, "signature, domain, and nonce are required")
		return
	}
	entry, err := cfg.Registry.VerifyLogin(req.Domain, req.Nonce, req.Signature)
	if err != nil {
		cfg.Logger.Warn("authproxy: verify-signature rejected", "err", err, "domain", req.Domain)
		writeJSONError(w, http.StatusUnauthorized, "signature not accepted")
		return
	}
	if !cfg.allowed(entry.Principal, nil) {
		cfg.Logger.Warn("authproxy: verify-signature principal not allowed", "principal", entry.Principal)
		writeJSONError(w, http.StatusUnauthorized, "signature not accepted")
		return
	}
	cfg.Logger.Info("authproxy: verify-signature", "principal", entry.Principal, "domain", req.Domain)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(verifySigResponse{Principal: entry.Principal})
}

// writeJSONError writes a {"error": msg} body with the given status — the JSON error
// shape the verify-signature contract pins (its callers parse JSON, not text).
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: msg})
}

// allowed applies the optional authz allowlist. Empty allowlist (no principals AND no
// groups) → any registered card passes.
func (cfg VerifierConfig) allowed(principal string, groups []string) bool {
	if len(cfg.AllowPrincipals) == 0 && len(cfg.AllowGroups) == 0 {
		return true
	}
	if cfg.AllowPrincipals[principal] {
		return true
	}
	for _, g := range groups {
		if cfg.AllowGroups[g] {
			return true
		}
	}
	return false
}

// safeRedirect guards against open redirects: only a site-relative path (single "/",
// not "//" which is protocol-relative to another host).
func safeRedirect(rd string) bool {
	return strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//")
}

func randNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
