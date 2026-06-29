package authproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultCookieName is the verifier's session cookie name.
const DefaultCookieName = "__papi_session"

// VerifierConfig configures the forward-auth verifier (FDR-0014). It holds the
// verifier-only cookie HMAC key, the oracle's Ed25519 PUBLIC key (verify-only — the
// verifier cannot forge a login), the oracle's login URL, and the principal/groups
// allowlist.
type VerifierConfig struct {
	// CookieKey is the verifier-only HMAC key for the session cookie + login state.
	CookieKey []byte
	// OraclePub verifies oracle attestations (the verifier holds only the public key).
	OraclePub ed25519.PublicKey
	// OracleLogin is the oracle's /authorize URL the login flow redirects to.
	OracleLogin string
	// ExternalURL is the verifier's own externally-reachable base (scheme://host),
	// used to build the callback and as the attestation audience.
	ExternalURL string
	// AllowPrincipals / AllowGroups are the authz allowlist. When BOTH are empty, any
	// authenticated principal is allowed (a card login is already required).
	AllowPrincipals map[string]bool
	AllowGroups     map[string]bool
	// CookieName defaults to DefaultCookieName. CookieSecure/CookieDomain set the
	// cookie attributes (Secure requires HTTPS; set false only for plain-HTTP tailnet).
	CookieName   string
	CookieSecure bool
	CookieDomain string
	// StateTTL bounds the login round-trip (default 5m).
	StateTTL time.Duration
	Logger   *slog.Logger
	now      func() time.Time // overridable in tests
}

// VerifierHandler serves the forward-auth endpoints: /auth/verify (the nginx
// auth_request target), /auth/login (start a card login), /auth/callback (consume
// the oracle attestation → mint the cookie).
func VerifierHandler(cfg VerifierConfig) http.Handler {
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultCookieName
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
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/verify", cfg.handleVerify)
	mux.HandleFunc("/auth/login", cfg.handleLogin)
	mux.HandleFunc("/auth/callback", cfg.handleCallback)
	return mux
}

// handleVerify is the auth_request target: a valid, allowlisted session cookie → 200
// + identity headers (nginx maps Remote-User → X-WEBAUTH-USER for Forgejo); anything
// else → 401 (nginx then redirects to /auth/login). No PAPI call (validate-at-mint).
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
	q.Set("aud", cfg.ExternalURL)
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleCallback consumes the oracle's attestation (Ed25519) + the login state,
// checks nonce/audience/allowlist, mints the session cookie, and redirects back.
func (cfg VerifierConfig) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, err := ParseState(cfg.CookieKey, q.Get("state"), cfg.now())
	if err != nil {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	att, err := ParseAttest(cfg.OraclePub, q.Get("att"), cfg.now())
	if err != nil {
		cfg.Logger.Warn("authproxy: attestation rejected", "err", err)
		http.Error(w, "invalid attestation", http.StatusUnauthorized)
		return
	}
	if att.Nonce != st.Nonce {
		http.Error(w, "attestation nonce mismatch", http.StatusUnauthorized)
		return
	}
	if att.Aud != cfg.ExternalURL {
		http.Error(w, "attestation audience mismatch", http.StatusUnauthorized)
		return
	}
	if !cfg.allowed(att.Principal, att.Groups) {
		cfg.Logger.Warn("authproxy: principal not allowed", "principal", att.Principal, "groups", att.Groups)
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}
	cookie, err := MintSession(cfg.CookieKey, SessionClaims{
		Principal: att.Principal, Groups: att.Groups, Exp: att.SessionExp,
	})
	if err != nil {
		http.Error(w, "cookie mint failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    cookie,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		Expires:  time.Unix(att.SessionExp, 0),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	rd := st.RD
	if !safeRedirect(rd) {
		rd = "/"
	}
	cfg.Logger.Info("authproxy: login", "principal", att.Principal, "groups", att.Groups)
	http.Redirect(w, r, rd, http.StatusFound)
}

// allowed applies the authz allowlist. Empty allowlist (no principals AND no groups)
// → any authenticated principal passes (a card login was already required).
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

// safeRedirect guards against open redirects: only a site-relative path (starts with
// a single "/", not "//" which is protocol-relative to another host).
func safeRedirect(rd string) bool {
	return strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//")
}

func randNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
