package authproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func testVerifier(t *testing.T) (VerifierConfig, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	cfg := VerifierConfig{
		CookieKey:    testKey,
		OraclePub:    pub,
		OracleLogin:  "https://oracle.example/authorize",
		ExternalURL:  "https://krone.example",
		AllowGroups:  map[string]bool{"owner": true},
		CookieSecure: true,
		now:          func() time.Time { return now },
	}
	return cfg, priv, now
}

func TestVerifyValidCookie(t *testing.T) {
	cfg, _, now := testVerifier(t)
	cookie, _ := MintSession(cfg.CookieKey, SessionClaims{
		Principal: "self", Groups: []string{"owner"}, Exp: now.Add(15 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Remote-User") != "self" {
		t.Errorf("Remote-User = %q, want self", rec.Header().Get("Remote-User"))
	}
	if rec.Header().Get("Remote-Groups") != "owner" {
		t.Errorf("Remote-Groups = %q, want owner", rec.Header().Get("Remote-Groups"))
	}
}

func TestVerifyRejects(t *testing.T) {
	cfg, _, now := testVerifier(t)
	// no cookie
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/verify", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no cookie = %d, want 401", rec.Code)
	}
	// expired cookie
	exp, _ := MintSession(cfg.CookieKey, SessionClaims{Principal: "self", Groups: []string{"owner"}, Exp: now.Add(-time.Minute).Unix()})
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: exp})
	rec = httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expired cookie = %d, want 401", rec.Code)
	}
	// authenticated but not in the allowlist (group "guest" not allowed)
	notallowed, _ := MintSession(cfg.CookieKey, SessionClaims{Principal: "stranger", Groups: []string{"guest"}, Exp: now.Add(time.Hour).Unix()})
	req = httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: notallowed})
	rec = httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("not-allowlisted = %d, want 401", rec.Code)
	}
}

func callbackURL(att, state string) string {
	return "/auth/callback?att=" + url.QueryEscape(att) + "&state=" + url.QueryEscape(state)
}

func TestCallbackMintsCookie(t *testing.T) {
	cfg, priv, now := testVerifier(t)
	state, _ := MintState(cfg.CookieKey, StateClaims{Nonce: "n1", RD: "/admin", Exp: now.Add(5 * time.Minute).Unix()})
	att, _ := MintAttest(priv, AttestClaims{
		Principal: "self", Groups: []string{"owner"}, Nonce: "n1", Aud: cfg.ExternalURL,
		SessionExp: now.Add(15 * time.Minute).Unix(), Exp: now.Add(2 * time.Minute).Unix(),
	})
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, callbackURL(att, state), nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d, want 302; body %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin" {
		t.Errorf("redirect = %q, want /admin", loc)
	}
	var set *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == DefaultCookieName {
			set = c
		}
	}
	if set == nil {
		t.Fatal("no session cookie set")
	}
	if !set.HttpOnly || !set.Secure {
		t.Errorf("cookie flags: HttpOnly=%v Secure=%v, want both true", set.HttpOnly, set.Secure)
	}
	sc, err := ParseSession(cfg.CookieKey, set.Value, now)
	if err != nil || sc.Principal != "self" {
		t.Errorf("minted cookie invalid: %v / %+v", err, sc)
	}
}

func TestCallbackRejects(t *testing.T) {
	cfg, priv, now := testVerifier(t)
	good := func() (string, AttestClaims) {
		state, _ := MintState(cfg.CookieKey, StateClaims{Nonce: "n1", RD: "/admin", Exp: now.Add(5 * time.Minute).Unix()})
		return state, AttestClaims{Principal: "self", Groups: []string{"owner"}, Nonce: "n1", Aud: cfg.ExternalURL,
			SessionExp: now.Add(15 * time.Minute).Unix(), Exp: now.Add(2 * time.Minute).Unix()}
	}
	run := func(att, state string) int {
		rec := httptest.NewRecorder()
		VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, callbackURL(att, state), nil))
		return rec.Code
	}

	// nonce mismatch → 401
	state, ac := good()
	ac.Nonce = "WRONG"
	att, _ := MintAttest(priv, ac)
	if code := run(att, state); code != http.StatusUnauthorized {
		t.Errorf("nonce mismatch = %d, want 401", code)
	}
	// wrong audience → 401
	state, ac = good()
	ac.Aud = "https://evil.example"
	att, _ = MintAttest(priv, ac)
	if code := run(att, state); code != http.StatusUnauthorized {
		t.Errorf("wrong aud = %d, want 401", code)
	}
	// attestation signed by a DIFFERENT key (forged) → 401
	state, ac = good()
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	att, _ = MintAttest(otherPriv, ac)
	if code := run(att, state); code != http.StatusUnauthorized {
		t.Errorf("forged attestation = %d, want 401", code)
	}
	// principal/groups not allowed → 403
	state, ac = good()
	ac.Groups = []string{"guest"}
	ac.Principal = "stranger"
	att, _ = MintAttest(priv, ac)
	if code := run(att, state); code != http.StatusForbidden {
		t.Errorf("not allowed = %d, want 403", code)
	}
}

func TestLoginRedirectsToOracle(t *testing.T) {
	cfg, _, _ := testVerifier(t)
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?rd=/admin", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "oracle.example" || loc.Path != "/authorize" {
		t.Errorf("redirect host/path = %s%s, want oracle.example/authorize", loc.Host, loc.Path)
	}
	q := loc.Query()
	if q.Get("state") == "" || q.Get("nonce") == "" {
		t.Error("redirect missing state/nonce")
	}
	if q.Get("callback") != "https://krone.example/auth/callback" || q.Get("aud") != "https://krone.example" {
		t.Errorf("callback/aud = %q / %q", q.Get("callback"), q.Get("aud"))
	}
	// the state must carry the nonce passed to the oracle (binding)
	st, err := ParseState(cfg.CookieKey, q.Get("state"), time.Unix(1_700_000_000, 0))
	if err != nil || st.Nonce != q.Get("nonce") || st.RD != "/admin" {
		t.Errorf("state binding wrong: %v / %+v vs nonce %q", err, st, q.Get("nonce"))
	}
}

func TestSafeRedirect(t *testing.T) {
	for in, want := range map[string]bool{
		"/admin": true, "/": true, "/a/b?x=1": true,
		"//evil.example": false, "http://evil.example": false, "": false, "evil": false,
	} {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %v, want %v", in, got, want)
		}
	}
}
