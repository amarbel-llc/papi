package authproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/alfa/signchallenge"
)

const testDomain = "forge.linenisgreat.com"

// testCard generates an ecdsa key and a one-entry Registry holding its slot-9A line
// (cn=tester), as papi-ssh-sync would emit.
func testCard(t *testing.T) (*ecdsa.PrivateKey, *Registry) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshpub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshpub)), "\n") +
		" piggy slot=9A guid=ABCD1234 cn=tester\n"
	reg, err := ParseRegistry([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return priv, reg
}

// cardSign produces a §5.2 signature markl over Preimage(domain, nonce) with priv.
func cardSign(t *testing.T, priv *ecdsa.PrivateKey, domain, nonce string) string {
	t.Helper()
	digest := sha256.Sum256(signchallenge.Preimage(domain, nonce))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	sig, err := markl.Build(markl.PurposeAuthSig, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func testVerifier(reg *Registry) (VerifierConfig, time.Time) {
	now := time.Unix(1_700_000_000, 0)
	cfg := VerifierConfig{
		CookieKey:    testKey,
		Registry:     reg,
		OracleLogin:  "http://localhost:9098/authorize",
		ExternalURL:  "https://" + testDomain,
		CookieSecure: true,
		now:          func() time.Time { return now },
	}
	return cfg, now
}

func TestVerifyValidCookie(t *testing.T) {
	_, reg := testCard(t)
	cfg, now := testVerifier(reg)
	cookie, _ := MintSession(cfg.CookieKey, SessionClaims{Principal: "tester", Exp: now.Add(time.Hour).Unix()})
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Remote-User") != "tester" {
		t.Errorf("Remote-User = %q, want tester", rec.Header().Get("Remote-User"))
	}
}

func TestVerifyNoCookie(t *testing.T) {
	_, reg := testCard(t)
	cfg, _ := testVerifier(reg)
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/verify", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no cookie = %d, want 401", rec.Code)
	}
}

func TestCallbackVerifiesCardSig(t *testing.T) {
	priv, reg := testCard(t)
	cfg, now := testVerifier(reg)
	state, _ := MintState(cfg.CookieKey, StateClaims{Nonce: "N1", RD: "/admin", Exp: now.Add(5 * time.Minute).Unix()})
	sig := cardSign(t, priv, testDomain, "N1")
	target := "/auth/callback?sig=" + url.QueryEscape(sig) + "&state=" + url.QueryEscape(state)
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

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
	sc, err := ParseSession(cfg.CookieKey, set.Value, now)
	if err != nil || sc.Principal != "tester" {
		t.Errorf("minted cookie invalid: %v / %+v", err, sc)
	}
}

func TestCallbackRejects(t *testing.T) {
	priv, reg := testCard(t)
	cfg, now := testVerifier(reg)
	state, _ := MintState(cfg.CookieKey, StateClaims{Nonce: "N1", RD: "/admin", Exp: now.Add(5 * time.Minute).Unix()})
	run := func(sig string) int {
		rec := httptest.NewRecorder()
		VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/auth/callback?sig="+url.QueryEscape(sig)+"&state="+url.QueryEscape(state), nil))
		return rec.Code
	}

	// signed by a key NOT in the registry → 401
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if code := run(cardSign(t, stranger, testDomain, "N1")); code != http.StatusUnauthorized {
		t.Errorf("unregistered key = %d, want 401", code)
	}
	// right key but WRONG domain (relay defense) → 401
	if code := run(cardSign(t, priv, "evil.example", "N1")); code != http.StatusUnauthorized {
		t.Errorf("wrong-domain sig = %d, want 401", code)
	}
	// right key but WRONG nonce → 401
	if code := run(cardSign(t, priv, testDomain, "WRONG")); code != http.StatusUnauthorized {
		t.Errorf("wrong-nonce sig = %d, want 401", code)
	}
}

func TestLoginRedirectsToOracle(t *testing.T) {
	_, reg := testCard(t)
	cfg, _ := testVerifier(reg)
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?rd=/admin", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "localhost:9098" || loc.Path != "/authorize" {
		t.Errorf("redirect = %s, want the oracle /authorize", loc)
	}
	q := loc.Query()
	if q.Get("nonce") == "" || q.Get("callback") != "https://"+testDomain+"/auth/callback" {
		t.Errorf("redirect params: nonce=%q callback=%q", q.Get("nonce"), q.Get("callback"))
	}
	st, err := ParseState(cfg.CookieKey, q.Get("state"), time.Unix(1_700_000_000, 0))
	if err != nil || st.Nonce != q.Get("nonce") || st.RD != "/admin" {
		t.Errorf("state binding wrong: %v / %+v vs nonce %q", err, st, q.Get("nonce"))
	}
}

// verifySigHandler builds a standalone verify-signature-only verifier (registry +
// EnableVerifySignature, no cookie/oracle config) — the FDR-0013 app-native shape.
func verifySigHandler(reg *Registry) http.Handler {
	return VerifierHandler(VerifierConfig{Registry: reg, EnableVerifySignature: true})
}

// postVerifySig POSTs a JSON body to /auth/verify-signature and returns the status +
// decoded JSON (principal on 200, error otherwise).
func postVerifySig(h http.Handler, body string) (int, map[string]string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/verify-signature", strings.NewReader(body)))
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

// verifySigBody builds the {signature, domain, nonce} request JSON.
func verifySigBody(sig, domain, nonce string) string {
	return fmt.Sprintf(`{"signature":%q,"domain":%q,"nonce":%q}`, sig, domain, nonce)
}

func TestVerifySignatureValid(t *testing.T) {
	priv, reg := testCard(t)
	sig := cardSign(t, priv, testDomain, "app-nonce-1")
	code, body := postVerifySig(verifySigHandler(reg), verifySigBody(sig, testDomain, "app-nonce-1"))
	if code != http.StatusOK {
		t.Fatalf("verify-signature = %d, want 200; body %v", code, body)
	}
	if body["principal"] != "tester" {
		t.Errorf("principal = %q, want tester", body["principal"])
	}
}

// TestVerifySignatureRejects: an unregistered signer, a signature over the wrong
// domain (relay defense), and one over the wrong nonce each yield 401 with an error
// body — the same guards handleCallback enforces, minus the cookie.
func TestVerifySignatureRejects(t *testing.T) {
	priv, reg := testCard(t)
	h := verifySigHandler(reg)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unregistered key": cardSign(t, stranger, testDomain, "N"),
		"wrong domain":     cardSign(t, priv, "evil.example", "N"),
		"wrong nonce":      cardSign(t, priv, testDomain, "OTHER"),
	}
	for name, sig := range cases {
		code, body := postVerifySig(h, verifySigBody(sig, testDomain, "N"))
		if code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, code)
		}
		if body["error"] == "" {
			t.Errorf("%s: expected an error body, got %v", name, body)
		}
	}
}

func TestVerifySignatureBadRequest(t *testing.T) {
	_, reg := testCard(t)
	h := verifySigHandler(reg)
	if code, _ := postVerifySig(h, `{"signature":"x"}`); code != http.StatusBadRequest {
		t.Errorf("missing fields = %d, want 400", code)
	}
	if code, _ := postVerifySig(h, `{not json`); code != http.StatusBadRequest {
		t.Errorf("malformed json = %d, want 400", code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/verify-signature", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", rec.Code)
	}
}

// TestVerifySignatureNotMountedByDefault: a plain forward-auth verifier (flag off)
// does not expose the verify oracle.
func TestVerifySignatureNotMountedByDefault(t *testing.T) {
	_, reg := testCard(t)
	cfg, _ := testVerifier(reg) // EnableVerifySignature defaults false
	rec := httptest.NewRecorder()
	VerifierHandler(cfg).ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/auth/verify-signature", strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Errorf("verify-signature with flag off = %d, want 404", rec.Code)
	}
}

// TestVerifySignatureStandaloneOmitsForwardAuth: with no cookie key, the verify
// oracle works and the cookie-dependent forward-auth routes are not mounted.
func TestVerifySignatureStandaloneOmitsForwardAuth(t *testing.T) {
	priv, reg := testCard(t)
	h := verifySigHandler(reg) // Registry + flag only; no CookieKey
	sig := cardSign(t, priv, testDomain, "N")
	if code, _ := postVerifySig(h, verifySigBody(sig, testDomain, "N")); code != http.StatusOK {
		t.Errorf("standalone verify-signature = %d, want 200", code)
	}
	for _, path := range []string{"/auth/verify", "/auth/login", "/auth/callback"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("standalone %s = %d, want 404 (no cookie key → no forward-auth)", path, rec.Code)
		}
	}
}

// TestVerifySignatureAllowlist: an AllowPrincipals allowlist gates the verify oracle,
// and a disallowed-but-registered principal collapses to 401 (no 403, no principal
// leak) so the endpoint never reveals that an unlisted card is registered.
func TestVerifySignatureAllowlist(t *testing.T) {
	priv, reg := testCard(t) // principal "tester"
	sig := cardSign(t, priv, testDomain, "N")

	deny := VerifierHandler(VerifierConfig{
		Registry: reg, EnableVerifySignature: true, AllowPrincipals: Set([]string{"someone-else"}),
	})
	code, body := postVerifySig(deny, verifySigBody(sig, testDomain, "N"))
	if code != http.StatusUnauthorized {
		t.Errorf("disallowed principal = %d, want 401 (collapsed, not 403)", code)
	}
	if body["principal"] != "" {
		t.Errorf("disallowed principal leaked in body: %v", body)
	}

	allow := VerifierHandler(VerifierConfig{
		Registry: reg, EnableVerifySignature: true, AllowPrincipals: Set([]string{"tester"}),
	})
	if code, _ := postVerifySig(allow, verifySigBody(sig, testDomain, "N")); code != http.StatusOK {
		t.Errorf("allowlisted principal = %d, want 200", code)
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
