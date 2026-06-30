package authproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/amarbel-llc/papi/internal/0/markl"
	"github.com/amarbel-llc/papi/internal/alfa/signchallenge"
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
