package authproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/alfa/logingrant"
)

const grantPrincipal = "nikulin-session"

type testCardSigner struct{ priv *ecdsa.PrivateKey }

func (s testCardSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, sg, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	sg.FillBytes(rs[32:])
	return rs, nil
}

// rawGrantSig signs arbitrary bytes (even a malformed grant) the way the card signs a
// grant, so the verifier's own parsing is what rejects it.
func rawGrantSig(t *testing.T, priv *ecdsa.PrivateKey, text []byte) string {
	t.Helper()
	rs, err := testCardSigner{priv}.SignSlot9A(context.Background(), "", logingrant.GrantPreimage(text))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := markl.Build(markl.PurposeLoginGrantSig, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

type grantCase struct {
	cfg      VerifierConfig
	now      time.Time
	cardPriv *ecdsa.PrivateKey
	keyPriv  ed25519.PrivateKey
	grant    logingrant.Grant
}

// newGrantCase builds a verifier with one registered card (principal "tester"), grants
// enabled for grantPrincipal only, and a grant for a seeded ed25519 key that is valid
// around the fixed test clock. mutate adjusts the grant before it is signed.
func newGrantCase(t *testing.T, mutate func(*logingrant.Grant)) grantCase {
	t.Helper()
	cardPriv, reg := testCard(t)
	cfg, now := testVerifier(reg)
	cfg.AllowGrantPrincipals = map[string]bool{grantPrincipal: true}

	keyPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub, err := ssh.NewPublicKey(keyPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	g := logingrant.Grant{
		Principal:  grantPrincipal,
		Key:        pub,
		Domain:     testDomain,
		NotBefore:  now.Add(-time.Hour).UTC(),
		Expires:    now.Add(24 * time.Hour).UTC(),
		MaxSession: 2 * time.Hour,
		Nonce:      "AAECAwQFBgcICQoLDA0ODw",
	}
	if mutate != nil {
		mutate(&g)
	}
	return grantCase{cfg: cfg, now: now, cardPriv: cardPriv, keyPriv: keyPriv, grant: g}
}

type grantParams struct {
	text      []byte
	cardSig   string
	loginSig  string
	omitGrant bool
}

func (c grantCase) goodParams(t *testing.T, nonce string) grantParams {
	t.Helper()
	text, err := logingrant.Build(c.grant)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return grantParams{
		text:     text,
		cardSig:  rawGrantSig(t, c.cardPriv, text),
		loginSig: logingrant.SignLogin(c.keyPriv, testDomain, nonce, c.grant.ID()),
	}
}

func (c grantCase) callback(t *testing.T, nonce string, p grantParams) *httptest.ResponseRecorder {
	t.Helper()
	state, err := MintState(c.cfg.CookieKey, StateClaims{Nonce: nonce, RD: "/", Exp: c.now.Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"state": {state}, "sig": {p.loginSig}}
	if !p.omitGrant {
		q.Set("grant", logingrant.EncodeText(p.text))
		q.Set("grant_sig", p.cardSig)
	}
	rec := httptest.NewRecorder()
	VerifierHandler(c.cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?"+q.Encode(), nil))
	return rec
}

func sessionOf(t *testing.T, c grantCase, rec *httptest.ResponseRecorder) SessionClaims {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d, want 302; body %s", rec.Code, rec.Body.String())
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == DefaultCookieName {
			claims, err := ParseSession(c.cfg.CookieKey, ck.Value, c.now)
			if err != nil {
				t.Fatalf("minted cookie does not parse: %v", err)
			}
			return claims
		}
	}
	t.Fatal("no session cookie set")
	return SessionClaims{}
}

func TestGrantLoginMintsRestrictedCookie(t *testing.T) {
	c := newGrantCase(t, nil)
	claims := sessionOf(t, c, c.callback(t, "N1", c.goodParams(t, "N1")))
	if claims.Principal != grantPrincipal {
		t.Errorf("principal = %q, want the grant's restricted principal", claims.Principal)
	}
	if claims.Grant != c.grant.ID() {
		t.Errorf("cookie grant = %q, want %q", claims.Grant, c.grant.ID())
	}
	if want := c.now.Add(2 * time.Hour).Unix(); claims.Exp != want {
		t.Errorf("exp = %d, want now+max-session = %d", claims.Exp, want)
	}
}

func TestGrantSessionIsCappedByGrantExpiry(t *testing.T) {
	c := newGrantCase(t, func(g *logingrant.Grant) { g.Expires = g.NotBefore.Add(time.Hour + 30*time.Minute) })
	claims := sessionOf(t, c, c.callback(t, "N1", c.goodParams(t, "N1")))
	if want := c.grant.Expires.Unix(); claims.Exp != want {
		t.Errorf("exp = %d, want grant expiry %d (30m away, under max-session 2h)", claims.Exp, want)
	}
}

func TestGrantSessionIsCappedBySessionTTL(t *testing.T) {
	c := newGrantCase(t, func(g *logingrant.Grant) { g.MaxSession = 6 * time.Hour })
	c.cfg.SessionTTL = time.Hour
	claims := sessionOf(t, c, c.callback(t, "N1", c.goodParams(t, "N1")))
	if want := c.now.Add(time.Hour).Unix(); claims.Exp != want {
		t.Errorf("exp = %d, want now+SessionTTL = %d", claims.Exp, want)
	}
}

// Every refusal must look identical to a bad signature: 401, no cookie, and a generic
// body that does not say which check failed.
func TestGrantLoginRefusals(t *testing.T) {
	type tweak func(t *testing.T, c *grantCase, p *grantParams)
	cases := map[string]tweak{
		"expired (now == expires)": func(t *testing.T, c *grantCase, p *grantParams) {
			c.grant.Expires = c.now
			*p = c.goodParams(t, "N1")
		},
		"not yet valid": func(t *testing.T, c *grantCase, p *grantParams) {
			c.grant.NotBefore = c.now.Add(time.Minute)
			*p = c.goodParams(t, "N1")
		},
		"card signature by an unregistered key": func(t *testing.T, c *grantCase, p *grantParams) {
			other, _ := testCard(t)
			p.cardSig = rawGrantSig(t, other, p.text)
		},
		"grant altered after signing": func(t *testing.T, c *grantCase, p *grantParams) {
			p.text = bytes.Replace(p.text, []byte("max-session: 7200"), []byte("max-session: 7201"), 1)
		},
		"grant for another verifier domain": func(t *testing.T, c *grantCase, p *grantParams) {
			c.grant.Domain = "other.example"
			*p = c.goodParams(t, "N1")
		},
		"principal not allowed": func(t *testing.T, c *grantCase, p *grantParams) {
			c.cfg.AllowGrantPrincipals = map[string]bool{"someone-else": true}
		},
		"grants not enabled": func(t *testing.T, c *grantCase, p *grantParams) {
			c.cfg.AllowGrantPrincipals = nil
		},
		"principal is a card principal": func(t *testing.T, c *grantCase, p *grantParams) {
			c.grant.Principal = "tester"
			c.cfg.AllowGrantPrincipals = map[string]bool{"tester": true}
			*p = c.goodParams(t, "N1")
		},
		"login signed by a different key": func(t *testing.T, c *grantCase, p *grantParams) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			p.loginSig = logingrant.SignLogin(other, testDomain, "N1", c.grant.ID())
		},
		"login signed over the card-login preimage": func(t *testing.T, c *grantCase, p *grantParams) {
			p.loginSig = logingrant.EncodeSig(ed25519.Sign(c.keyPriv, []byte("papi-auth-v1\n"+testDomain+"\nN1")))
		},
		"login bound to another grant id": func(t *testing.T, c *grantCase, p *grantParams) {
			p.loginSig = logingrant.SignLogin(c.keyPriv, testDomain, "N1", strings.Repeat("0", 32))
		},
		"login over a different nonce": func(t *testing.T, c *grantCase, p *grantParams) {
			p.loginSig = logingrant.SignLogin(c.keyPriv, testDomain, "N2", c.grant.ID())
		},
		"non-canonical grant, validly signed": func(t *testing.T, c *grantCase, p *grantParams) {
			p.text = append(p.text, []byte("extra: 1\n")...)
			p.cardSig = rawGrantSig(t, c.cardPriv, p.text)
		},
		"oversize grant, validly signed": func(t *testing.T, c *grantCase, p *grantParams) {
			p.text = bytes.Repeat([]byte("a"), 4096)
			p.cardSig = rawGrantSig(t, c.cardPriv, p.text)
		},
		"grant signature of the wrong purpose": func(t *testing.T, c *grantCase, p *grantParams) {
			p.cardSig = cardSign(t, c.cardPriv, testDomain, "N1")
		},
		"missing grant signature": func(t *testing.T, c *grantCase, p *grantParams) { p.cardSig = "" },
		"missing login signature": func(t *testing.T, c *grantCase, p *grantParams) { p.loginSig = "" },
	}
	for name, tw := range cases {
		t.Run(name, func(t *testing.T) {
			c := newGrantCase(t, nil)
			p := c.goodParams(t, "N1")
			tw(t, &c, &p)
			rec := c.callback(t, "N1", p)
			// Exactly 401, never a different code: a 403 or 400 would tell a prober which
			// check failed.
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("callback = %d, want exactly 401; body %s", rec.Code, rec.Body.String())
			}
			for _, ck := range rec.Result().Cookies() {
				if ck.Name == DefaultCookieName {
					t.Error("a cookie was set on a refused login")
				}
			}
			if body := rec.Body.String(); strings.Contains(body, "grant") || strings.Contains(body, "expired") {
				t.Errorf("refusal body leaks which check failed: %q", body)
			}
		})
	}
}

func TestGrantLoginRefusedWhenDenyListed(t *testing.T) {
	c := newGrantCase(t, nil)
	deny, err := ParseDenyList([]byte(c.grant.ID() + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.GrantDeny = deny
	if rec := c.callback(t, "N1", c.goodParams(t, "N1")); rec.Code != http.StatusUnauthorized {
		t.Errorf("deny-listed grant logged in: %d", rec.Code)
	}
}

// Deny-listing must kill sessions already issued, not only new logins.
func TestDenyListKillsLiveGrantCookies(t *testing.T) {
	c := newGrantCase(t, nil)
	claims := sessionOf(t, c, c.callback(t, "N1", c.goodParams(t, "N1")))
	cookie, err := MintSession(c.cfg.CookieKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(cfg VerifierConfig) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
		req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookie})
		rec := httptest.NewRecorder()
		VerifierHandler(cfg).ServeHTTP(rec, req)
		return rec.Code
	}
	if got := verify(c.cfg); got != http.StatusOK {
		t.Fatalf("live grant cookie = %d, want 200", got)
	}

	denyPath := filepath.Join(t.TempDir(), "deny")
	if err := os.WriteFile(denyPath, []byte("# none yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deny, err := LoadDenyList(denyPath)
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.GrantDeny = deny
	if got := verify(c.cfg); got != http.StatusOK {
		t.Fatalf("cookie with an empty deny list = %d, want 200", got)
	}
	if err := os.WriteFile(denyPath, []byte(c.grant.ID()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(denyPath, future, future); err != nil {
		t.Fatal(err)
	}
	if got := verify(c.cfg); got != http.StatusUnauthorized {
		t.Errorf("cookie of a deny-listed grant = %d, want 401", got)
	}
}

// A grant cookie must not outlive the operator turning grants off.
func TestGrantCookieRefusedWhenGrantsDisabled(t *testing.T) {
	c := newGrantCase(t, nil)
	claims := sessionOf(t, c, c.callback(t, "N1", c.goodParams(t, "N1")))
	cookie, _ := MintSession(c.cfg.CookieKey, claims)
	c.cfg.AllowGrantPrincipals = nil
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	VerifierHandler(c.cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("= %d, want 401", rec.Code)
	}
}

// The stateless verify-signature oracle (FDR-0013) must not learn about grants.
func TestVerifySignatureOracleIgnoresGrants(t *testing.T) {
	c := newGrantCase(t, nil)
	c.cfg.EnableVerifySignature = true
	p := c.goodParams(t, "N1")
	body := `{"signature":"` + p.loginSig + `","domain":"` + testDomain + `","nonce":"N1"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-signature", strings.NewReader(body))
	rec := httptest.NewRecorder()
	VerifierHandler(c.cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("verify-signature accepted a software login signature: %d", rec.Code)
	}
}

// The existing card login is unchanged when grants are configured.
func TestCardLoginStillWorksWithGrantsEnabled(t *testing.T) {
	c := newGrantCase(t, nil)
	state, _ := MintState(c.cfg.CookieKey, StateClaims{Nonce: "N1", RD: "/", Exp: c.now.Add(5 * time.Minute).Unix()})
	sig := cardSign(t, c.cardPriv, testDomain, "N1")
	rec := httptest.NewRecorder()
	VerifierHandler(c.cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/auth/callback?sig="+url.QueryEscape(sig)+"&state="+url.QueryEscape(state), nil))
	claims := sessionOf(t, c, rec)
	if claims.Principal != "tester" || claims.Grant != "" {
		t.Errorf("card login claims = %+v", claims)
	}
}

// idOfText is the grant id of arbitrary text, so a test can sign a login over a grant
// the strict parser will not build, and be sure the parser is the only thing refusing it.
func idOfText(text []byte) string {
	sum := sha256.Sum256(text)
	return hex.EncodeToString(sum[:16])
}

// The 168h bound at the verifier, not just in the package: exactly 168h logs in, one
// second more is refused even with a valid card signature and login signature.
func TestVerifierEnforcesTheWindowBound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  time.Duration
		wantOK bool
	}{
		{"exactly 168h", 0, true},
		{"168h + 1s", time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newGrantCase(t, func(g *logingrant.Grant) {
				g.Expires = g.NotBefore.Add(168 * time.Hour)
			})
			text, err := logingrant.Build(c.grant)
			if err != nil {
				t.Fatal(err)
			}
			if tc.extra != 0 {
				stretched := c.grant.Expires.Add(tc.extra).UTC().Format("2006-01-02T15:04:05Z")
				old := c.grant.Expires.UTC().Format("2006-01-02T15:04:05Z")
				text = bytes.Replace(text, []byte("expires: "+old), []byte("expires: "+stretched), 1)
			}
			p := grantParams{
				text:     text,
				cardSig:  rawGrantSig(t, c.cardPriv, text),
				loginSig: logingrant.SignLogin(c.keyPriv, testDomain, "N1", idOfText(text)),
			}
			rec := c.callback(t, "N1", p)
			if tc.wantOK && rec.Code != http.StatusFound {
				t.Errorf("= %d, want 302", rec.Code)
			}
			if !tc.wantOK && rec.Code != http.StatusUnauthorized {
				t.Errorf("= %d, want 401", rec.Code)
			}
		})
	}
}

// Forgejo resolves usernames case-insensitively, so a card principal differing from
// the grant principal only in case is the same account and must be refused.
func TestGrantPrincipalCollisionIgnoresCase(t *testing.T) {
	c := newGrantCase(t, nil)
	pub, err := ssh.NewPublicKey(&c.cardPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := ParseRegistry([]byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) +
		" piggy slot=9A guid=ABCD1234 cn=Nikulin-Session\n"))
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.Registry = reg
	if rec := c.callback(t, "N1", c.goodParams(t, "N1")); rec.Code != http.StatusUnauthorized {
		t.Errorf("a case-variant card principal was not refused: %d", rec.Code)
	}
}

// Any registered slot-9A key may sign a grant, but a card the operator has NOT allowed
// to log in (AllowPrincipals) must not be able to mint a way in through a grant.
func TestGrantSignerMustBeAnAllowedCard(t *testing.T) {
	c := newGrantCase(t, nil)
	c.cfg.AllowPrincipals = Set([]string{"someone-else"})
	if rec := c.callback(t, "N1", c.goodParams(t, "N1")); rec.Code != http.StatusUnauthorized {
		t.Errorf("grant signed by a card outside AllowPrincipals = %d, want 401", rec.Code)
	}
	c.cfg.AllowPrincipals = Set([]string{"tester"})
	if rec := c.callback(t, "N1", c.goodParams(t, "N1")); rec.Code != http.StatusFound {
		t.Errorf("grant signed by an allowed card = %d, want 302", rec.Code)
	}
}

// /auth/verify tells the proxy whether a session is a grant session, so it can map it
// to a restricted account instead of the operator's.
func TestVerifyEmitsRemoteGrantOnlyForGrantSessions(t *testing.T) {
	c := newGrantCase(t, nil)
	get := func(claims SessionClaims) *httptest.ResponseRecorder {
		cookie, err := MintSession(c.cfg.CookieKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
		req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookie})
		rec := httptest.NewRecorder()
		VerifierHandler(c.cfg).ServeHTTP(rec, req)
		return rec
	}

	grant := get(SessionClaims{Principal: grantPrincipal, Exp: c.now.Add(time.Hour).Unix(), Grant: c.grant.ID()})
	if grant.Code != http.StatusOK || grant.Header().Get("Remote-Grant") != c.grant.ID() {
		t.Errorf("grant session: %d, Remote-Grant %q, want 200 and the grant id", grant.Code, grant.Header().Get("Remote-Grant"))
	}
	if grant.Header().Get("Remote-User") != grantPrincipal {
		t.Errorf("Remote-User = %q", grant.Header().Get("Remote-User"))
	}

	card := get(SessionClaims{Principal: "tester", Exp: c.now.Add(time.Hour).Unix()})
	if card.Code != http.StatusOK {
		t.Fatalf("card session = %d", card.Code)
	}
	if _, present := card.Header()["Remote-Grant"]; present {
		t.Error("a card session carried a Remote-Grant header")
	}
}

func TestRegistryEntriesExposesCardPrincipals(t *testing.T) {
	_, reg := testCard(t)
	entries := reg.Entries()
	if len(entries) != 1 || entries[0].Principal != "tester" {
		t.Fatalf("Entries() = %+v", entries)
	}
}
