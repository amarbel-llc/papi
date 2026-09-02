package forgetoken

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeVerifier stands in for the papi forward-auth verifier's two login legs.
type fakeVerifier struct {
	// loginLocation is the /auth/login redirect target; empty means no Location
	// header at all, i.e. the route is not the verifier's.
	loginLocation string
	// callbackStatus, when non-zero, replaces the 302 on /auth/callback.
	callbackStatus int
	// omitCookie suppresses the Set-Cookie on an otherwise-successful callback.
	omitCookie bool

	gotSig   string
	gotState string
}

func (v *fakeVerifier) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if v.loginLocation != "" {
			w.Header().Set("Location", v.loginLocation)
		}
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		v.gotSig = r.URL.Query().Get("sig")
		v.gotState = r.URL.Query().Get("state")
		if v.callbackStatus != 0 {
			w.WriteHeader(v.callbackStatus)
			return
		}
		if !v.omitCookie {
			http.SetCookie(w, &http.Cookie{Name: DefaultSessionCookie, Value: "session-value"})
		}
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// oracleRedirect is the Location the real verifier aims at the workstation oracle.
// The `callback` param is included because the verifier sends it, not because
// CardLogin reads it — CardLogin takes only the nonce and state and calls the
// callback itself.
func oracleRedirect(nonce, state string) string {
	return "https://oracle.example:9098/authorize?" + url.Values{
		"callback": {"https://forge.example/auth/callback"},
		"nonce":    {nonce},
		"state":    {state},
	}.Encode()
}

func TestCardLoginDrivesBothLegs(t *testing.T) {
	v := &fakeVerifier{loginLocation: oracleRedirect("nonce-1", "state-1")}
	srv := v.server(t)

	var signedDomain, signedNonce string
	cred, err := CardLogin(context.Background(), srv.URL, "forge.example", "",
		func(_ context.Context, domain, nonce string) (string, error) {
			signedDomain, signedNonce = domain, nonce
			return "papi-auth-sig-v1@ecdsa_p256_sig-abc", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if signedNonce != "nonce-1" {
		t.Fatalf("signed nonce %q, want the one /auth/login minted", signedNonce)
	}
	if signedDomain != "forge.example" {
		t.Fatalf("signed domain %q: the preimage must bind the verifier's domain", signedDomain)
	}
	if v.gotState != "state-1" {
		t.Fatalf("callback state %q, want the login's state echoed back", v.gotState)
	}
	if v.gotSig != "papi-auth-sig-v1@ecdsa_p256_sig-abc" {
		t.Fatalf("callback sig %q", v.gotSig)
	}
	if cred.Value != "session-value" {
		t.Fatalf("credential value %q, want the Set-Cookie value", cred.Value)
	}
}

// The forge vhost routes anything carrying an Authorization header away from the
// header-asserting location, so the cookie credential must add none.
func TestSessionCookieCredentialSetsNoAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/sasha/tokens", nil)
	SessionCookieCredential{Value: "v"}.apply(req)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("cookie credential set Authorization %q; that would bypass the asserting location", got)
	}
	c, err := req.Cookie(DefaultSessionCookie)
	if err != nil || c.Value != "v" {
		t.Fatalf("cookie: %v / %v", c, err)
	}
}

func TestCardLoginFailures(t *testing.T) {
	sign := func(context.Context, string, string) (string, error) { return "sig", nil }

	t.Run("login route not exposed", func(t *testing.T) {
		srv := (&fakeVerifier{}).server(t) // 302 with no Location
		_, err := CardLogin(context.Background(), srv.URL, "forge.example", "", sign)
		if err == nil || !strings.Contains(err.Error(), "/auth/login") {
			t.Fatalf("want a /auth/login error, got %v", err)
		}
	})

	t.Run("signature rejected", func(t *testing.T) {
		v := &fakeVerifier{
			loginLocation:  oracleRedirect("n", "s"),
			callbackStatus: http.StatusUnauthorized,
		}
		srv := v.server(t)
		_, err := CardLogin(context.Background(), srv.URL, "forge.example", "", sign)
		if err == nil || !strings.Contains(err.Error(), "binding domain") {
			t.Fatalf("a 401 should name the two likely causes, got %v", err)
		}
	})

	t.Run("no cookie issued", func(t *testing.T) {
		v := &fakeVerifier{loginLocation: oracleRedirect("n", "s"), omitCookie: true}
		srv := v.server(t)
		_, err := CardLogin(context.Background(), srv.URL, "forge.example", "", sign)
		if err == nil || !strings.Contains(err.Error(), "cookie") {
			t.Fatalf("want a missing-cookie error, got %v", err)
		}
	})

	t.Run("no binding domain", func(t *testing.T) {
		srv := (&fakeVerifier{loginLocation: oracleRedirect("n", "s")}).server(t)
		if _, err := CardLogin(context.Background(), srv.URL, "", "", sign); err == nil {
			t.Fatal("an empty binding domain must fail rather than sign the wrong preimage")
		}
	})
}
