package forgetoken

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DefaultSessionCookie is the papi forward-auth verifier's session cookie name.
const DefaultSessionCookie = "__papi_session"

// SessionCookieCredential authenticates by presenting the forward-auth verifier's
// session cookie, which the reverse proxy turns into an asserted account — the
// credential kind the forge accepts for minting alongside password basic-auth.
//
// It deliberately sets NO Authorization header. The forge vhost keeps
// header-authenticated and proxy-authenticated requests disjoint by routing anything
// carrying an Authorization header away from the asserting location, so adding one
// here would silently defeat the whole mechanism.
type SessionCookieCredential struct {
	Name  string
	Value string
}

func (c SessionCookieCredential) apply(r *http.Request) {
	name := c.Name
	if name == "" {
		name = DefaultSessionCookie
	}
	r.AddCookie(&http.Cookie{Name: name, Value: c.Value})
}

// canMint: the reverse proxy turns this cookie into an asserted account, which is
// exactly the second credential kind the forge's mint routes accept.
func (c SessionCookieCredential) canMint() bool { return true }

// NonceSigner signs a verifier login nonce with the operator's card and returns the
// §5.2 signature as a papi-auth-sig-v1 markl id.
//
// The signing itself is a parameter rather than a dependency so this package stays
// free of the card and §5 machinery; the CLI supplies a closure over papi's slot-9A
// signer.
type NonceSigner func(ctx context.Context, domain, nonce string) (string, error)

// CardLogin obtains a verifier session cookie by driving the forward-auth login flow
// headlessly, with the card standing in for the browser.
//
// The flow exists for browsers: /auth/login redirects to a workstation oracle that
// holds the card, and the oracle redirects back to /auth/callback with a signature. A
// CLI already has the card, so it reads the nonce and state straight out of the first
// redirect, signs, and calls the callback itself — the oracle is never involved and
// the verifier needs no change to support this.
//
// authDomain MUST be the host the verifier binds signatures to (the host of its
// configured external URL), not necessarily the host being called: the preimage is
// byte-exact, and a mismatch fails as an indistinguishable 401.
func CardLogin(ctx context.Context, verifierBase, authDomain, cookieName string, sign NonceSigner) (SessionCookieCredential, error) {
	if sign == nil {
		return SessionCookieCredential{}, errors.New("card login needs a signer")
	}
	if authDomain == "" {
		return SessionCookieCredential{}, errors.New("card login needs the verifier's binding domain (§5.2 preimage)")
	}
	base, err := normalizeBase(verifierBase)
	if err != nil {
		return SessionCookieCredential{}, err
	}
	if cookieName == "" {
		cookieName = DefaultSessionCookie
	}
	// Both legs answer with a 302 that carries the payload; following it would
	// discard exactly what we came for (the oracle URL, then the Set-Cookie).
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	nonce, state, err := loginRedirect(ctx, client, base)
	if err != nil {
		return SessionCookieCredential{}, err
	}
	sig, err := sign(ctx, authDomain, nonce)
	if err != nil {
		return SessionCookieCredential{}, fmt.Errorf("sign the login nonce: %w", err)
	}
	value, err := loginCallback(ctx, client, base, state, sig, cookieName)
	if err != nil {
		return SessionCookieCredential{}, err
	}
	return SessionCookieCredential{Name: cookieName, Value: value}, nil
}

// loginRedirect performs the /auth/login leg and returns the nonce and state the
// verifier minted, read out of the redirect it aims at the oracle.
func loginRedirect(ctx context.Context, client *http.Client, base string) (nonce, state string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/auth/login?rd=/", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("GET /auth/login: %w", err)
	}
	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	if location == "" {
		return "", "", fmt.Errorf("GET /auth/login: HTTP %d with no redirect; "+
			"the verifier's login route may not be exposed here", resp.StatusCode)
	}
	u, err := url.Parse(location)
	if err != nil {
		return "", "", fmt.Errorf("GET /auth/login: unparseable redirect %q: %w", location, err)
	}
	q := u.Query()
	nonce, state = q.Get("nonce"), q.Get("state")
	if nonce == "" || state == "" {
		return "", "", fmt.Errorf("GET /auth/login: redirect carries no nonce/state (%q)", location)
	}
	return nonce, state, nil
}

// loginCallback performs the /auth/callback leg and returns the session cookie value.
func loginCallback(ctx context.Context, client *http.Client, base, state, sig, cookieName string) (string, error) {
	// The callback spells the signature parameter "sig" — the JSON verify-signature
	// oracle is the one that calls it "signature".
	callback := base + "/auth/callback?" + url.Values{"state": {state}, "sig": {sig}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /auth/callback: %w", err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			return c.Value, nil
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("GET /auth/callback: HTTP %d — the card's slot-9A key is not "+
			"registered with this verifier, or the signature's binding domain is wrong", resp.StatusCode)
	}
	return "", fmt.Errorf("GET /auth/callback: HTTP %d set no %s cookie", resp.StatusCode, cookieName)
}
