package signchallenge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/amarbel-llc/papi/internal/0/markl"
)

// TestPreimageBytes pins the §5.2 framing byte-for-byte: prefix, two single-LF
// separators, no trailing newline. The site-linenisgreat verifier reconstructs the
// identical bytes (PapiAuthService::preimage), so any drift here silently breaks the
// live round-trip — this is the guard against that.
func TestPreimageBytes(t *testing.T) {
	got := Preimage("staging.linenisgreat.com", "deadbeef")
	want := "papi-auth-v1\nstaging.linenisgreat.com\ndeadbeef"
	if string(got) != want {
		t.Fatalf("Preimage = %q, want %q", got, want)
	}
	if got[len(got)-1] == '\n' {
		t.Errorf("Preimage has a trailing newline; the server builds none (§5.2)")
	}
	if n := bytes.Count(got, []byte("\n")); n != 2 {
		t.Errorf("Preimage has %d LF separators, want exactly 2", n)
	}
	if bytes.Contains(got, []byte("\r")) {
		t.Errorf("Preimage contains CR; separators must be bare LF (§5.2)")
	}
}

func TestParseChallenge(t *testing.T) {
	ch, err := ParseChallenge([]byte(`{"challenge_id":"abc","nonce":"00ff","expires_at":1750000000}`))
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if ch.ChallengeID != "abc" || ch.Nonce != "00ff" || ch.ExpiresAt != 1750000000 {
		t.Errorf("ParseChallenge = %+v", ch)
	}
	for name, bad := range map[string]string{
		"no challenge_id": `{"nonce":"00ff"}`,
		"no nonce":        `{"challenge_id":"abc"}`,
		"not json":        `not json`,
	} {
		if _, err := ParseChallenge([]byte(bad)); err == nil {
			t.Errorf("ParseChallenge(%s) = nil err, want error", name)
		}
	}
}

// fakeSigner signs as a slot-9A card would: SHA-256 over the bare preimage, ECDSA
// P-256, returned as raw r‖s — exactly what `piggy sign-bytes --slot 9a --format
// raw` produces.
type fakeSigner struct{ priv *ecdsa.PrivateKey }

func (f fakeSigner) SignSlot9A(_ context.Context, _ string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, f.priv, digest[:])
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	return rs, nil
}

// TestSignProducesVerifiableResponse is the end-to-end conformance check: the
// emitted signature MUST verify over SHA-256(preimage) with the signing key —
// exactly what the server's openssl_verify does against the registered slot-9A
// pubkey. It pins the preimage framing, the markl purpose/format, and the r‖s
// encoding in one shot.
func TestSignProducesVerifiableResponse(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ch := Challenge{ChallengeID: "chal-1", Nonce: "0011223344556677"}
	domain := "staging.linenisgreat.com"

	resp, err := Sign(context.Background(), fakeSigner{priv}, "GUID", domain, ch)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if resp.ChallengeID != ch.ChallengeID {
		t.Errorf("challenge_id = %q, want %q (echoed verbatim)", resp.ChallengeID, ch.ChallengeID)
	}

	id, err := markl.Parse(resp.Signature)
	if err != nil {
		t.Fatalf("Parse signature markl %q: %v", resp.Signature, err)
	}
	if id.Purpose != markl.PurposeAuthSig || id.Format != markl.FormatEcdsaP256Sig {
		t.Errorf("signature purpose/format = %q/%q, want %q/%q",
			id.Purpose, id.Format, markl.PurposeAuthSig, markl.FormatEcdsaP256Sig)
	}
	if len(id.Payload) != 64 {
		t.Fatalf("signature payload = %d bytes, want 64 raw r‖s", len(id.Payload))
	}

	r := new(big.Int).SetBytes(id.Payload[:32])
	s := new(big.Int).SetBytes(id.Payload[32:])
	digest := sha256.Sum256(Preimage(domain, ch.Nonce))
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("signature does not verify over SHA-256(preimage) with the signing key")
	}

	// The response must marshal to the exact {challenge_id, signature} wire body.
	wire, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(got) != 2 || got["challenge_id"] != ch.ChallengeID || got["signature"] != resp.Signature {
		t.Errorf("wire body = %s, want exactly {challenge_id, signature}", wire)
	}
}

func TestSignRequiresDomain(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(context.Background(), fakeSigner{priv}, "GUID", "", Challenge{Nonce: "x"}); err == nil {
		t.Error("Sign with empty domain = nil err, want error (§5.2 binding)")
	}
}

func TestSignPropagatesSignerError(t *testing.T) {
	if _, err := Sign(context.Background(), errSigner{}, "GUID", "d", Challenge{Nonce: "n"}); err == nil {
		t.Error("Sign = nil err when the signer fails, want propagation")
	}
}

type errSigner struct{}

func (errSigner) SignSlot9A(context.Context, string, []byte) ([]byte, error) {
	return nil, errCard
}

var errCard = &signErr{}

type signErr struct{}

func (*signErr) Error() string { return "errSigner: no card" }

// TestHandlerSignsPostedChallenge is the cardless proof of the signing oracle
// (papi#36): POST a §5.1 challenge to /sign and the returned body MUST be the same
// verifiable {challenge_id, signature} Sign produces, with the CORS origin pinned.
// It uses the injected fakeSigner, so it needs no card — it proves the HTTP
// transport + framing, not the card leg.
func TestHandlerSignsPostedChallenge(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const domain = "staging.linenisgreat.com"
	const origin = "http://localhost:3000"
	const nonce = "0011223344556677"
	h := Handler(ServeConfig{Signer: fakeSigner{priv}, GUID: "GUID", Domain: domain, Origin: origin})

	chJSON := []byte(`{"challenge_id":"chal-1","nonce":"` + nonce + `","expires_at":1750000000}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(chJSON)))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sign = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, origin)
	}

	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /sign response: %v", err)
	}
	if resp.ChallengeID != "chal-1" {
		t.Errorf("challenge_id = %q, want chal-1 (echoed verbatim)", resp.ChallengeID)
	}
	id, err := markl.Parse(resp.Signature)
	if err != nil {
		t.Fatalf("parse signature markl %q: %v", resp.Signature, err)
	}
	if id.Purpose != markl.PurposeAuthSig || id.Format != markl.FormatEcdsaP256Sig || len(id.Payload) != 64 {
		t.Fatalf("signature markl = %q/%q len %d, want %q/%q len 64",
			id.Purpose, id.Format, len(id.Payload), markl.PurposeAuthSig, markl.FormatEcdsaP256Sig)
	}
	r := new(big.Int).SetBytes(id.Payload[:32])
	s := new(big.Int).SetBytes(id.Payload[32:])
	digest := sha256.Sum256(Preimage(domain, nonce))
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("handler signature does not verify over SHA-256(preimage) with the signing key")
	}
}

// TestHandlerOPTIONSPreflight checks the CORS preflight the browser sends before the
// cross-origin (and Private-Network) POST: 204 with the pinned origin and the
// Access-Control-Allow-Private-Network header that lets an HTTPS SPA reach this
// http://127.0.0.1 oracle.
func TestHandlerOPTIONSPreflight(t *testing.T) {
	const origin = "http://localhost:3000"
	h := Handler(ServeConfig{Signer: errSigner{}, GUID: "G", Domain: "d", Origin: origin})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/sign", nil))

	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS /sign = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("preflight Access-Control-Allow-Origin = %q, want %q", got, origin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Private-Network"); got != "true" {
		t.Errorf("preflight Access-Control-Allow-Private-Network = %q, want true", got)
	}
}

// TestHandlerRejectsBadChallenge: a malformed challenge body is the browser's fault
// (400), distinct from a card/signer failure (502).
func TestHandlerRejectsBadChallenge(t *testing.T) {
	h := Handler(ServeConfig{Signer: errSigner{}, GUID: "G", Domain: "d", Origin: "http://localhost:3000"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader([]byte("not json"))))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /sign with bad body = %d, want 400", rec.Code)
	}
}

// TestHandlerSignerFailureIsBadGateway: when the card/signer leg fails on a
// well-formed challenge, the oracle reports 502 (a gateway failure), not 400.
func TestHandlerSignerFailureIsBadGateway(t *testing.T) {
	h := Handler(ServeConfig{Signer: errSigner{}, GUID: "G", Domain: "staging.linenisgreat.com", Origin: "http://localhost:3000"})
	chJSON := []byte(`{"challenge_id":"c","nonce":"00ff","expires_at":1}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(chJSON)))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("POST /sign with a failing signer = %d, want 502", rec.Code)
	}
}

// TestLoginBrokerRunsHandshake proves the /login broker: a browser posts only
// {auth_key_id} to the oracle, and the oracle runs discovery → challenge → sign →
// response against the PAPI server server-side, returning the minted session. The
// fake PAPI server verifies the signature the broker produced over SHA-256(preimage)
// before issuing the session, so a green test means the whole relayed handshake is
// byte-correct. Cardless (injected fakeSigner).
func TestLoginBrokerRunsHandshake(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const domain = "staging.linenisgreat.com"
	const nonce = "0011223344556677"
	var verified bool

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/papi", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"auth": map[string]any{
			"scheme":    "piggy-sign-challenge",
			"challenge": base + "/papi/auth/challenge",
			"response":  base + "/papi/auth/response",
		}}})
	})
	mux.HandleFunc("/papi/auth/challenge", func(w http.ResponseWriter, _ *http.Request) {
		// Enveloped {data, meta}, matching the reference server.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"challenge_id": "c1", "nonce": nonce, "expires_at": 0},
			"meta": map[string]any{"type": "papi-auth-challenge"},
		})
	})
	mux.HandleFunc("/papi/auth/response", func(w http.ResponseWriter, r *http.Request) {
		var body Response
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		id, err := markl.Parse(body.Signature)
		if err != nil {
			http.Error(w, "bad signature markl", http.StatusBadRequest)
			return
		}
		r2 := new(big.Int).SetBytes(id.Payload[:32])
		s2 := new(big.Int).SetBytes(id.Payload[32:])
		digest := sha256.Sum256(Preimage(domain, nonce))
		if !ecdsa.Verify(&priv.PublicKey, digest[:], r2, s2) {
			http.Error(w, "signature verify failed", http.StatusUnauthorized)
			return
		}
		verified = true
		// Enveloped {data, meta}, matching the reference server — the broker must
		// unwrap it before handing the session to the browser.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"session": "sess-1", "principal": "p", "groups": []string{}, "expires_at": 0},
			"meta": map[string]any{"type": "papi-auth-session"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := Handler(ServeConfig{
		Signer: fakeSigner{priv}, GUID: "GUID", Domain: domain,
		Origin: "http://demo.example:8080", Target: srv.URL,
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login",
		bytes.NewReader([]byte(`{"auth_key_id":"piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-x"}`))))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !verified {
		t.Error("the PAPI server never received a verifiable signature from the broker")
	}
	var sess map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sess["session"] != "sess-1" {
		t.Errorf("session = %v, want the broker to pass through sess-1", sess["session"])
	}
}

// TestAuthorizeCardSigns drives the /authorize forward-auth login: it card-signs the
// §5.2 preimage bound to the callback's host + the verifier's nonce and 302s to the
// callback with the signature, which Verify accepts under the card's public key. No
// PAPI server, no software key. Cardless test (injected fakeSigner).
func TestAuthorizeCardSigns(t *testing.T) {
	cardPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const callback = "https://forge.linenisgreat.com/auth/callback"
	h := Handler(ServeConfig{Signer: fakeSigner{cardPriv}, GUID: "G", AllowCallbacks: []string{callback}})
	target := "/authorize?callback=" + url.QueryEscape(callback) + "&nonce=NONCE123&state=ST"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("/authorize = %d, want 302; body %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != callback {
		t.Errorf("redirect = %s, want %s", loc, callback)
	}
	if loc.Query().Get("state") != "ST" {
		t.Errorf("state = %q, want ST (passed through)", loc.Query().Get("state"))
	}
	sig := loc.Query().Get("sig")
	// the signature must verify over Preimage(callback host, nonce) with the card key
	if err := Verify(&cardPriv.PublicKey, "forge.linenisgreat.com", "NONCE123", sig); err != nil {
		t.Errorf("Verify of /authorize signature: %v", err)
	}
	// a different domain must NOT verify (relay defense across verifiers)
	if err := Verify(&cardPriv.PublicKey, "evil.example", "NONCE123", sig); err == nil {
		t.Error("signature verified under the wrong domain — relay defense broken")
	}
}

// TestAuthorizeRejectsBadCallback: a callback outside the allowlist is refused before
// any card sign (403); missing params are a 400.
func TestAuthorizeRejectsBadCallback(t *testing.T) {
	cardPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := Handler(ServeConfig{
		Signer: fakeSigner{cardPriv}, GUID: "G",
		AllowCallbacks: []string{"https://forge.linenisgreat.com/auth/callback"},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/authorize?callback="+url.QueryEscape("https://evil.example/cb")+"&nonce=N&state=S", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("evil callback = %d, want 403", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/authorize?callback="+url.QueryEscape("https://forge.linenisgreat.com/auth/callback"), nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing params = %d, want 400", rec.Code)
	}
}
