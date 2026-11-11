package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"code.linenisgreat.com/papi/internal/alfa/logingrant"
	"code.linenisgreat.com/papi/internal/bravo/authproxy"
)

const grantTestPrincipal = "nikulin-session"

// grantEnv is the real authproxy verifier (grants enabled) and a forge token API behind
// one host, with a signed grant file and a matching key file on disk. What is under
// test is the whole client path: grant file -> key signature -> /auth/callback ->
// cookie -> mint.
type grantEnv struct {
	srv       *httptest.Server
	grantFile string
	keyFile   string
	keyPriv   ed25519.PrivateKey
	grant     logingrant.Grant
	mintedBy  []string // principals the forge saw on a token create
}

func newGrantEnv(t *testing.T, mutate func(*logingrant.Grant)) *grantEnv {
	t.Helper()
	env := &grantEnv{}
	cardPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cardPub, err := ssh.NewPublicKey(&cardPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := authproxy.ParseRegistry([]byte(
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cardPub))) + " piggy slot=9A guid=ABCD1234 cn=operator\n"))
	if err != nil {
		t.Fatal(err)
	}

	cookieKey := bytes.Repeat([]byte("k"), 32)
	var handler http.Handler
	env.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(env.srv.Close)

	_, env.keyPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPub, err := ssh.NewPublicKey(env.keyPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(env.srv.URL, "http://")
	now := time.Now().UTC().Truncate(time.Second)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	env.grant = logingrant.Grant{
		Principal:  grantTestPrincipal,
		Key:        keyPub,
		Domain:     host,
		NotBefore:  now.Add(-time.Hour),
		Expires:    now.Add(48 * time.Hour),
		MaxSession: time.Hour,
		Nonce:      logingrant.EncodeSig(nonce),
	}
	if mutate != nil {
		mutate(&env.grant)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", authproxy.VerifierHandler(authproxy.VerifierConfig{
		CookieKey:            cookieKey,
		Registry:             registry,
		OracleLogin:          "https://oracle.example/authorize",
		ExternalURL:          env.srv.URL,
		AllowGrantPrincipals: authproxy.Set([]string{grantTestPrincipal}),
	}))
	mux.HandleFunc("/api/v1/users/sasha/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("[]"))
			return
		}
		ck, err := r.Cookie(authproxy.DefaultCookieName)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims, err := authproxy.ParseSession(cookieKey, ck.Value, time.Now())
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		env.mintedBy = append(env.mintedBy, claims.Principal)
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "name": body.Name, "sha1": "grant-minted-secret"})
	})
	handler = mux

	dir := t.TempDir()
	text, err := logingrant.Build(env.grant)
	if err != nil {
		t.Fatalf("Build grant: %v", err)
	}
	sig, err := logingrant.SignGrant(context.Background(), signerFake{cardPriv}, "", text)
	if err != nil {
		t.Fatal(err)
	}
	env.grantFile = filepath.Join(dir, "grant")
	if err := os.WriteFile(env.grantFile, logingrant.MarshalSigned(text, sig), 0o644); err != nil {
		t.Fatal(err)
	}
	env.keyFile = filepath.Join(dir, "key")
	writeOpenSSHKey(t, env.keyFile, env.keyPriv, 0o600)
	return env
}

func writeOpenSSHKey(t *testing.T, path string, priv ed25519.PrivateKey, mode os.FileMode) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
		t.Fatal(err)
	}
}

func (e *grantEnv) mint(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{
		"mint", "--host", e.srv.URL, "--user", "sasha", "--repo", "linenisgreat/papi",
		"--session", "papi/lucid-hazel",
	}, extra...)
	return runForgeToken(t, args...)
}

func TestMintWithLoginGrantAndKeyFile(t *testing.T) {
	env := newGrantEnv(t, nil)
	out, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
	if err != nil {
		t.Fatalf("mint: %v\n%s", err, out)
	}
	if !strings.Contains(out, "grant-minted-secret") {
		t.Errorf("token not printed:\n%s", out)
	}
	if len(env.mintedBy) != 1 || env.mintedBy[0] != grantTestPrincipal {
		t.Errorf("forge saw principals %v, want the grant's restricted principal only", env.mintedBy)
	}
}

func TestMintWithLoginGrantAndAgentKey(t *testing.T) {
	env := newGrantEnv(t, nil)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: env.keyPriv}); err != nil {
		t.Fatal(err)
	}
	orig := dialLoginAgent
	dialLoginAgent = func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = agent.ServeAgent(keyring, server); _ = server.Close() }()
		return client, nil
	}
	defer func() { dialLoginAgent = orig }()

	out, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-agent")
	if err != nil {
		t.Fatalf("mint via agent: %v\n%s", err, out)
	}
	if len(env.mintedBy) != 1 {
		t.Errorf("minted %d tokens, want 1", len(env.mintedBy))
	}
}

func TestMintWithLoginGrantRefusals(t *testing.T) {
	t.Run("grant for another key", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		writeOpenSSHKey(t, env.keyFile, other, 0o600)
		out, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("want a key-mismatch error, got %v\n%s", err, out)
		}
		if len(env.mintedBy) != 0 {
			t.Error("a token was minted")
		}
	})
	t.Run("expired grant is refused locally", func(t *testing.T) {
		env := newGrantEnv(t, func(g *logingrant.Grant) {
			g.NotBefore = time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
			g.Expires = time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
		})
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want an expiry error, got %v", err)
		}
	})
	t.Run("grant bound to another verifier is refused locally", func(t *testing.T) {
		env := newGrantEnv(t, func(g *logingrant.Grant) { g.Domain = "elsewhere.example" })
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "elsewhere.example") {
			t.Fatalf("want a domain error naming the grant's domain, got %v", err)
		}
	})
	t.Run("key file readable by others", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		if err := os.Chmod(env.keyFile, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("want a permissions error, got %v", err)
		}
	})
	t.Run("verifier refuses a tampered grant", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		data, _ := os.ReadFile(env.grantFile)
		data = bytes.Replace(data, []byte("max-session: 3600"), []byte("max-session: 3601"), 1)
		if err := os.WriteFile(env.grantFile, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "login grant was refused") {
			t.Fatalf("want the grant-refused error, got %v", err)
		}
		if len(env.mintedBy) != 0 {
			t.Error("a token was minted")
		}
	})
}

// The key file is a bearer credential read from a path an attacker on the host may
// influence, so it is opened without following symlinks, checked on the open fd, and
// size-capped; and the grant file is read with a bound.
func TestLoginInputFilesAreHardened(t *testing.T) {
	t.Run("key file is a symlink", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		link := filepath.Join(filepath.Dir(env.keyFile), "link")
		if err := os.Symlink(env.keyFile, link); err != nil {
			t.Fatal(err)
		}
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", link)
		if err == nil {
			t.Fatal("a symlinked key file was followed")
		}
		if len(env.mintedBy) != 0 {
			t.Error("a token was minted")
		}
	})
	t.Run("key file is a directory", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", filepath.Dir(env.keyFile))
		if err == nil {
			t.Fatal("a directory was accepted as a key file")
		}
	})
	t.Run("key file is oversize", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		if err := os.WriteFile(env.keyFile, bytes.Repeat([]byte("a"), 1<<20), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("want a size refusal, got %v", err)
		}
	})
	t.Run("grant file is oversize", func(t *testing.T) {
		env := newGrantEnv(t, nil)
		if err := os.WriteFile(env.grantFile, bytes.Repeat([]byte("a"), 1<<20), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := env.mint(t, "--login-grant", env.grantFile, "--login-key-file", env.keyFile)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("want a size refusal, got %v", err)
		}
	})
}

func TestLoginGrantFlagCombinations(t *testing.T) {
	env := newGrantEnv(t, nil)
	for name, args := range map[string][]string{
		"grant without a key source": {"--login-grant", env.grantFile},
		"two key sources":            {"--login-grant", env.grantFile, "--login-key-file", env.keyFile, "--login-key-agent"},
		"key file without grant":     {"--login-key-file", env.keyFile},
		"agent without grant":        {"--login-key-agent"},
		"grant with card-login":      {"--login-grant", env.grantFile, "--login-key-file", env.keyFile, "--card-login"},
		"grant with password":        {"--login-grant", env.grantFile, "--login-key-file", env.keyFile, "--password-command", "echo x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := env.mint(t, args...); err == nil {
				t.Errorf("%v accepted", args)
			}
			if len(env.mintedBy) != 0 {
				t.Error("a token was minted")
			}
		})
	}
}
