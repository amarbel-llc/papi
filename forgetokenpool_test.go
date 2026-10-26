package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/0/forgetoken"
	"code.linenisgreat.com/papi/internal/alfa/signchallenge"
	"code.linenisgreat.com/papi/internal/bravo/authproxy"
)

func TestForgeTokenMintBatchValidation(t *testing.T) {
	for name, args := range map[string][]string{
		"batch without out":  {"mint", "--batch", "rows"},
		"out without batch":  {"mint", "--out", "dir"},
		"batch with session": {"mint", "--batch", "-", "--out", "d", "--session", "s"},
		"batch with repo":    {"mint", "--batch", "-", "--out", "d", "--repo", "papi"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runForgeToken(t, args...); err == nil {
				t.Fatalf("%v must be refused", args)
			}
		})
	}
}

// countingSigner is signerFake that counts card signatures.
type countingSigner struct {
	signerFake
	n *int
}

func (s countingSigner) SignSlot9A(ctx context.Context, guid string, msg []byte) ([]byte, error) {
	*s.n++
	return s.signerFake.SignSlot9A(ctx, guid, msg)
}

// poolCardForge is the forward-auth verifier's login legs and the forge's token API
// behind one host, as the real vhost serves them. The verifier does not check the
// signature: what is under test is how many times papi asks the card.
func poolCardForge(t *testing.T) *httptest.Server {
	t.Helper()
	var nextID int64
	var names []string
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://oracle.example/authorize?"+url.Values{
			"nonce": {"n1"}, "state": {"s1"},
		}.Encode())
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: authproxy.DefaultCookieName, Value: "cookie"})
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/api/v1/users/sasha/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			list := make([]forgetoken.Token, len(names))
			for i, n := range names {
				list[i] = forgetoken.Token{ID: int64(i + 1), Name: n}
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		if c, err := r.Cookie(authproxy.DefaultCookieName); err != nil || c.Value != "cookie" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		nextID++
		names = append(names, body.Name)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": nextID, "name": body.Name, "sha1": "pool-secret-" + strconv.FormatInt(nextID, 10),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// `mint --batch --card-login` signs with the card once for the whole pool, writes
// each secret to its own file, and keeps every secret off stdout and stderr.
func TestForgeTokenMintBatchCardLoginOnce(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signs := 0
	orig := signChallengeSignerFn
	signChallengeSignerFn = func(_ context.Context, _, guid, _, _ string) (signchallenge.Signer, string, error) {
		return countingSigner{signerFake{priv}, &signs}, guid, nil
	}
	defer func() { signChallengeSignerFn = orig }()

	srv := poolCardForge(t)
	tmp := t.TempDir()
	rows := filepath.Join(tmp, "rows")
	if err := os.WriteFile(rows, []byte(
		"linenisgreat/papi pool/papi/01\nlinenisgreat/papi pool/papi/02\nlinenisgreat/spinclass pool/spinclass/01\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "pool")

	output, err := runForgeToken(t, "mint", "--host", srv.URL, "--user", "sasha", "--card-login",
		"--batch", rows, "--out", out, "--ttl", "336h")
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	if signs != 1 {
		t.Fatalf("card signed %d times, want 1 for three tokens", signs)
	}
	if strings.Contains(output, "pool-secret-") {
		t.Fatalf("a secret reached the command's output:\n%s", output)
	}
	for _, session := range []string{"pool/papi/01", "pool/papi/02", "pool/spinclass/01"} {
		if !strings.Contains(output, "\t"+session+"\t") {
			t.Errorf("output should list session %s:\n%s", session, output)
		}
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 { // three secrets + manifest
		t.Fatalf("pool dir has %d entries, want 4", len(entries))
	}
}
