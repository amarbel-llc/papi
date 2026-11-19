package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/alfa/signchallenge"
)

// runAuth executes `papi auth` against srvURL with the slot-9A signer faked, and
// returns stdout and stderr separately (the session must only ever reach stdout).
func runAuth(t *testing.T, srvURL string, priv *ecdsa.PrivateKey, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	orig := signChallengeSignerFn
	signChallengeSignerFn = func(_ context.Context, _, guid, _, _ string) (signchallenge.Signer, string, error) {
		return signerFake{priv}, guid, nil
	}
	defer func() { signChallengeSignerFn = orig }()

	cmd := newAuthCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(append([]string{srvURL}, args...))
	err = cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestAuthCmd(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const authKeyID = "piggy-auth-v1@ecdsa_p256_pub-me"
	srv := reposSignServer(t, &priv.PublicKey, authKeyID)
	defer srv.Close()

	t.Run("default is the session payload as JSON", func(t *testing.T) {
		out, _, err := runAuth(t, srv.URL, priv, "--auth-key-id", authKeyID)
		if err != nil {
			t.Fatalf("auth: %v", err)
		}
		var got struct {
			Session   string   `json:"session"`
			Principal string   `json:"principal"`
			Groups    []string `json:"groups"`
			ExpiresAt int64    `json:"expires_at"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if got.Session != "sess1" || got.Principal != "tester" || got.ExpiresAt != 9999999999 {
			t.Errorf("unexpected payload: %+v", got)
		}
	})

	// Each fresh server consumes one challenge, so the remaining modes use their own.
	t.Run("--raw prints the bare id", func(t *testing.T) {
		s := reposSignServer(t, &priv.PublicKey, authKeyID)
		defer s.Close()
		out, errOut, err := runAuth(t, s.URL, priv, "--auth-key-id", authKeyID, "--raw")
		if err != nil {
			t.Fatalf("auth --raw: %v", err)
		}
		if out != "sess1\n" {
			t.Errorf("want %q, got %q", "sess1\n", out)
		}
		if strings.Contains(errOut, "sess1") {
			t.Errorf("the session id leaked to stderr: %q", errOut)
		}
	})

	t.Run("--header prints the curl header", func(t *testing.T) {
		s := reposSignServer(t, &priv.PublicKey, authKeyID)
		defer s.Close()
		out, _, err := runAuth(t, s.URL, priv, "--auth-key-id", authKeyID, "--header")
		if err != nil {
			t.Fatalf("auth --header: %v", err)
		}
		if out != "Authorization: PiggySession sess1\n" {
			t.Errorf("want the header line, got %q", out)
		}
	})

	t.Run("--raw and --header are mutually exclusive, before any card step", func(t *testing.T) {
		_, _, err := runAuth(t, srv.URL, priv, "--auth-key-id", authKeyID, "--raw", "--header")
		if err == nil {
			t.Fatal("--raw with --header must be refused")
		}
	})

	t.Run("no credential is refused, before any request", func(t *testing.T) {
		_, _, err := runAuth(t, srv.URL, priv)
		if err == nil || !strings.Contains(err.Error(), "--auth-key-id") {
			t.Fatalf("want an error naming --auth-key-id, got %v", err)
		}
	})

	t.Run("an unregistered key fails and prints nothing on stdout", func(t *testing.T) {
		s := reposSignServer(t, &priv.PublicKey, authKeyID)
		defer s.Close()
		out, _, err := runAuth(t, s.URL, priv, "--auth-key-id", "piggy-auth-v1@ecdsa_p256_pub-other")
		if err == nil || out != "" {
			t.Fatalf("want an error and empty stdout, got err=%v out=%q", err, out)
		}
	})
}
