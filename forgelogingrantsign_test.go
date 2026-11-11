package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"code.linenisgreat.com/papi/internal/alfa/logingrant"
	"code.linenisgreat.com/papi/internal/alfa/signchallenge"
)

func runForgeGrant(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newForgeGrantCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return stdout.String(), stderr.String(), err
}

func withFakeCard(t *testing.T) (*ecdsa.PrivateKey, *int) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signs := 0
	orig := signChallengeSignerFn
	signChallengeSignerFn = func(_ context.Context, _, guid, _, _ string) (signchallenge.Signer, string, error) {
		return countingSigner{signerFake{priv}, &signs}, guid, nil
	}
	origNow := grantSignNow
	grantSignNow = func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 500, time.UTC) }
	t.Cleanup(func() { signChallengeSignerFn = orig; grantSignNow = origNow })
	return priv, &signs
}

func writePubKey(t *testing.T, dir string, pub ssh.PublicKey, comment string) string {
	t.Helper()
	path := filepath.Join(dir, "mint.pub")
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newMintPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func TestForgeGrantSignProducesAVerifiableGrant(t *testing.T) {
	card, signs := withFakeCard(t)
	dir := t.TempDir()
	pub := newMintPub(t)
	keyFile := writePubKey(t, dir, pub, "nikulin mint key")
	out := filepath.Join(dir, "grant")

	_, _, err := runForgeGrant(t, "sign",
		"--principal", "nikulin-session", "--key-file", keyFile, "--domain", "forge.example",
		"--not-before", "2026-11-11T00:00:00Z", "--expires", "2026-11-18T00:00:00Z",
		"--max-session", "2h", "--out", out)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if *signs != 1 {
		t.Errorf("card signed %d times, want exactly 1", *signs)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text, sig, err := logingrant.ParseSigned(data)
	if err != nil {
		t.Fatalf("output is not a signed grant: %v\n%s", err, data)
	}
	if err := logingrant.VerifyGrantSig(&card.PublicKey, text, sig); err != nil {
		t.Errorf("card signature does not verify: %v", err)
	}
	g, _ := logingrant.Parse(text)
	if g.Principal != "nikulin-session" || g.Domain != "forge.example" || g.MaxSession != 2*time.Hour ||
		g.Expires.Format(time.RFC3339) != "2026-11-18T00:00:00Z" {
		t.Errorf("grant fields wrong: %+v", g)
	}
	if string(g.Key.Marshal()) != string(pub.Marshal()) {
		t.Error("grant names a different key than the key file")
	}
	if strings.Contains(string(data), "nikulin mint key") {
		t.Error("the key file's comment leaked into the grant")
	}
	if g.Nonce == "" {
		t.Error("no nonce")
	}
}

func TestForgeGrantSignWritesToStdoutByDefault(t *testing.T) {
	withFakeCard(t)
	keyFile := writePubKey(t, t.TempDir(), newMintPub(t), "")
	stdout, _, err := runForgeGrant(t, "sign", "--principal", "p", "--key-file", keyFile,
		"--domain", "forge.example", "--expires", "2026-11-12T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := logingrant.ParseSigned([]byte(stdout)); err != nil {
		t.Fatalf("stdout is not a signed grant: %v\n%s", err, stdout)
	}
}

func TestForgeGrantSignRefusals(t *testing.T) {
	withFakeCard(t)
	dir := t.TempDir()
	good := writePubKey(t, dir, newMintPub(t), "")
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPub, _ := ssh.NewPublicKey(&ec.PublicKey)
	ecFile := filepath.Join(dir, "ec.pub")
	if err := os.WriteFile(ecFile, ssh.MarshalAuthorizedKey(ecPub), 0o644); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "exists")
	if err := os.WriteFile(existing, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := func(extra ...string) []string {
		return append([]string{
			"sign", "--principal", "p", "--key-file", good, "--domain", "forge.example",
			"--not-before", "2026-11-11T00:00:00Z", "--expires", "2026-11-18T00:00:00Z",
		}, extra...)
	}
	cases := map[string][]string{
		"no principal":        {"sign", "--key-file", good, "--domain", "d.example", "--expires", "2026-11-18T00:00:00Z"},
		"no key":              {"sign", "--principal", "p", "--domain", "d.example", "--expires", "2026-11-18T00:00:00Z"},
		"no domain":           {"sign", "--principal", "p", "--key-file", good, "--expires", "2026-11-18T00:00:00Z"},
		"no expires":          {"sign", "--principal", "p", "--key-file", good, "--domain", "d.example"},
		"ecdsa key":           {"sign", "--principal", "p", "--key-file", ecFile, "--domain", "d.example", "--expires", "2026-11-18T00:00:00Z"},
		"window over 168h":    base("--expires", "2026-11-18T00:00:01Z"),
		"expires not UTC":     base("--expires", "2026-11-18T01:00:00+01:00"),
		"expires before":      base("--expires", "2026-11-10T00:00:00Z"),
		"bad max-session":     base("--max-session", "0s"),
		"overwrites a file":   base("--out", existing),
		"domain with scheme":  base("--domain", "https://forge.example"),
		"key is a directory":  {"sign", "--principal", "p", "--key-file", dir, "--domain", "d.example", "--expires", "2026-11-18T00:00:00Z"},
		"private key as pub":  {"sign", "--principal", "p", "--key-file", filepath.Join(dir, "absent"), "--domain", "d.example", "--expires", "2026-11-18T00:00:00Z"},
		"expires in the past": {"sign", "--principal", "p", "--key-file", good, "--domain", "d.example", "--not-before", "2020-01-01T00:00:00Z", "--expires", "2020-01-02T00:00:00Z"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runForgeGrant(t, args...); err == nil {
				t.Errorf("accepted %v", args)
			}
		})
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep me" {
		t.Error("an existing file was overwritten")
	}
}

// If the output file appears between the early check and the write, the grant is not
// lost (the card already signed) and the other file is not overwritten.
func TestForgeGrantSignRaceOnOutKeepsTheSignature(t *testing.T) {
	withFakeCard(t)
	dir := t.TempDir()
	keyFile := writePubKey(t, dir, newMintPub(t), "")
	out := filepath.Join(dir, "grant")

	orig := signChallengeSignerFn
	signChallengeSignerFn = func(ctx context.Context, mode, guid, pin, sock string) (signchallenge.Signer, string, error) {
		s, g, err := orig(ctx, mode, guid, pin, sock)
		// The file appears after validation, as the signer is built.
		_ = os.WriteFile(out, []byte("planted"), 0o644)
		return s, g, err
	}
	defer func() { signChallengeSignerFn = orig }()

	stdout, _, err := runForgeGrant(t, "sign", "--principal", "p", "--key-file", keyFile,
		"--domain", "forge.example", "--not-before", "2026-11-11T00:00:00Z",
		"--expires", "2026-11-12T00:00:00Z", "--out", out)
	if err == nil {
		t.Fatal("overwrote a file that appeared during signing")
	}
	if data, _ := os.ReadFile(out); string(data) != "planted" {
		t.Error("the planted file was overwritten")
	}
	if _, _, perr := logingrant.ParseSigned([]byte(stdout)); perr != nil {
		t.Errorf("the signed grant was not preserved on stdout: %v\n%s", perr, stdout)
	}
}

// The card must not be touched when the request is invalid: a refusal costs the
// operator nothing at the card.
func TestForgeGrantSignDoesNotTouchTheCardOnBadInput(t *testing.T) {
	_, signs := withFakeCard(t)
	keyFile := writePubKey(t, t.TempDir(), newMintPub(t), "")
	_, _, err := runForgeGrant(t, "sign", "--principal", "p", "--key-file", keyFile,
		"--domain", "forge.example", "--not-before", "2026-11-11T00:00:00Z", "--expires", "2026-12-31T00:00:00Z")
	if err == nil {
		t.Fatal("oversize window accepted")
	}
	if *signs != 0 {
		t.Errorf("card signed %d times for an invalid grant", *signs)
	}
}
