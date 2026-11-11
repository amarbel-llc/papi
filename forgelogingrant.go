package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"code.linenisgreat.com/papi/internal/0/forgetoken"
	"code.linenisgreat.com/papi/internal/alfa/logingrant"
	"code.linenisgreat.com/papi/internal/bravo/authproxy"
)

// loginKeySign signs the login preimage with the grant's software key and returns the
// raw 64-byte ed25519 signature.
type loginKeySign func(msg []byte) ([]byte, error)

// dialLoginAgent reaches the ssh-agent holding the grant key. A seam so tests can serve
// an in-memory agent instead of a socket.
var dialLoginAgent = func() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("--login-key-agent needs $SSH_AUTH_SOCK")
	}
	return net.Dial("unix", sock)
}

// validateLoginFlags enforces that a login-grant login is chosen deliberately and alone:
// a grant needs exactly one key source, the key flags mean nothing without a grant, and
// no other credential may be silently shadowed by it.
func (f *forgeTokenFlags) validateLoginFlags() error {
	hasKey := f.loginKeyFile != "" || f.loginKeyAgent
	switch {
	case f.loginGrant == "" && hasKey:
		return errors.New("--login-key-file and --login-key-agent only apply with --login-grant")
	case f.loginGrant == "":
		return nil
	case f.loginKeyFile != "" && f.loginKeyAgent:
		return errors.New("--login-key-file and --login-key-agent are alternatives; pass one")
	case !hasKey:
		return errors.New("--login-grant needs the grant's key: pass --login-key-file or --login-key-agent")
	case f.cardLogin || f.passwordCmd != "" || f.tokenCmd != "":
		return errors.New("--login-grant is its own credential; drop --card-login, --password-command and --token-command")
	}
	return nil
}

// grantCredential performs a login-grant login (RFC-0001 §5.2.1): it reads the signed
// grant, proves possession of the grant's software key over the verifier's nonce, and
// returns the session-cookie credential. The grant is checked locally first, so an
// expired or mis-bound one fails with a precise message instead of the verifier's
// deliberately generic 401.
func (f *forgeTokenFlags) grantCredential(ctx context.Context, base, domain string) (forgetoken.Credential, error) {
	data, err := os.ReadFile(f.loginGrant)
	if err != nil {
		return nil, fmt.Errorf("read login grant: %w", err)
	}
	text, cardSig, err := logingrant.ParseSigned(data)
	if err != nil {
		return nil, fmt.Errorf("login grant %s: %w", f.loginGrant, err)
	}
	g, err := logingrant.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("login grant %s: %w", f.loginGrant, err)
	}
	if err := g.ValidAt(time.Now()); err != nil {
		return nil, fmt.Errorf("login grant %s (valid %s to %s): %w", f.loginGrant,
			g.NotBefore.Format(time.RFC3339), g.Expires.Format(time.RFC3339), err)
	}
	if g.Domain != domain {
		return nil, fmt.Errorf("login grant is bound to %q but this login's binding domain is %q "+
			"(see --auth-domain)", g.Domain, domain)
	}

	var sign loginKeySign
	if f.loginKeyAgent {
		sign = agentKeySigner(g.Key)
	} else if sign, err = fileKeySigner(f.loginKeyFile, g.Key); err != nil {
		return nil, err
	}
	id := g.ID()
	return forgetoken.Login(ctx, base, domain, authproxy.DefaultCookieName,
		func(_ context.Context, domain, nonce string) (string, error) {
			raw, err := sign(logingrant.LoginPreimage(domain, nonce, id))
			if err != nil {
				return "", err
			}
			return logingrant.EncodeSig(raw), nil
		},
		url.Values{"grant": {logingrant.EncodeText(text)}, "grant_sig": {cardSig}})
}

// fileKeySigner loads an unencrypted OpenSSH ed25519 private key and checks it is the
// key the grant names. The file must not be readable by group or other: this key is a
// bearer credential.
func fileKeySigner(path string, want ssh.PublicKey) (loginKeySign, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("login key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("login key %s has permissions %#o; make it private (chmod 600)",
			path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("login key: %w", err)
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("login key is passphrase-protected; use --login-key-agent instead")
		}
		return nil, fmt.Errorf("login key %s: %w", path, err)
	}
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		priv = k
	case *ed25519.PrivateKey:
		priv = *k
	default:
		return nil, fmt.Errorf("login key %s is %T, not ed25519", path, raw)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	if string(pub.Marshal()) != string(want.Marshal()) {
		return nil, fmt.Errorf("login key %s does not match the key named in the grant", path)
	}
	return func(msg []byte) ([]byte, error) { return ed25519.Sign(priv, msg), nil }, nil
}

// agentKeySigner asks the ssh-agent to sign with the grant's key. The agent decides
// whether to prompt or refuse; papi only names the key.
func agentKeySigner(want ssh.PublicKey) loginKeySign {
	return func(msg []byte) ([]byte, error) {
		conn, err := dialLoginAgent()
		if err != nil {
			return nil, fmt.Errorf("reach the ssh-agent: %w", err)
		}
		defer conn.Close()
		sig, err := agent.NewClient(conn).Sign(want, msg)
		if err != nil {
			return nil, fmt.Errorf("the ssh-agent would not sign with the grant's key: %w", err)
		}
		if sig.Format != ssh.KeyAlgoED25519 || len(sig.Blob) != ed25519.SignatureSize {
			return nil, fmt.Errorf("the ssh-agent returned a %s signature of %d bytes, want ed25519",
				sig.Format, len(sig.Blob))
		}
		return sig.Blob, nil
	}
}
