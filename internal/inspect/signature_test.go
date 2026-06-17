package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amarbel-llc/papi/internal/papi"
	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
)

// signDoc builds a §10.4 ssh-9a-signed PAPI document around doc (a map without a
// signature member), signing the same way piggy does: full SSH-wire blob
// string(alg) || string(r,s) over the RFC 8785 JCS bytes. It publishes the
// signer's key in piggy.ssh_authorized_keys and returns the full document JSON.
func signDoc(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	piggy, _ := doc["piggy"].(map[string]any)
	if piggy == nil {
		piggy = map[string]any{}
		doc["piggy"] = piggy
	}
	piggy["ssh_authorized_keys"] = []any{keyLine}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	sshSig, err := signer.Sign(rand.Reader, canon)
	if err != nil {
		t.Fatal(err)
	}

	wire := append(sshString([]byte(sshSig.Format)), sshString([]byte(sshSig.Blob))...)
	doc["signature"] = map[string]any{
		"alg": "ssh-9a",
		"key": keyLine,
		"sig": base64.StdEncoding.EncodeToString(wire),
	}
	full, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func serveDoc(data []byte) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte(`,"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`))
	})
	return httptest.NewServer(mux)
}

func signaturePointFor(t *testing.T, data []byte) point {
	t.Helper()
	srv := serveDoc(data)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return signaturePoint(context.Background(), c)
}

func TestSignatureValid(t *testing.T) {
	full := signDoc(t, map[string]any{"version": "papi/v0", "person": map[string]any{"handle": "tester"}})
	p := signaturePointFor(t, full)
	if !p.ok || p.reason != "" {
		t.Fatalf("valid signature not accepted: %+v", p)
	}
	if !strings.Contains(p.desc, "signed-and-valid") {
		t.Errorf("desc = %q", p.desc)
	}
}

func TestSignatureTampered(t *testing.T) {
	full := signDoc(t, map[string]any{"version": "papi/v0", "person": map[string]any{"handle": "tester"}})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(full, &m); err != nil {
		t.Fatal(err)
	}
	m["person"] = json.RawMessage(`{"handle":"attacker"}`) // change signed content
	tampered, _ := json.Marshal(m)
	p := signaturePointFor(t, tampered)
	if p.ok || !p.must {
		t.Fatalf("tampered signature not flagged signed-but-invalid: %+v", p)
	}
}

func TestSignatureUnsigned(t *testing.T) {
	p := signaturePointFor(t, []byte(`{"version":"papi/v0","person":{"handle":"t"}}`))
	if p.reason == "" {
		t.Fatalf("unsigned doc should be a skip, got %+v", p)
	}
}

func TestSignatureKeyNotPublished(t *testing.T) {
	full := signDoc(t, map[string]any{"version": "papi/v0"})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(full, &m); err != nil {
		t.Fatal(err)
	}
	m["piggy"] = json.RawMessage(`{"ssh_authorized_keys":[]}`) // unpublish the signing key
	unpub, _ := json.Marshal(m)
	p := signaturePointFor(t, unpub)
	if p.reason == "" {
		t.Fatalf("unpublished key should be a skip (unverifiable), got %+v", p)
	}
}
