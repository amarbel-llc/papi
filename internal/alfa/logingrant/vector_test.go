package logingrant

import "testing"

// Golden vector (RFC-0001 §5.2.1): a deterministic test seed (0x07 x 32; a public test
// key, never a real credential) and fixed fields yield exactly these bytes. ed25519 is
// deterministic, so the login signature is pinned too; any change to the canonical
// text, the grant id, or the login preimage framing breaks this on purpose.
const (
	vectorText = "papi login-grant v1\n" +
		"principal: nikulin-session\n" +
		"key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs\n" +
		"domain: forge.example\n" +
		"not-before: 2026-11-11T00:00:00Z\n" +
		"expires: 2026-11-18T00:00:00Z\n" +
		"max-session: 7200\n" +
		"nonce: AAECAwQFBgcICQoLDA0ODw\n"
	vectorID       = "3d42781784af9c27fd66550539775a88"
	vectorLoginSig = "Pwt7rwROd4Z7WFSH4Iyee8Ygk6FkeFvnUnblPYl-lKRUVtga012hwcjQOVziv7Pjss9S2YPrygfILTw48miKBw"
)

func TestGoldenVector(t *testing.T) {
	g, priv := goodGrant(t)
	if got := string(g.Text()); got != vectorText {
		t.Errorf("text drifted:\n%s", got)
	}
	if g.ID() != vectorID {
		t.Errorf("id = %s, want %s", g.ID(), vectorID)
	}
	if sig := SignLogin(priv, testDomain, "N1", g.ID()); sig != vectorLoginSig {
		t.Errorf("login sig = %s, want %s", sig, vectorLoginSig)
	}

	parsed, err := Parse([]byte(vectorText))
	if err != nil {
		t.Fatalf("Parse(vector): %v", err)
	}
	if err := parsed.VerifyLogin(testDomain, "N1", vectorLoginSig); err != nil {
		t.Errorf("pinned login signature rejected: %v", err)
	}
}
