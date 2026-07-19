package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/0/papi"
	"golang.org/x/crypto/ssh"
)

// testCoLocRecipient is a well-formed §5.1 slot-9D recipient id; a co_location
// proof binds it to a slot-9A key.
const testCoLocRecipient = "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"

// coLocKey is an ephemeral slot-9A key standing in for a published card key: its
// markl-id, its OpenSSH authorized_keys line, and a signer over a claim.
type coLocKey struct {
	priv    *ecdsa.PrivateKey
	id      string // piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…
	sshLine string
}

func newCoLocKey(t *testing.T) coLocKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	id, err := markl.Build(markl.PurposePIVAuth, markl.FormatSSHEcdsaNistp256Pub, compressed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return coLocKey{priv, id, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))}
}

// sign produces a papi-proof-sig-v1@ecdsa_p256_sig markl-id over SHA-256(msg) —
// exactly what a slot-9A card produces for a §9.6 claim.
func (k coLocKey) sign(t *testing.T, msg string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	id, err := markl.Build(markl.PurposeProofSig, markl.FormatEcdsaP256Sig, rs)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// validEntry builds a verifiable Level-A co_location entry binding
// testCoLocRecipient to k.
func validEntry(t *testing.T, k coLocKey) papi.CoLocation {
	claim := coLocationClaim(testCoLocRecipient, k.id)
	return papi.CoLocation{
		ID:        "co-loc-1",
		Recipient: testCoLocRecipient,
		Key:       k.id,
		Level:     "soft",
		Claim:     claim,
		Sig:       k.sign(t, claim),
	}
}

// serveCoLoc serves a /papi document publishing sshLine + recipient and the given
// co_location entries, returning a client pointed at it.
func serveCoLoc(t *testing.T, sshLine, recipient string, entries []papi.CoLocation) *papi.Client {
	t.Helper()
	data := map[string]any{
		"version": "papi/v0",
		"piggy": map[string]any{
			"ssh_authorized_keys":   []any{sshLine},
			"encryption_recipients": []any{recipient},
		},
		"co_location": entries,
	}
	dataB, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/papi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(dataB)
		_, _ = w.Write([]byte(`,"meta":{"type":"papi","version":"papi/v0","visibility":"public"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verdict classifies a point into the §9.6.3 three outcomes.
func verdict(p point) string {
	switch {
	case p.reason != "":
		return "unverifiable"
	case !p.ok:
		return "unverified"
	default:
		return "verified"
	}
}

func only(t *testing.T, pts []point) point {
	t.Helper()
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	return pts[0]
}

func TestCoLocationVerified(t *testing.T) {
	k := newCoLocKey(t)
	c := serveCoLoc(t, k.sshLine, testCoLocRecipient, []papi.CoLocation{validEntry(t, k)})
	p := only(t, coLocationChecks(context.Background(), c))
	if v := verdict(p); v != "verified" {
		t.Errorf("verdict = %s, want verified; %s %v", v, p.reason, p.diag)
	}
}

// A "attested" entry with a valid Level-A binding but RESERVED evidence verifies at
// the Level-A floor (never silently reported as the stronger level).
func TestCoLocationAttestedVerifiesAtFloor(t *testing.T) {
	k := newCoLocKey(t)
	e := validEntry(t, k)
	e.Level = "attested"
	p := only(t, coLocationChecks(context.Background(), serveCoLoc(t, k.sshLine, testCoLocRecipient, []papi.CoLocation{e})))
	if v := verdict(p); v != "verified" {
		t.Fatalf("verdict = %s, want verified; %s %v", v, p.reason, p.diag)
	}
	if !strings.Contains(p.desc, "RESERVED") {
		t.Errorf("attested floor verdict should note RESERVED evidence; got %q", p.desc)
	}
}

func TestCoLocationNoMember(t *testing.T) {
	k := newCoLocKey(t)
	p := only(t, coLocationChecks(context.Background(), serveCoLoc(t, k.sshLine, testCoLocRecipient, nil)))
	if verdict(p) != "unverifiable" { // a skip
		t.Errorf("empty co_location[] should skip; got %s", verdict(p))
	}
}

func TestCoLocationRejects(t *testing.T) {
	ctx := context.Background()

	t.Run("tampered claim -> unverified", func(t *testing.T) {
		k := newCoLocKey(t)
		e := validEntry(t, k)
		e.Claim += " (tampered)"
		p := only(t, coLocationChecks(ctx, serveCoLoc(t, k.sshLine, testCoLocRecipient, []papi.CoLocation{e})))
		if verdict(p) != "unverified" {
			t.Errorf("got %s, want unverified; %s", verdict(p), p.desc)
		}
	})

	t.Run("forged sig -> unverified", func(t *testing.T) {
		k := newCoLocKey(t)
		e := validEntry(t, k)
		e.Sig = k.sign(t, "a different message") // valid markl, wrong message
		p := only(t, coLocationChecks(ctx, serveCoLoc(t, k.sshLine, testCoLocRecipient, []papi.CoLocation{e})))
		if verdict(p) != "unverified" {
			t.Errorf("got %s, want unverified; %s", verdict(p), p.desc)
		}
	})

	t.Run("unpublished key -> unverifiable", func(t *testing.T) {
		published, other := newCoLocKey(t), newCoLocKey(t)
		// Entry binds `other`, but only `published` is in ssh_authorized_keys.
		claim := coLocationClaim(testCoLocRecipient, other.id)
		e := papi.CoLocation{ID: "x", Recipient: testCoLocRecipient, Key: other.id, Level: "soft", Claim: claim, Sig: other.sign(t, claim)}
		p := only(t, coLocationChecks(ctx, serveCoLoc(t, published.sshLine, testCoLocRecipient, []papi.CoLocation{e})))
		if verdict(p) != "unverifiable" {
			t.Errorf("got %s, want unverifiable; %s", verdict(p), p.desc)
		}
	})

	t.Run("unpublished recipient -> unverifiable", func(t *testing.T) {
		k := newCoLocKey(t)
		e := validEntry(t, k)
		// Serve a DIFFERENT recipient than the entry binds.
		other := "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqqqqqqqq"
		p := only(t, coLocationChecks(ctx, serveCoLoc(t, k.sshLine, other, []papi.CoLocation{e})))
		if verdict(p) != "unverifiable" {
			t.Errorf("got %s, want unverifiable; %s", verdict(p), p.desc)
		}
	})

	t.Run("unknown level -> unverifiable", func(t *testing.T) {
		k := newCoLocKey(t)
		e := validEntry(t, k)
		e.Level = "platinum"
		p := only(t, coLocationChecks(ctx, serveCoLoc(t, k.sshLine, testCoLocRecipient, []papi.CoLocation{e})))
		if verdict(p) != "unverifiable" {
			t.Errorf("got %s, want unverifiable; %s", verdict(p), p.desc)
		}
	})

	t.Run("duplicate id -> second unverifiable", func(t *testing.T) {
		k := newCoLocKey(t)
		e := validEntry(t, k)
		pts := coLocationChecks(ctx, serveCoLoc(t, k.sshLine, testCoLocRecipient, []papi.CoLocation{e, e}))
		if len(pts) != 2 {
			t.Fatalf("got %d points, want 2", len(pts))
		}
		if verdict(pts[0]) != "verified" || verdict(pts[1]) != "unverifiable" {
			t.Errorf("got %s,%s want verified,unverifiable", verdict(pts[0]), verdict(pts[1]))
		}
	})
}
