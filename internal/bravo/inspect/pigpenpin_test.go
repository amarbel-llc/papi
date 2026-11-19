//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"code.linenisgreat.com/hyphence/go/hyphence"
	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/alfa/papi"
)

func TestParsePigpenLocator(t *testing.T) {
	a, b := newPigpenSigner(t), newPigpenSigner(t)

	t.Run("bare locator has no pins", func(t *testing.T) {
		origin, pins, err := ParsePigpenLocator("api.example.com")
		if err != nil || origin != "api.example.com" || len(pins) != 0 {
			t.Fatalf("got %q %v %v", origin, pins, err)
		}
	})

	t.Run("signer set", func(t *testing.T) {
		origin, pins, err := ParsePigpenLocator("api.example.com#signer=" + a.keyID + "," + b.keyID)
		if err != nil || origin != "api.example.com" || len(pins) != 2 {
			t.Fatalf("got %q %v %v", origin, pins, err)
		}
	})

	t.Run("url form keeps its scheme", func(t *testing.T) {
		origin, pins, err := ParsePigpenLocator("https://api.example.com#signer=" + a.keyID)
		if err != nil || origin != "https://api.example.com" || len(pins) != 1 {
			t.Fatalf("got %q %v %v", origin, pins, err)
		}
	})

	// Every malformed pin must be an error at parse time (before any fetch),
	// never a silent fall back to unpinned.
	for name, loc := range map[string]string{
		"empty fragment":     "api.example.com#",
		"unknown key":        "api.example.com#pin=" + a.keyID,
		"empty list":         "api.example.com#signer=",
		"empty element":      "api.example.com#signer=" + a.keyID + ",",
		"not a markl id":     "api.example.com#signer=nonsense",
		"wrong purpose":      "api.example.com#signer=" + mustBuildSelfSig(t),
		"second fragment":    "api.example.com#signer=" + a.keyID + "#signer=" + b.keyID,
		"extra fragment key": "api.example.com#signer=" + a.keyID + "&x=1",
	} {
		t.Run("malformed: "+name, func(t *testing.T) {
			if _, _, err := ParsePigpenLocator(loc); err == nil {
				t.Fatalf("ParsePigpenLocator(%q) must fail", loc)
			}
		})
	}
}

func mustBuildSelfSig(t *testing.T) string {
	t.Helper()
	id, err := markl.Build(markl.PurposePigpenSelfSig, markl.FormatEcdsaP256Sig, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// buildTwoKeyPigpenDoc publishes both signers' keys (first, second in that
// order) and self-signs with signWith.
func buildTwoKeyPigpenDoc(t *testing.T, first, second, signWith pigpenSigner) []byte {
	t.Helper()
	lines := []hyphence.MetadataLine{
		{Prefix: '-', Value: first.keyID},
		{Prefix: '-', Value: second.keyID},
		{Prefix: '!', Value: "pigpen-v1"},
	}
	input, err := pigpenStripSelfBytes(lines)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, signWith.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sigID, err := markl.Build(markl.PurposePigpenSelfSig, markl.FormatEcdsaP256Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	return renderPigpenDoc(t, []hyphence.MetadataLine{lines[0], lines[1], {Prefix: '-', Value: sigID}, lines[2]})
}

func resolvePinned(t *testing.T, doc []byte, authIDs []string, pins ...pigpenSigner) ([]byte, error) {
	t.Helper()
	srv := newPigpenFixtureServer(t, doc, false, authIDs)
	c, err := papi.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var parsed [][]byte
	for _, p := range pins {
		id, perr := markl.Parse(p.keyID)
		if perr != nil {
			t.Fatal(perr)
		}
		parsed = append(parsed, id.Payload)
	}
	return ResolvePigpenPinned(context.Background(), c, parsed)
}

func TestResolvePigpenPinned(t *testing.T) {
	first, second, stranger := newPigpenSigner(t), newPigpenSigner(t), newPigpenSigner(t)
	published := []string{first.keyID, second.keyID}

	t.Run("signed by the second key, pinned to the second only: accepted", func(t *testing.T) {
		// Today's resolver would try only the FIRST key line and reject this.
		doc := buildTwoKeyPigpenDoc(t, first, second, second)
		got, err := resolvePinned(t, doc, published, second)
		if err != nil || string(got) != string(doc) {
			t.Fatalf("pinned second key must verify and pass bytes through: %v", err)
		}
	})

	t.Run("pin set of both: either signer accepted", func(t *testing.T) {
		for _, signer := range []pigpenSigner{first, second} {
			doc := buildTwoKeyPigpenDoc(t, first, second, signer)
			if _, err := resolvePinned(t, doc, published, first, second); err != nil {
				t.Fatalf("pin set of both keys must accept a document signed by either: %v", err)
			}
		}
	})

	t.Run("signed by an unpinned key: refused naming the key seen", func(t *testing.T) {
		doc := buildTwoKeyPigpenDoc(t, first, second, second)
		_, err := resolvePinned(t, doc, published, first)
		var np *errPigpenSignerNotPinned
		if !errors.As(err, &np) {
			t.Fatalf("want errPigpenSignerNotPinned, got %v", err)
		}
		if !strings.Contains(err.Error(), "signer not pinned") {
			t.Errorf("message must say %q, got %q", "signer not pinned", err)
		}
		if !strings.Contains(err.Error(), second.keyID) {
			t.Errorf("message must name the key seen (%s), got %q", second.keyID, err)
		}
	})

	t.Run("origin swap: its own key, its own piggy-ids, valid signature: refused", func(t *testing.T) {
		// The circularity the pin closes: a hostile origin serves a fully
		// self-consistent document under its own key.
		doc := buildTwoKeyPigpenDoc(t, stranger, stranger, stranger)
		_, err := resolvePinned(t, doc, []string{stranger.keyID}, first, second)
		var np *errPigpenSignerNotPinned
		if !errors.As(err, &np) {
			t.Fatalf("a self-consistent foreign origin must be refused as not pinned, got %v", err)
		}
	})

	t.Run("pinned key present but its signature is invalid: refused", func(t *testing.T) {
		doc := buildTwoKeyPigpenDoc(t, first, second, stranger) // signed by a key not in the doc
		_, err := resolvePinned(t, doc, published, first, second)
		if !errors.Is(err, errPigpenSigInvalid) {
			t.Fatalf("want signature invalid, got %v", err)
		}
	})

	t.Run("pinned key not published on piggy-ids: refused", func(t *testing.T) {
		doc := buildTwoKeyPigpenDoc(t, first, second, second)
		_, err := resolvePinned(t, doc, []string{first.keyID}, second)
		if !errors.Is(err, errPigpenKeyNotPublished) {
			t.Fatalf("pin is a second condition, not the trust root; want not published, got %v", err)
		}
	})

	t.Run("pinned and unsigned: refused", func(t *testing.T) {
		doc := buildPigpenDoc(t, first, false, false)
		_, err := resolvePinned(t, doc, published, first)
		if !errors.Is(err, errPigpenUnsigned) {
			t.Fatalf("want unsigned, got %v", err)
		}
	})

	t.Run("no pins: first-key behaviour unchanged", func(t *testing.T) {
		doc := buildTwoKeyPigpenDoc(t, first, second, second)
		if _, err := resolvePinned(t, doc, published); err == nil {
			t.Fatal("without pins only the first key line is tried, so a document signed by the second must still fail")
		}
		doc = buildTwoKeyPigpenDoc(t, first, second, first)
		if _, err := resolvePinned(t, doc, published); err != nil {
			t.Fatalf("unpinned, first key signs: %v", err)
		}
	})
}
