package forgetoken

import (
	"context"
	"testing"
	"time"
)

// RevokeAll is the end-of-window cleanup for an account that exists only for
// grant-driven sessions: it removes EVERY token, papi-named or not, because a holder of
// the grant key chooses its own token names and could have minted one papi cannot
// parse.
func TestRevokeAllRemovesEveryTokenIncludingForeignNames(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	f := &fakeForge{tokens: []Token{
		{ID: 1, Name: TokenName("papi/a", deadline)},
		{ID: 2, Name: TokenName("papi/b", time.Time{})}, // never swept
		{ID: 3, Name: "attacker-chosen-name"},           // papi cannot parse it
	}}
	c := newTestClient(t, f)
	revoked, err := c.RevokeAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 3 {
		t.Fatalf("revoked %d, want all 3: %#v", len(revoked), revoked)
	}
	if len(f.deleted) != 3 {
		t.Fatalf("deleted %v", f.deleted)
	}
}

func TestRevokeAllOnAnEmptyAccountSucceeds(t *testing.T) {
	c := newTestClient(t, &fakeForge{})
	revoked, err := c.RevokeAll(context.Background())
	if err != nil || len(revoked) != 0 {
		t.Fatalf("revoked %v, err %v", revoked, err)
	}
}

func newTokenOnlyClient(t *testing.T, f *fakeForge) *Client {
	t.Helper()
	c, err := NewClient(f.server(t).URL, "sasha", TokenCredential{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRevokeAllNeedsAMintCapableCredential(t *testing.T) {
	f := &fakeForge{tokens: []Token{{ID: 1, Name: "x"}}}
	c := newTokenOnlyClient(t, f)
	if _, err := c.RevokeAll(context.Background()); err == nil {
		t.Fatal("a token credential cannot delete; RevokeAll must say so")
	}
	if len(f.deleted) != 0 {
		t.Error("a delete reached the forge")
	}
}
