package forgetoken

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePoolRows(t *testing.T) {
	rows, err := ParsePoolRows(strings.NewReader(
		"# trip pool\n\nlinenisgreat/papi pool/papi/01\n  spinclass   pool/spinclass/01  \n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []PoolRow{
		{Repo: RepoTarget{Owner: "linenisgreat", Name: "papi"}, Session: "pool/papi/01"},
		{Repo: RepoTarget{Name: "spinclass"}, Session: "pool/spinclass/01"},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d: got %+v, want %+v", i, rows[i], want[i])
		}
	}

	for name, input := range map[string]string{
		"one field":   "papi\n",
		"three":       "papi pool/1 12h\n",
		"bad repo":    "a/b/c pool/1\n",
		"no rows":     "# nothing\n",
		"dup session": "papi pool/1\nspinclass pool/1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePoolRows(strings.NewReader(input)); err == nil {
				t.Fatalf("%q must be refused", input)
			}
		})
	}
}

// poolForge extends fakeForge so minted tokens join the inventory (the collision
// check reads it) and each secret is distinct (so a file cannot hold the wrong one).
type poolForge struct {
	fakeForge
	failMintAt int // 1-based mint number that fails with 500; 0 = never
	mints      int
	onMint     func(n int) // runs as mint n arrives, before the token is created
	cookies    []string
}

func (f *poolForge) handler(t *testing.T) http.Handler {
	t.Helper()
	inner := f.fakeForge.server(t).Config.Handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/users/sasha/tokens" {
			if c, err := r.Cookie(DefaultSessionCookie); err == nil {
				f.cookies = append(f.cookies, c.Value)
			}
			f.mints++
			if f.onMint != nil {
				f.onMint(f.mints)
			}
			if f.mints == f.failMintAt {
				writeJSON(t, w, http.StatusInternalServerError, map[string]string{"message": "boom"})
				return
			}
			var body createTokenBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			f.nextID++
			tok := Token{ID: f.nextID, Name: body.Name, Secret: secretFor(f.nextID)}
			f.tokens = append(f.tokens, Token{ID: tok.ID, Name: tok.Name})
			writeJSON(t, w, http.StatusCreated, tok)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

func secretFor(id int64) string { return "secret-" + string(rune('a'+id)) }

func newPoolClient(t *testing.T, f *poolForge, cred Credential) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "sasha", cred)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var basic = BasicCredential{User: "sasha", Password: "hunter2"}

func twoRows() []PoolRow {
	return []PoolRow{
		{Repo: RepoTarget{Name: "papi"}, Session: "pool/papi/01"},
		{Repo: RepoTarget{Owner: "linenisgreat", Name: "spinclass"}, Session: "pool/spinclass/01"},
	}
}

func TestMintPoolWritesOneFilePerTokenAndASecretFreeManifest(t *testing.T) {
	f := &poolForge{}
	c := newPoolClient(t, f, basic)
	dir := filepath.Join(t.TempDir(), "pool")
	deadline := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)

	m, err := c.MintPool(context.Background(), dir, twoRows(), deadline, []string{"write:repository"})
	if err != nil {
		t.Fatal(err)
	}

	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("pool dir mode: %v / %v, want 0700", fi, err)
	}
	if len(m.Tokens) != 2 {
		t.Fatalf("manifest has %d tokens, want 2", len(m.Tokens))
	}
	for i, e := range m.Tokens {
		if e.Session != twoRows()[i].Session {
			t.Errorf("entry %d session %q", i, e.Session)
		}
		path := filepath.Join(dir, e.File)
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode: %v / %v, want 0600", e.File, fi, err)
		}
		raw, _ := os.ReadFile(path)
		if got := strings.TrimSuffix(string(raw), "\n"); got != secretFor(e.ID) {
			t.Errorf("%s holds %q, want the secret minted as id %d", e.File, got, e.ID)
		}
		// Each token is individually addressable: its name decodes to its own session.
		if s, d, ok := ParseTokenName(TokenName(e.Session, deadline)); !ok || s != e.Session || !d.Equal(deadline) {
			t.Errorf("entry %d does not round-trip through the name", i)
		}
	}
	if m.Tokens[0].Repo != "linenisgreat/papi" {
		t.Errorf("bare repo should resolve its owner, got %q", m.Tokens[0].Repo)
	}

	manifest, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, ManifestName)); fi.Mode().Perm() != 0o600 {
		t.Errorf("manifest mode %v, want 0600", fi.Mode().Perm())
	}
	if strings.Contains(string(manifest), "secret-") {
		t.Fatalf("manifest carries a secret:\n%s", manifest)
	}
	var onDisk PoolManifest
	if err := json.Unmarshal(manifest, &onDisk); err != nil || len(onDisk.Tokens) != 2 {
		t.Fatalf("manifest on disk: %v / %+v", err, onDisk)
	}
}

// Everything that can be checked without minting is checked before the first mint,
// so a bad pool fails with zero tokens created rather than a half-made pool.
func TestMintPoolRefusesBeforeMinting(t *testing.T) {
	cases := map[string]func(t *testing.T, f *poolForge) (string, []PoolRow){
		"existing out dir": func(t *testing.T, _ *poolForge) (string, []PoolRow) {
			return t.TempDir(), twoRows()
		},
		"session already has a token": func(t *testing.T, f *poolForge) (string, []PoolRow) {
			f.tokens = []Token{{ID: 9, Name: TokenName("pool/spinclass/01", time.Time{})}}
			return filepath.Join(t.TempDir(), "pool"), twoRows()
		},
		"unresolvable repo": func(t *testing.T, _ *poolForge) (string, []PoolRow) {
			rows := append(twoRows(), PoolRow{Repo: RepoTarget{Name: "twice"}, Session: "pool/twice/01"})
			return filepath.Join(t.TempDir(), "pool"), rows
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := &poolForge{}
			dir, rows := setup(t, f)
			c := newPoolClient(t, f, basic)
			if _, err := c.MintPool(context.Background(), dir, rows, time.Time{}, []string{"write:repository"}); err == nil {
				t.Fatal("expected a refusal")
			}
			if f.mints != 0 {
				t.Fatalf("%d token(s) minted before the refusal", f.mints)
			}
		})
	}
}

// A mint failing mid-batch keeps what was already minted on disk and in the
// manifest — those tokens exist on the forge and must stay findable — and says which
// sessions were not minted.
func TestMintPoolPartialFailureKeepsAnAccurateManifest(t *testing.T) {
	f := &poolForge{failMintAt: 2}
	c := newPoolClient(t, f, basic)
	dir := filepath.Join(t.TempDir(), "pool")

	m, err := c.MintPool(context.Background(), dir, twoRows(), time.Time{}, []string{"write:repository"})
	if err == nil {
		t.Fatal("expected the second mint's failure")
	}
	if !strings.Contains(err.Error(), "pool/spinclass/01") {
		t.Errorf("error should name the unminted session, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-") {
		t.Fatalf("error carries a secret: %v", err)
	}
	if len(m.Tokens) != 1 || m.Tokens[0].Session != "pool/papi/01" {
		t.Fatalf("returned manifest %+v, want only the first session", m.Tokens)
	}
	var onDisk PoolManifest
	raw, _ := os.ReadFile(filepath.Join(dir, ManifestName))
	if err := json.Unmarshal(raw, &onDisk); err != nil || len(onDisk.Tokens) != 1 {
		t.Fatalf("manifest on disk after partial failure: %v / %s", err, raw)
	}
}

// A token whose secret cannot be saved is unrecoverable, so a write failure must
// revoke it: no live credential may be left that nobody holds.
func TestMintPoolWriteFailureRevokesTheUnsavedToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pool")
	f := &poolForge{}
	// Occupy the second slot's file name, so its exclusive create fails.
	f.onMint = func(n int) {
		if n == 2 {
			blocker := filepath.Join(dir, escapeSession("pool/spinclass/01")+".token")
			if err := os.WriteFile(blocker, nil, 0o600); err != nil {
				t.Errorf("plant blocker: %v", err)
			}
		}
	}
	c := newPoolClient(t, f, basic)

	m, err := c.MintPool(context.Background(), dir, twoRows(), time.Time{}, []string{"write:repository"})
	if err == nil {
		t.Fatal("expected the second token's write failure")
	}
	if !strings.Contains(err.Error(), "pool/spinclass/01") {
		t.Errorf("error should name the slot that failed to save, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-") {
		t.Fatalf("error carries a secret: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "2" {
		t.Fatalf("deleted %v, want exactly the unsaved token [2]", f.deleted)
	}
	if len(m.Tokens) != 1 || m.Tokens[0].Session != "pool/papi/01" {
		t.Fatalf("manifest %+v, want only the saved first token", m.Tokens)
	}
}

// The point of the batch: ONE card interaction, then every mint rides the same
// verifier session cookie. The signer is a closure, so no card is involved.
func TestCardLoginOnceMintsTheWholePool(t *testing.T) {
	v := &fakeVerifier{loginLocation: oracleRedirect("n", "s")}
	vsrv := v.server(t)
	signs := 0
	cred, err := CardLogin(context.Background(), vsrv.URL, "forge.example", "",
		func(context.Context, string, string) (string, error) { signs++; return "sig", nil })
	if err != nil {
		t.Fatal(err)
	}

	f := &poolForge{}
	c := newPoolClient(t, f, cred)
	rows := append(twoRows(), PoolRow{Repo: RepoTarget{Name: "papi"}, Session: "pool/papi/02"})
	if _, err := c.MintPool(context.Background(), filepath.Join(t.TempDir(), "pool"), rows,
		time.Time{}, []string{"write:repository"}); err != nil {
		t.Fatal(err)
	}
	if signs != 1 {
		t.Fatalf("card signed %d times, want exactly 1 for the whole pool", signs)
	}
	if len(f.cookies) != 3 {
		t.Fatalf("%d mints carried the session cookie, want 3", len(f.cookies))
	}
	for _, c := range f.cookies {
		if c != "session-value" {
			t.Errorf("mint carried cookie %q", c)
		}
	}
}
