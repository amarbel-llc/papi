package forgetoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeForge is a stand-in for the token-management API: it records what was posted
// and serves a fixed inventory, so the tests assert on the WIRE SHAPE papi sends
// rather than on our own structs.
type fakeForge struct {
	tokens     []Token
	lastCreate map[string]any
	lastAuth   string
	deleted    []string
	nextID     int64
	// mintStatus, when non-zero, replaces the 201 — used to reproduce the forge
	// refusing a credential kind.
	mintStatus int
}

func (f *fakeForge) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/sasha/tokens", func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodGet:
			writeJSON(t, w, http.StatusOK, f.tokens)
		case http.MethodPost:
			if f.mintStatus != 0 {
				writeJSON(t, w, f.mintStatus, map[string]string{"message": "auth method not allowed"})
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&f.lastCreate); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			f.nextID++
			writeJSON(t, w, http.StatusCreated, Token{
				ID:     f.nextID,
				Name:   f.lastCreate["name"].(string),
				Secret: "minted-secret",
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/users/sasha/tokens/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/sasha/tokens/")
		f.deleted = append(f.deleted, id)
		for _, tok := range f.tokens {
			if id == strconv.FormatInt(tok.ID, 10) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		writeJSON(t, w, http.StatusNotFound, map[string]string{"message": "token does not exist"})
	})
	mux.HandleFunc("/api/v1/repos/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		type owner struct {
			Login string `json:"login"`
		}
		type repo struct {
			Name  string `json:"name"`
			Owner owner  `json:"owner"`
		}
		var data []repo
		switch q {
		case "papi":
			// A substring hit that is NOT the repo asked for must be ignored.
			data = []repo{{Name: "papi", Owner: owner{"linenisgreat"}}, {Name: "papi-private", Owner: owner{"other"}}}
		case "twice":
			data = []repo{{Name: "twice", Owner: owner{"alice"}}, {Name: "twice", Owner: owner{"bob"}}}
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"data": data})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func newTestClient(t *testing.T, f *fakeForge) *Client {
	t.Helper()
	srv := f.server(t)
	c, err := NewClient(srv.URL, "sasha", BasicCredential{User: "sasha", Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The whole per-repo promise rides on `repositories` being PRESENT in the request:
// Forgejo reads its absence as ResourceAllRepos=true, i.e. a user-wide token.
func TestMintSendsResourceRepositories(t *testing.T) {
	f := &fakeForge{}
	c := newTestClient(t, f)
	tok, err := c.Mint(context.Background(), MintRequest{
		Session: "papi/mild-maple",
		Scopes:  []string{"write:repository"},
		Repos:   []RepoTarget{{Owner: "linenisgreat", Name: "papi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Secret != "minted-secret" {
		t.Fatalf("mint must return the one-time secret, got %q", tok.Secret)
	}
	// The package renders the name, so a caller cannot mint an orphan that
	// RevokeSession and Sweep would never find.
	if got := f.lastCreate["name"]; got != TokenName("papi/mild-maple", time.Time{}) {
		t.Fatalf("minted name %v, want the one TokenName renders", got)
	}
	repos, present := f.lastCreate["repositories"]
	if !present {
		t.Fatal("`repositories` absent from the create body: the forge would mint a USER-WIDE token")
	}
	list, ok := repos.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("repositories: got %#v, want one entry", repos)
	}
	entry := list[0].(map[string]any)
	if entry["owner"] != "linenisgreat" || entry["name"] != "papi" {
		t.Fatalf("resource row: got %#v", entry)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("sasha:hunter2"))
	if f.lastAuth != want {
		t.Fatalf("basic auth header: got %q, want %q", f.lastAuth, want)
	}
}

// Refusing an empty target set is what makes a user-wide token unreachable through
// this package, rather than something a caller can produce by passing no repos.
func TestMintRefusesAnEmptyRepoSet(t *testing.T) {
	f := &fakeForge{}
	c := newTestClient(t, f)
	_, err := c.Mint(context.Background(), MintRequest{
		Session: "papi/mild-maple",
		Scopes:  []string{"write:repository"},
	})
	if err == nil {
		t.Fatal("mint with no repositories must fail rather than mint a user-wide token")
	}
	if f.lastCreate != nil {
		t.Fatal("mint must not reach the forge when the target set is empty")
	}
}

func TestMintSurfacesTheAuthMethodRejection(t *testing.T) {
	f := &fakeForge{mintStatus: http.StatusUnauthorized}
	c := newTestClient(t, f)
	_, err := c.Mint(context.Background(), MintRequest{
		Session: "papi/mild-maple",
		Scopes:  []string{"write:repository"},
		Repos:   []RepoTarget{{Owner: "linenisgreat", Name: "papi"}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsAuthMethod(err) {
		t.Fatalf("a 401 must be recognisable as the credential-kind rejection, got %v", err)
	}
}

// A token credential can never mint or revoke, so the client says so instead of
// making a request whose 403 would misleadingly blame the token's scopes.
func TestTokenCredentialIsRefusedWithoutAskingTheForge(t *testing.T) {
	f := &fakeForge{tokens: []Token{{ID: 1, Name: TokenName("papi/x", time.Time{})}}}
	srv := f.server(t)
	c, err := NewClient(srv.URL, "sasha", TokenCredential{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	_, mintErr := c.Mint(context.Background(), MintRequest{
		Session: "papi/x",
		Scopes:  []string{"write:repository"},
		Repos:   []RepoTarget{{Owner: "linenisgreat", Name: "papi"}},
	})
	if !errors.Is(mintErr, ErrCredentialCannotMint) {
		t.Fatalf("mint error = %v, want ErrCredentialCannotMint", mintErr)
	}
	if !errors.Is(c.DeleteByID(context.Background(), 1), ErrCredentialCannotMint) {
		t.Fatal("revoke must be refused for the same reason")
	}
	if f.lastCreate != nil || len(f.deleted) != 0 {
		t.Fatal("neither call should have reached the forge")
	}
	// Listing is the one route a token credential genuinely drives.
	if _, err := c.List(context.Background()); err != nil {
		t.Fatalf("list must still work with a token credential: %v", err)
	}
}

// Revoking an already-gone token has to succeed, or spinclass's orphan sweep — which
// re-runs revoke for any credential it never saw revoked — would retry forever.
func TestDeleteTreatsAlreadyGoneAsSuccess(t *testing.T) {
	f := &fakeForge{}
	c := newTestClient(t, f)
	if err := c.DeleteByID(context.Background(), 4242); err != nil {
		t.Fatalf("deleting an absent token must succeed: %v", err)
	}
}

func TestRevokeSessionOnlyTouchesThatSession(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	f := &fakeForge{tokens: []Token{
		{ID: 1, Name: TokenName("papi/mild-maple", deadline)},
		{ID: 2, Name: TokenName("papi/bold-mulberry", deadline)},
		{ID: 3, Name: "forge/krone-api-token"}, // the operator's own, unparseable
	}}
	c := newTestClient(t, f)
	revoked, err := c.RevokeSession(context.Background(), "papi/mild-maple")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].ID != 1 {
		t.Fatalf("revoked %#v, want only token 1", revoked)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "1" {
		t.Fatalf("deleted %v, want exactly [1]", f.deleted)
	}
}

func TestRevokeSessionWithNothingToDoSucceeds(t *testing.T) {
	f := &fakeForge{}
	c := newTestClient(t, f)
	revoked, err := c.RevokeSession(context.Background(), "papi/gone")
	if err != nil {
		t.Fatalf("revoking a session with no tokens must succeed: %v", err)
	}
	if len(revoked) != 0 {
		t.Fatalf("revoked %#v, want none", revoked)
	}
}

func TestSweepRevokesOnlyExpiredPapiTokens(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeForge{tokens: []Token{
		{ID: 1, Name: TokenName("papi/expired", now.Add(-time.Hour))},
		{ID: 2, Name: TokenName("papi/live", now.Add(time.Hour))},
		{ID: 3, Name: TokenName("papi/no-deadline", time.Time{})},
		{ID: 4, Name: "a-hand-made-token"},
	}}
	c := newTestClient(t, f)
	revoked, err := c.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].ID != 1 {
		t.Fatalf("swept %#v, want only the expired token", revoked)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "1" {
		t.Fatalf("deleted %v, want exactly [1]", f.deleted)
	}
}

func TestResolveRepo(t *testing.T) {
	f := &fakeForge{}
	c := newTestClient(t, f)
	ctx := context.Background()

	t.Run("bare name resolves to its owner", func(t *testing.T) {
		got, err := c.ResolveRepo(ctx, RepoTarget{Name: "papi"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Owner != "linenisgreat" || got.Name != "papi" {
			t.Fatalf("got %s, want linenisgreat/papi", got)
		}
	})
	t.Run("an explicit owner is left alone", func(t *testing.T) {
		got, err := c.ResolveRepo(ctx, RepoTarget{Owner: "someone", Name: "papi"})
		if err != nil || got.Owner != "someone" {
			t.Fatalf("got %s, %v", got, err)
		}
	})
	t.Run("an ambiguous name is an error, not a guess", func(t *testing.T) {
		_, err := c.ResolveRepo(ctx, RepoTarget{Name: "twice"})
		if err == nil {
			t.Fatal("an ambiguous name must fail rather than pick a repository")
		}
		if !strings.Contains(err.Error(), "alice/twice") || !strings.Contains(err.Error(), "bob/twice") {
			t.Fatalf("the error should name the candidates, got %v", err)
		}
	})
	t.Run("an unknown name is an error", func(t *testing.T) {
		if _, err := c.ResolveRepo(ctx, RepoTarget{Name: "absent"}); err == nil {
			t.Fatal("expected an error for a repository the credential cannot see")
		}
	})
}

func TestParseRepo(t *testing.T) {
	cases := []struct {
		in        string
		want      RepoTarget
		wantError bool
	}{
		{in: "linenisgreat/papi", want: RepoTarget{Owner: "linenisgreat", Name: "papi"}},
		{in: "/linenisgreat/papi.git", want: RepoTarget{Owner: "linenisgreat", Name: "papi"}},
		// spinclass's SPINCLASS_FORGE_REPO is owner-less on vanity remotes.
		{in: "papi", want: RepoTarget{Name: "papi"}},
		{in: "papi.git", want: RepoTarget{Name: "papi"}},
		{in: "", wantError: true},
		{in: "a/b/c", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseRepo(tc.in)
			if tc.wantError {
				if err == nil {
					t.Fatalf("ParseRepo(%q) = %s, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ParseRepo(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSecretFromCommand(t *testing.T) {
	got, err := SecretFromCommand(context.Background(), "printf 'secret-value\\nignored\\n'")
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret-value" {
		t.Fatalf("got %q, want the first line only", got)
	}
	if _, err := SecretFromCommand(context.Background(), "true"); err == nil {
		t.Fatal("a command printing nothing must be an error, not an empty secret")
	}
	if _, err := SecretFromCommand(context.Background(), "exit 3"); err == nil {
		t.Fatal("a failing command must be an error")
	}
}
