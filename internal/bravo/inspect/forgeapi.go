package inspect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// ErrNoForgeAPIBase reports that the domain's forge model does not say where the
// forge's API lives — either no entry declares §1.1's api_base_url (Amendment 25),
// or several do and none was named. It is a distinct error because the fix is
// specific and worth stating: publish the member, or pass the host explicitly.
var ErrNoForgeAPIBase = errors.New("no forge entry declares an API base")

// ResolveForgeAPIBase reads a domain's forge model and returns the base URL of the
// forge's management API — what a consumer needs in order to CALL the forge, as
// opposed to reading this document's projection of it.
//
// It exists because a split deployment publishes the plane you clone from and the
// plane you call on different hosts, and only the first is discoverable: base_url
// names a vanity or read plane that may serve git alone. Without this, every
// consumer hardcodes the API host out of band.
//
// forgeID selects one entry by id. When empty, the entry that DECLARES an
// api_base_url is chosen, and it is an error for several to do so — picking one by
// kind or by document order would silently aim mint and revoke calls at the wrong
// forge.
//
// The member may be published only on the §5-gated projection when the API plane's
// hostname should not be advertised anonymously (§1.1), so an anonymous miss is not
// conclusive: with §5 credentials in opts, the lookup is retried authenticated. The
// anonymous attempt comes first so the common case costs no card operation.
func ResolveForgeAPIBase(ctx context.Context, target, forgeID string, opts Options) (string, error) {
	c, err := papi.NewClient(target)
	if err != nil {
		return "", err
	}

	anon, err := fetchForgeEntries(ctx, c, "")
	if err != nil {
		return "", err
	}
	base, err := selectForgeAPIBase(anon, forgeID)
	if err == nil || !errors.Is(err, ErrNoForgeAPIBase) || !opts.authed() {
		return base, err
	}

	// Anonymous view declares nothing; the member may be §5-gated.
	sess, herr := Handshake(ctx, c, opts)
	if herr != nil {
		return "", fmt.Errorf("%w; the §5 retry also failed: %v", err, herr)
	}
	authed, ferr := fetchForgeEntries(ctx, c, sess.ID)
	if ferr != nil {
		return "", fmt.Errorf("%w; the §5 retry also failed: %v", err, ferr)
	}
	return selectForgeAPIBase(authed, forgeID)
}

func fetchForgeEntries(ctx context.Context, c *papi.Client, session string) ([]forgeEntry, error) {
	var (
		resp *papi.Response
		err  error
	)
	if session == "" {
		resp, err = c.Fetch(ctx, "/papi/forges")
	} else {
		resp, err = c.FetchAuthed(ctx, "/papi/forges", session)
	}
	if err != nil {
		return nil, fmt.Errorf("GET /papi/forges: %w", err)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("GET /papi/forges: HTTP %d", resp.Status)
	}
	return decodeForgeEntries(resp.Body)
}

// selectForgeAPIBase applies the selection rules to one projection's entries.
func selectForgeAPIBase(entries []forgeEntry, forgeID string) (string, error) {
	if forgeID != "" {
		for _, f := range entries {
			if f.ID != forgeID {
				continue
			}
			if f.APIBaseURL != "" {
				return f.APIBaseURL, nil
			}
			// §1.1: absent means the API, if any, is served at base_url. The
			// caller named this forge, so honour that rather than erroring.
			if f.BaseURL != "" {
				return f.BaseURL, nil
			}
			return "", fmt.Errorf("forge %q declares neither api_base_url nor base_url", forgeID)
		}
		return "", fmt.Errorf("no forge entry with id %q (have: %s)", forgeID, forgeIDs(entries))
	}

	var declared []forgeEntry
	for _, f := range entries {
		if f.APIBaseURL != "" {
			declared = append(declared, f)
		}
	}
	switch len(declared) {
	case 1:
		return declared[0].APIBaseURL, nil
	case 0:
		return "", fmt.Errorf("%w (forges: %s)", ErrNoForgeAPIBase, forgeIDs(entries))
	default:
		return "", fmt.Errorf("several forge entries declare an API base (%s); name one",
			forgeIDs(declared))
	}
}

func forgeIDs(entries []forgeEntry) string {
	if len(entries) == 0 {
		return "none"
	}
	ids := make([]string, len(entries))
	for i, f := range entries {
		ids[i] = f.ID
	}
	return strings.Join(ids, ", ")
}
