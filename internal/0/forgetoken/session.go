package forgetoken

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Managed is a papi-minted token recovered from the forge, with the session and
// deadline decoded back out of its name. Tokens papi did not mint never become a
// Managed, which is what confines RevokeSession and Sweep to papi's own tokens.
type Managed struct {
	Token
	Session  string
	Deadline time.Time // zero when the token was minted with no deadline
}

// Expired reports whether the token's deadline has passed. A token with no
// deadline never expires and is only ever removed by an explicit revoke.
func (m Managed) Expired(now time.Time) bool {
	return !m.Deadline.IsZero() && now.After(m.Deadline)
}

// Managed lists the account's papi-minted tokens, decoding each name into its
// session and deadline. Hand-made tokens, and any name papi cannot parse, are
// skipped.
func (c *Client) Managed(ctx context.Context) ([]Managed, error) {
	tokens, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Managed
	for _, t := range tokens {
		session, deadline, ok := ParseTokenName(t.Name)
		if !ok {
			continue
		}
		out = append(out, Managed{Token: t, Session: session, Deadline: deadline})
	}
	return out, nil
}

// RevokeSession deletes every papi-minted token belonging to session and returns
// the ones it deleted. Revoking a session with no tokens is success with an empty
// result, not an error: spinclass retries a failed revoke from its next orphan
// sweep, so a revoke that failed on "already gone" would loop forever.
//
// It matches on the session decoded from each token's name rather than on the name
// string, so a session key that escapes to the same characters as another still
// cannot be revoked by mistake.
func (c *Client) RevokeSession(ctx context.Context, session string) ([]Managed, error) {
	managed, err := c.Managed(ctx)
	if err != nil {
		return nil, err
	}
	var revoked []Managed
	for _, m := range managed {
		if m.Session != session {
			continue
		}
		if err := c.DeleteByID(ctx, m.ID); err != nil {
			return revoked, fmt.Errorf("revoke token %q (id %d): %w", m.Name, m.ID, err)
		}
		revoked = append(revoked, m)
	}
	return revoked, nil
}

// Sweep deletes every papi-minted token whose deadline has passed, and returns
// them. This is the issuer-side backstop for sessions that crashed without
// revoking: Forgejo has no native token expiry (forgejo#8837), so the deadline
// lives in the token's name and enforcing it is papi's job.
//
// It keeps going after a failed delete so one stuck token cannot strand the rest,
// returning what it managed to revoke alongside the error.
func (c *Client) Sweep(ctx context.Context, now time.Time) ([]Managed, error) {
	managed, err := c.Managed(ctx)
	if err != nil {
		return nil, err
	}
	var (
		revoked []Managed
		failed  []error
	)
	for _, m := range managed {
		if !m.Expired(now) {
			continue
		}
		if err := c.DeleteByID(ctx, m.ID); err != nil {
			failed = append(failed, fmt.Errorf("revoke expired token %q (id %d): %w", m.Name, m.ID, err))
			continue
		}
		revoked = append(revoked, m)
	}
	if len(failed) > 0 {
		// errors.Join rather than flattening to a string: it keeps each *APIError
		// reachable through errors.As, so a caller can still ask whether a sweep
		// failure was the credential-kind rejection and say something useful.
		return revoked, fmt.Errorf("%d expired token(s) could not be revoked: %w",
			len(failed), errors.Join(failed...))
	}
	return revoked, nil
}
