package enroll

import (
	"context"
	"fmt"

	"code.linenisgreat.com/papi/internal/0/piggymgmt"
)

// ManageSignBytesSigner implements the slot-9A byte-signer through `piggy
// manage --jsonrpc` (piggy RFC 0007 sign_bytes), for when papi holds the PIN.
// The PIN reaches piggy as the answer to its secret.request, over the pipe to
// the child, so it never appears on a command line (`-P <pin>` is readable by
// every user through /proc/<pid>/cmdline).
//
// The PIN is offered once per signature. If piggy asks again (a wrong PIN), the
// signer declines rather than spend another of the card's retries.
type ManageSignBytesSigner struct {
	PIN string
	// Start opens the manage session; nil means piggymgmt.Start with "piggy".
	Start func(ctx context.Context) (SignBytesSession, error)
}

// SignBytesSession is the slice of a piggy manage session the signer uses.
type SignBytesSession interface {
	SignBytes(ctx context.Context, slot, guid, format string, msg []byte) ([]byte, error)
	SetSecretFunc(piggymgmt.SecretFunc)
	Close() error
}

type manageSession struct{ *piggymgmt.Session }

func (s manageSession) SetSecretFunc(f piggymgmt.SecretFunc) { s.OnSecret = f }

// SignSlot9A signs msg with the slot-9A key of the card identified by guid and
// returns the raw 64-byte r‖s.
func (m ManageSignBytesSigner) SignSlot9A(ctx context.Context, guid string, msg []byte) ([]byte, error) {
	start := m.Start
	if start == nil {
		start = func(ctx context.Context) (SignBytesSession, error) {
			s, err := piggymgmt.Start(ctx, "piggy")
			if err != nil {
				return nil, err
			}
			return manageSession{s}, nil
		}
	}
	s, err := start(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	offered := false
	s.SetSecretFunc(func(r piggymgmt.SecretRequest) (string, error) {
		if r.Kind != "current_pin" || offered {
			return "", piggymgmt.ErrDeclined
		}
		offered = true
		return m.PIN, nil
	})
	rs, err := s.SignBytes(ctx, "9a", guid, "raw", msg)
	if err != nil {
		return nil, fmt.Errorf("piggy manage sign_bytes --slot 9a (guid %q): %w", guid, err)
	}
	if len(rs) != 64 {
		return nil, fmt.Errorf("piggy manage sign_bytes --slot 9a (guid %q): got %d bytes, want 64 raw r‖s", guid, len(rs))
	}
	return rs, nil
}

// PINSigner returns the slot-9A signer for a PIN the operator gave papi: the
// manage-protocol signer when there is one, so the PIN never goes on a command
// line; otherwise `piggy sign-bytes`, which asks for the PIN itself.
func PINSigner(pin string) Signer {
	if pin != "" {
		return ManageSignBytesSigner{PIN: pin}
	}
	return PiggySignBytesSigner{}
}
