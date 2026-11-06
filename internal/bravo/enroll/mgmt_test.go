package enroll

import (
	"context"
	"errors"
	"testing"

	"code.linenisgreat.com/papi/internal/0/piggymgmt"
)

// fakeSession plays piggy's side of sign_bytes: it asks for the PIN askTimes
// times through the signer's SecretFunc and records the answers.
type fakeSession struct {
	secret   piggymgmt.SecretFunc
	askTimes int
	answers  []string
	declines int
	closed   bool
	sig      []byte
	gotGUID  string
}

func (f *fakeSession) SetSecretFunc(fn piggymgmt.SecretFunc) { f.secret = fn }
func (f *fakeSession) Close() error                          { f.closed = true; return nil }

func (f *fakeSession) SignBytes(_ context.Context, slot, guid, format string, _ []byte) ([]byte, error) {
	f.gotGUID = guid
	if slot != "9a" || format != "raw" {
		return nil, errors.New("unexpected slot/format")
	}
	for range f.askTimes {
		s, err := f.secret(piggymgmt.SecretRequest{Kind: "current_pin", Prompt: "PIN"})
		if err != nil {
			f.declines++
			return nil, &piggymgmt.RPCError{Code: piggymgmt.CodeInteractionDeclined, Message: "declined"}
		}
		f.answers = append(f.answers, s)
	}
	return f.sig, nil
}

func startWith(f *fakeSession) func(context.Context) (SignBytesSession, error) {
	return func(context.Context) (SignBytesSession, error) { return f, nil }
}

func TestManageSignerAnswersThePINOnce(t *testing.T) {
	f := &fakeSession{askTimes: 1, sig: make([]byte, 64)}
	rs, err := ManageSignBytesSigner{PIN: "246810", Start: startWith(f)}.SignSlot9A(context.Background(), "G", []byte("m"))
	if err != nil {
		t.Fatalf("SignSlot9A: %v", err)
	}
	if len(rs) != 64 || f.gotGUID != "G" || !f.closed {
		t.Errorf("rs=%d guid=%q closed=%v", len(rs), f.gotGUID, f.closed)
	}
	if len(f.answers) != 1 || f.answers[0] != "246810" {
		t.Errorf("answers = %v", f.answers)
	}
}

// A second PIN request means the first was wrong: decline rather than spend
// another retry on the same PIN.
func TestManageSignerDeclinesASecondPINRequest(t *testing.T) {
	f := &fakeSession{askTimes: 2, sig: make([]byte, 64)}
	_, err := ManageSignBytesSigner{PIN: "246810", Start: startWith(f)}.SignSlot9A(context.Background(), "G", nil)
	if err == nil {
		t.Fatal("want an error after declining the second PIN request")
	}
	if len(f.answers) != 1 || f.declines != 1 {
		t.Errorf("answers=%v declines=%d, want one answer then one decline", f.answers, f.declines)
	}
}

func TestManageSignerRejectsAShortSignature(t *testing.T) {
	f := &fakeSession{askTimes: 1, sig: []byte("short")}
	if _, err := (ManageSignBytesSigner{PIN: "1", Start: startWith(f)}).SignSlot9A(context.Background(), "G", nil); err == nil {
		t.Fatal("a non-64-byte signature should error")
	}
}

func TestPINSignerPicksTheChannel(t *testing.T) {
	if _, ok := PINSigner("246810").(ManageSignBytesSigner); !ok {
		t.Error("a PIN should select the manage-protocol signer")
	}
	if _, ok := PINSigner("").(PiggySignBytesSigner); !ok {
		t.Error("no PIN should select piggy sign-bytes, which prompts itself")
	}
}
