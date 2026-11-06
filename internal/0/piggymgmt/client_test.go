package piggymgmt

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// fakePiggy is an in-process stand-in for `piggy manage --jsonrpc`: it reads the
// client's requests and runs script against them. No card, no process.
type fakePiggy struct {
	t   *testing.T
	in  *bufio.Reader // client → fake
	out io.Writer     // fake → client
}

func (f *fakePiggy) read() map[string]any {
	f.t.Helper()
	line, err := f.in.ReadBytes('\n')
	if err != nil {
		f.t.Errorf("fake piggy: read: %v", err)
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		f.t.Errorf("fake piggy: bad line %q: %v", line, err)
	}
	return m
}

func (f *fakePiggy) send(v any) {
	f.t.Helper()
	b, _ := json.Marshal(v)
	if _, err := f.out.Write(append(b, '\n')); err != nil {
		f.t.Errorf("fake piggy: write: %v", err)
	}
}

// newPair returns a Client connected to a fake piggy running script in a
// goroutine, and a function that waits for the script to finish.
func newPair(t *testing.T, script func(f *fakePiggy)) (*Client, func()) {
	t.Helper()
	toFake, fromClient := io.Pipe()
	toClient, fromFake := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer fromFake.Close()
		script(&fakePiggy{t: t, in: bufio.NewReader(toFake), out: fromFake})
	}()
	c := NewClient(toClient, fromClient)
	return c, func() { _ = fromClient.Close(); <-done }
}

func handshake(f *fakePiggy) {
	req := f.read()
	if req["method"] != "initialize" {
		f.t.Errorf("first request = %v, want initialize", req["method"])
	}
	f.send(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]string{"protocol": "piggy-mgmt/1"}})
}

// The PIN crosses as a secret.request answer, and the signature comes back.
func TestSignBytesAnswersPINRequest(t *testing.T) {
	sig := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	c, wait := newPair(t, func(f *fakePiggy) {
		handshake(f)
		req := f.read()
		params, _ := req["params"].(map[string]any)
		if req["method"] != "sign_bytes" || params["slot"] != "9a" || params["guid"] != "G" || params["format"] != "raw" {
			t.Errorf("sign_bytes request = %v", req)
		}
		if params["message"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
			t.Errorf("message = %v", params["message"])
		}
		f.send(map[string]any{"jsonrpc": "2.0", "method": "progress", "params": map[string]string{"step": "sign", "message": "signing"}})
		f.send(map[string]any{
			"jsonrpc": "2.0", "id": 7, "method": "secret.request",
			"params": map[string]any{"kind": "current_pin", "prompt": "Enter PIN", "slot": "9a", "card": map[string]any{"guid": "G"}},
		})
		ans := f.read()
		if res, _ := ans["result"].(map[string]any); res["secret"] != "246810" || ans["id"] != float64(7) {
			t.Errorf("PIN answer = %v", ans)
		}
		f.send(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)}})
	})
	defer wait()
	var seen []string
	c.OnSecret = func(r SecretRequest) (string, error) {
		seen = append(seen, r.Kind)
		return "246810", nil
	}
	var steps []string
	c.OnProgress = func(p Progress) { steps = append(steps, p.Step) }

	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	got, err := c.SignBytes(ctx, "9a", "G", "raw", []byte("hello"))
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if string(got) != string(sig) {
		t.Errorf("signature = %q", got)
	}
	if len(seen) != 1 || seen[0] != "current_pin" {
		t.Errorf("secret kinds seen = %v", seen)
	}
	if len(steps) != 1 || steps[0] != "sign" {
		t.Errorf("progress steps = %v", steps)
	}
}

// With no OnSecret the client declines with -32010, and the command's error
// is returned.
func TestSignBytesDeclinesWithoutSecretFunc(t *testing.T) {
	c, wait := newPair(t, func(f *fakePiggy) {
		handshake(f)
		req := f.read()
		f.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "secret.request", "params": map[string]any{"kind": "current_pin", "prompt": "PIN"}})
		ans := f.read()
		if e, _ := ans["error"].(map[string]any); e["code"] != float64(CodeInteractionDeclined) {
			t.Errorf("want a -32010 decline, got %v", ans)
		}
		f.send(map[string]any{"jsonrpc": "2.0", "id": req["id"], "error": map[string]any{"code": CodeInteractionDeclined, "message": "interaction declined"}})
	})
	defer wait()
	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := c.SignBytes(ctx, "9a", "", "raw", []byte("x"))
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeInteractionDeclined {
		t.Fatalf("err = %v, want an RPCError -32010", err)
	}
}

// A SecretFunc error declines the request.
func TestSecretFuncErrorDeclines(t *testing.T) {
	c, wait := newPair(t, func(f *fakePiggy) {
		handshake(f)
		req := f.read()
		f.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "secret.request", "params": map[string]any{"kind": "new_pin", "prompt": "New PIN"}})
		ans := f.read()
		if _, ok := ans["error"]; !ok {
			t.Errorf("want an error answer, got %v", ans)
		}
		f.send(map[string]any{"jsonrpc": "2.0", "id": req["id"], "error": map[string]any{"code": CodeInteractionDeclined, "message": "declined"}})
	})
	defer wait()
	c.OnSecret = func(SecretRequest) (string, error) { return "", ErrDeclined }
	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignBytes(ctx, "9a", "", "raw", []byte("x")); err == nil {
		t.Fatal("want an error after declining")
	}
}

func TestInitializeRejectsUnknownMajor(t *testing.T) {
	c, wait := newPair(t, func(f *fakePiggy) {
		req := f.read()
		f.send(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]string{"protocol": "piggy-mgmt/2"}})
	})
	defer wait()
	if err := c.Initialize(context.Background()); err == nil {
		t.Fatal("want an error for piggy-mgmt/2")
	}
}

// A connection that closes before the result is an error, not a hang.
func TestConnectionClosedBeforeResult(t *testing.T) {
	c, wait := newPair(t, func(f *fakePiggy) {
		handshake(f)
		_ = f.read() // the sign_bytes request; then the fake exits and closes
	})
	defer wait()
	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignBytes(ctx, "9a", "", "raw", []byte("x")); err == nil {
		t.Fatal("want an error when piggy closes the connection")
	}
}
