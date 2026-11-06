// Package piggymgmt is a client for piggy's management command protocol
// (piggy RFC 0007, `piggy manage --jsonrpc`): newline-framed JSON-RPC 2.0 over
// the child's stdio. While a command runs, piggy sends the RFC 0006 interaction
// requests (secret.request for a PIN, confirm.request, progress) back over the
// same connection, and the client answers them before it gets the command's
// result.
//
// papi uses it so a PIN it holds reaches piggy as a secret.request answer on a
// pipe, never as a command-line argument (`-P <pin>` is readable by every user
// through /proc/<pid>/cmdline).
package piggymgmt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Protocol is the piggy-mgmt version this client speaks (RFC 0007 §4).
const Protocol = "piggy-mgmt/1"

// JSON-RPC error codes used by the protocol (RFC 0006 §4.4, RFC 0007 §6).
const (
	CodeMethodNotFound      = -32601
	CodeInteractionDeclined = -32010
)

// SecretRequest is one RFC 0006 §2.2 secret.request.
type SecretRequest struct {
	Kind              string  `json:"kind"`
	Prompt            string  `json:"prompt"`
	Card              *CardID `json:"card,omitempty"`
	Slot              string  `json:"slot,omitempty"`
	AttemptsRemaining *int    `json:"attempts_remaining,omitempty"`
	Detail            string  `json:"detail,omitempty"`
}

// CardID is the RFC 0006 §2.1 card identity carried by card-scoped requests.
type CardID struct {
	GUID   string `json:"guid"`
	Serial *int64 `json:"serial,omitempty"`
	CN     string `json:"cn,omitempty"`
}

// Progress is an RFC 0006 §2.6 progress notification.
type Progress struct {
	Step    string `json:"step"`
	Message string `json:"message"`
}

// ErrDeclined is returned by a SecretFunc to decline a request. The client
// answers piggy with interaction-declined (-32010), which aborts the command.
var ErrDeclined = errors.New("piggymgmt: interaction declined")

// SecretFunc answers a secret.request. Returning ErrDeclined, or any error,
// declines it.
type SecretFunc func(SecretRequest) (string, error)

// RPCError is a JSON-RPC error a command returned.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("piggy manage: %s (code %d)", e.Message, e.Code)
}

// Client drives one piggy manage connection. It is single-flight (RFC 0007 §4):
// one command at a time.
type Client struct {
	r      *bufio.Reader
	w      io.Writer
	nextID int

	// OnSecret answers secret.request. nil declines every request.
	OnSecret SecretFunc
	// OnProgress, if set, receives progress notifications.
	OnProgress func(Progress)
}

// NewClient wraps an already-open connection: r reads piggy's output, w writes
// to piggy's input.
func NewClient(r io.Reader, w io.Writer) *Client {
	return &Client{r: bufio.NewReader(r), w: w}
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Initialize runs the RFC 0007 §4 handshake. It must be the first call.
func (c *Client) Initialize(ctx context.Context) error {
	var res struct {
		Protocol string `json:"protocol"`
	}
	if err := c.call(ctx, "initialize", map[string]string{"protocol": Protocol}, &res); err != nil {
		return err
	}
	if major(res.Protocol) != major(Protocol) {
		return fmt.Errorf("piggy manage speaks %q, want %q", res.Protocol, Protocol)
	}
	return nil
}

// SignBytes runs the RFC 0007 §5.3 sign_bytes method and returns the signature
// bytes (raw r‖s for format "raw"). guid may be empty to use the sole card.
func (c *Client) SignBytes(ctx context.Context, slot, guid, format string, msg []byte) ([]byte, error) {
	params := map[string]string{
		"slot":    slot,
		"format":  format,
		"message": base64.StdEncoding.EncodeToString(msg),
	}
	if guid != "" {
		params["guid"] = guid
	}
	var res struct {
		Signature string `json:"signature"`
	}
	if err := c.call(ctx, "sign_bytes", params, &res); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(res.Signature)
	if err != nil {
		return nil, fmt.Errorf("piggy manage sign_bytes: signature is not base64: %w", err)
	}
	return sig, nil
}

// call sends one command request and serves interaction requests until the
// command's own response arrives.
func (c *Client) call(ctx context.Context, method string, params, result any) error {
	c.nextID++
	id := c.nextID
	if err := c.write(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return fmt.Errorf("piggy manage %s: write: %w", method, err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := c.r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) == 0 {
			if err != nil {
				return fmt.Errorf("piggy manage %s: connection closed before the result: %w", method, err)
			}
			continue // RFC 0007 §2: ignore blank lines
		}
		var m message
		if jerr := json.Unmarshal(line, &m); jerr != nil {
			return fmt.Errorf("piggy manage %s: malformed message: %w", method, jerr)
		}
		if m.Method != "" {
			if herr := c.handleInteraction(m); herr != nil {
				return fmt.Errorf("piggy manage %s: answer %s: %w", method, m.Method, herr)
			}
			continue
		}
		// A line without a method is the response to our one outstanding request.
		if m.Error != nil {
			return m.Error
		}
		if result != nil {
			if jerr := json.Unmarshal(m.Result, result); jerr != nil {
				return fmt.Errorf("piggy manage %s: decode result: %w", method, jerr)
			}
		}
		return nil
	}
}

// handleInteraction answers one interaction request, or consumes a
// notification (a message with no id).
func (c *Client) handleInteraction(m message) error {
	if len(m.ID) == 0 {
		if m.Method == "progress" && c.OnProgress != nil {
			var p Progress
			if json.Unmarshal(m.Params, &p) == nil {
				c.OnProgress(p)
			}
		}
		return nil
	}
	switch m.Method {
	case "secret.request":
		var req SecretRequest
		if err := json.Unmarshal(m.Params, &req); err != nil {
			return c.respondError(m.ID, CodeInteractionDeclined, "malformed secret.request")
		}
		if c.OnSecret == nil {
			return c.respondError(m.ID, CodeInteractionDeclined, "papi supplies no secret for "+req.Kind)
		}
		secret, err := c.OnSecret(req)
		if err != nil {
			return c.respondError(m.ID, CodeInteractionDeclined, err.Error())
		}
		return c.write(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]string{"secret": secret}})
	case "confirm.request", "mgmt_key.request", "card_select.request":
		return c.respondError(m.ID, CodeInteractionDeclined, "papi does not answer "+m.Method+" here")
	default:
		return c.respondError(m.ID, CodeMethodNotFound, "unknown method "+m.Method)
	}
}

func (c *Client) respondError(id json.RawMessage, code int, msg string) error {
	return c.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

func (c *Client) write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.w.Write(append(b, '\n'))
	return err
}

func major(protocol string) string {
	name, ver, _ := strings.Cut(protocol, "/")
	v, _, _ := strings.Cut(ver, ".")
	return name + "/" + v
}

// Session is a spawned `piggy manage --jsonrpc` process with an initialized
// Client.
type Session struct {
	*Client
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr *bytes.Buffer
}

// Start spawns `<name> manage --jsonrpc` and runs the handshake. Close it when done.
func Start(ctx context.Context, name string) (*Session, error) {
	cmd := exec.CommandContext(ctx, name, "manage", "--jsonrpc")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s manage --jsonrpc: %w", name, err)
	}
	s := &Session{Client: NewClient(stdout, stdin), cmd: cmd, stdin: stdin, stderr: &stderr}
	if err := s.Initialize(ctx); err != nil {
		_ = s.Close()
		return nil, s.withStderr(err)
	}
	return s, nil
}

// Close ends the connection (EOF on piggy's stdin is a clean shutdown) and
// waits for the process.
func (s *Session) Close() error {
	_ = s.stdin.Close()
	return s.cmd.Wait()
}

func (s *Session) withStderr(err error) error {
	if msg := strings.TrimSpace(s.stderr.String()); msg != "" {
		return fmt.Errorf("%w: %s", err, msg)
	}
	return err
}
