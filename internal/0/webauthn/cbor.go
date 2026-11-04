package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// maxCBORDepth bounds nesting so a hostile attestationObject cannot recurse the
// decoder deep. WebAuthn structures nest at most four levels (attestationObject
// → attStmt → x5c array → bytes).
const maxCBORDepth = 8

var errCBOR = errors.New("webauthn: malformed CBOR")

// decodeCBOR decodes one CBOR data item from the front of b and returns it with
// the number of bytes consumed. It accepts the subset WebAuthn uses (RFC 8949
// major types 0–5 with definite lengths, plus the simple values false/true/null)
// and rejects everything else: indefinite lengths, tags, floats, duplicate map
// keys, integers outside int64. Values decode as int64, []byte, string, []any,
// map[any]any (keys int64 or string), bool, or nil.
func decodeCBOR(b []byte) (any, int, error) {
	return decodeItem(b, 0)
}

func decodeItem(b []byte, depth int) (any, int, error) {
	if depth > maxCBORDepth {
		return nil, 0, fmt.Errorf("%w: nesting deeper than %d", errCBOR, maxCBORDepth)
	}
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	major, info := b[0]>>5, b[0]&0x1f
	if major == 7 {
		switch info {
		case 20:
			return false, 1, nil
		case 21:
			return true, 1, nil
		case 22:
			return nil, 1, nil
		}
		return nil, 0, fmt.Errorf("%w: unsupported simple/float value %#x", errCBOR, b[0])
	}
	if major == 6 {
		return nil, 0, fmt.Errorf("%w: tags are not supported", errCBOR)
	}
	arg, n, err := decodeArgument(b, info)
	if err != nil {
		return nil, 0, err
	}
	rest := b[n:]
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, 0, fmt.Errorf("%w: unsigned integer exceeds int64", errCBOR)
		}
		return int64(arg), n, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, 0, fmt.Errorf("%w: negative integer exceeds int64", errCBOR)
		}
		return -1 - int64(arg), n, nil
	case 2, 3:
		if arg > uint64(len(rest)) {
			return nil, 0, fmt.Errorf("%w: string length %d exceeds input", errCBOR, arg)
		}
		s := rest[:arg]
		if major == 3 {
			return string(s), n + int(arg), nil
		}
		return append([]byte(nil), s...), n + int(arg), nil
	case 4:
		if arg > uint64(len(rest)) { // every element is at least one byte
			return nil, 0, fmt.Errorf("%w: array length %d exceeds input", errCBOR, arg)
		}
		arr := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, m, err := decodeItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			n += m
		}
		return arr, n, nil
	case 5:
		if arg > uint64(len(rest))/2 {
			return nil, 0, fmt.Errorf("%w: map length %d exceeds input", errCBOR, arg)
		}
		m := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, kn, err := decodeItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n += kn
			switch k.(type) {
			case int64, string:
			default:
				return nil, 0, fmt.Errorf("%w: map key must be an integer or text", errCBOR)
			}
			if _, dup := m[k]; dup {
				return nil, 0, fmt.Errorf("%w: duplicate map key %v", errCBOR, k)
			}
			v, vn, err := decodeItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n += vn
			m[k] = v
		}
		return m, n, nil
	}
	return nil, 0, fmt.Errorf("%w: unknown major type %d", errCBOR, major)
}

// decodeArgument reads the head's argument (RFC 8949 §3) and returns it with the
// head length. Additional info 31 (indefinite length) and 28–30 are rejected.
func decodeArgument(b []byte, info byte) (uint64, int, error) {
	switch {
	case info < 24:
		return uint64(info), 1, nil
	case info == 24:
		if len(b) < 2 {
			return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
		}
		return uint64(b[1]), 2, nil
	case info == 25:
		if len(b) < 3 {
			return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
		}
		return uint64(binary.BigEndian.Uint16(b[1:])), 3, nil
	case info == 26:
		if len(b) < 5 {
			return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
		}
		return uint64(binary.BigEndian.Uint32(b[1:])), 5, nil
	case info == 27:
		if len(b) < 9 {
			return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
		}
		return binary.BigEndian.Uint64(b[1:]), 9, nil
	}
	return 0, 0, fmt.Errorf("%w: indefinite or reserved length (info %d)", errCBOR, info)
}

// decodeCBORExact decodes b as exactly one CBOR item with no trailing bytes.
func decodeCBORExact(b []byte) (any, error) {
	v, n, err := decodeCBOR(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", errCBOR, len(b)-n)
	}
	return v, nil
}

// UnwrapByteString returns the content of b when b is exactly one CBOR byte
// string — the shape fido2-cred(1) and fido2-assert(1) print authenticator data
// in ("CBOR encoded authenticator data").
func UnwrapByteString(b []byte) ([]byte, error) {
	v, err := decodeCBORExact(b)
	if err != nil {
		return nil, err
	}
	bs, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: not a byte string", errCBOR)
	}
	return bs, nil
}
