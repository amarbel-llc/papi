package webauthn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// maxCBORDepth bounds nesting so a hostile attestationObject cannot recurse the
// decoder deep. WebAuthn structures nest at most four levels (attestationObject
// → attStmt → x5c array → bytes).
const maxCBORDepth = 8

// decodeItem decodes one CBOR data item from the front of b (call it with depth
// 0) and returns it with the number of bytes consumed. It accepts the subset
// WebAuthn uses (RFC 8949 major types 0–5 with definite lengths, plus the simple
// values false/true/null) and rejects everything else: indefinite lengths, tags,
// floats, duplicate map keys, integers outside int64. Values decode as int64,
// []byte, string, []any, map[any]any (keys int64 or string), bool, or nil.
//
// Byte strings are sub-slices of b, not copies: callers that hand them out
// across the package boundary copy them there.
func decodeItem(b []byte, depth int) (any, int, error) {
	if depth > maxCBORDepth {
		return nil, 0, fmt.Errorf("%w: CBOR nesting deeper than %d", ErrMalformed, maxCBORDepth)
	}
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("%w: truncated CBOR", ErrMalformed)
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
		return nil, 0, fmt.Errorf("%w: unsupported CBOR simple/float value %#x", ErrMalformed, b[0])
	}
	if major == 6 {
		return nil, 0, fmt.Errorf("%w: CBOR tags are not supported", ErrMalformed)
	}
	arg, n, err := decodeArgument(b, info)
	if err != nil {
		return nil, 0, err
	}
	switch major {
	case 0, 1:
		if arg > math.MaxInt64 {
			return nil, 0, fmt.Errorf("%w: CBOR integer exceeds int64", ErrMalformed)
		}
		if major == 1 {
			return -1 - int64(arg), n, nil
		}
		return int64(arg), n, nil
	case 2, 3:
		rest := b[n:]
		if arg > uint64(len(rest)) {
			return nil, 0, fmt.Errorf("%w: CBOR string length %d exceeds input", ErrMalformed, arg)
		}
		s := rest[:arg:arg]
		if major == 3 {
			return string(s), n + int(arg), nil
		}
		return s, n + int(arg), nil
	case 4:
		// No capacity hint from the untrusted length: every element consumes at
		// least one byte, so a lying length fails as truncated input.
		var arr []any
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
		m := make(map[any]any)
		for i := uint64(0); i < arg; i++ {
			k, kn, err := decodeItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n += kn
			switch k.(type) {
			case int64, string:
			default:
				return nil, 0, fmt.Errorf("%w: CBOR map key must be an integer or text", ErrMalformed)
			}
			v, vn, err := decodeItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n += vn
			m[k] = v
			if uint64(len(m)) != i+1 {
				return nil, 0, fmt.Errorf("%w: duplicate CBOR map key %v", ErrMalformed, k)
			}
		}
		return m, n, nil
	}
	return nil, 0, fmt.Errorf("%w: unknown CBOR major type %d", ErrMalformed, major)
}

// decodeArgument reads the head's argument (RFC 8949 §3) and returns it with the
// head length. Additional info 31 (indefinite length) and 28–30 are rejected.
func decodeArgument(b []byte, info byte) (uint64, int, error) {
	if info < 24 {
		return uint64(info), 1, nil
	}
	if info > 27 {
		return 0, 0, fmt.Errorf("%w: CBOR indefinite or reserved length (info %d)", ErrMalformed, info)
	}
	size := 1 << (info - 24)
	if len(b) < 1+size {
		return 0, 0, fmt.Errorf("%w: truncated CBOR", ErrMalformed)
	}
	var buf [8]byte
	copy(buf[8-size:], b[1:1+size])
	return binary.BigEndian.Uint64(buf[:]), 1 + size, nil
}

// decodeCBORExact decodes b as exactly one CBOR item with no trailing bytes.
func decodeCBORExact(b []byte) (any, error) {
	v, n, err := decodeItem(b, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes after CBOR item", ErrMalformed, len(b)-n)
	}
	return v, nil
}

// UnwrapByteString returns (a copy of) the content of b when b is exactly one
// CBOR byte string — the shape fido2-cred(1) and fido2-assert(1) print
// authenticator data in ("CBOR encoded authenticator data").
func UnwrapByteString(b []byte) ([]byte, error) {
	v, err := decodeCBORExact(b)
	if err != nil {
		return nil, err
	}
	bs, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: not a CBOR byte string", ErrMalformed)
	}
	return bytes.Clone(bs), nil
}
