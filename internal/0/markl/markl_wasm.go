//go:build wasip1

// Inline blech32 for GOOS=wasip1. Piggy's markl adapter (markl_host.go)
// transitively imports purse-first/libs/dewey which has no WASM stub for
// setUserChanges. This file provides a self-contained Parse/Build using the
// same algorithm as piggy/go/internal/alfa/blech32 (MIT-licensed).
// File a bug against purse-first/libs/dewey to get a proper WASM stub.

package markl

import (
	"fmt"
	"strings"
)

// blech32 algorithm constants (RFC 0011 §3.1; generator from BIP173).
const blech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var blech32Generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func blech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk & 0x1ffffff) << 5
		chk ^= uint32(v)
		for i := range 5 {
			if top>>uint(i)&1 == 1 {
				chk ^= blech32Generator[i]
			}
		}
	}
	return chk
}

func blech32HRPExpand(hrp string) []byte {
	h := []byte(hrp) // caller ensures lowercase
	ret := make([]byte, 0, len(h)*2+1)
	for _, c := range h {
		ret = append(ret, c>>5)
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, c&31)
	}
	return ret
}

func blech32VerifyChecksum(hrp string, data []byte) bool {
	return blech32Polymod(append(blech32HRPExpand(hrp), data...)) == 1
}

func blech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(blech32HRPExpand(hrp), data...)
	values = append(values, make([]byte, 6)...)
	mod := blech32Polymod(values) ^ 1
	ret := make([]byte, 6)
	for p := range ret {
		ret[p] = byte(mod>>uint(5*(5-p))) & 31
	}
	return ret
}

func blech32ConvertBits(data []byte, fromBits, toBits byte, pad bool) ([]byte, error) {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	maxv := byte(1<<toBits - 1)
	for idx, value := range data {
		if value>>fromBits != 0 {
			return nil, fmt.Errorf("blech32: invalid data range at [%d]=%d (fromBits=%d)", idx, value, fromBits)
		}
		acc = acc<<fromBits | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte(acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits {
		return nil, fmt.Errorf("blech32: illegal zero padding")
	} else if byte(acc<<(toBits-bits))&maxv != 0 {
		return nil, fmt.Errorf("blech32: non-zero padding")
	}
	return ret, nil
}

// blech32Decode decodes a blech32 body string (no `purpose@` prefix).
// Enforces RFC 0011 §3.5 lowercase-only and §3.2 single-separator split.
func blech32Decode(s string) (hrp string, payload []byte, err error) {
	if strings.ToLower(s) != s {
		return "", nil, fmt.Errorf("blech32: uppercase or mixed case in %q", s)
	}
	pos := strings.IndexByte(s, '-')
	switch {
	case pos < 0:
		return "", nil, fmt.Errorf("blech32: no separator in %q", s)
	case pos == 0:
		return "", nil, fmt.Errorf("blech32: empty HRP in %q", s)
	case pos+7 > len(s):
		return "", nil, fmt.Errorf("blech32: data portion too short in %q", s)
	}
	hrp = s[:pos]
	dataPart := s[pos+1:]
	data := make([]byte, len(dataPart))
	for i, c := range dataPart {
		d := strings.IndexRune(blech32Charset, c)
		if d < 0 {
			return "", nil, fmt.Errorf("blech32: invalid character %q at position %d in %q", c, pos+1+i, s)
		}
		data[i] = byte(d)
	}
	if !blech32VerifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("blech32: invalid checksum in %q", s)
	}
	payload, err = blech32ConvertBits(data[:len(data)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}

// blech32Encode encodes hrp+data as a blech32 string (lowercase).
func blech32Encode(hrp string, data []byte) (string, error) {
	hrp = strings.ToLower(hrp)
	values, err := blech32ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	checksum := blech32CreateChecksum(hrp, values)
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('-')
	for _, v := range values {
		b.WriteByte(blech32Charset[v])
	}
	for _, v := range checksum {
		b.WriteByte(blech32Charset[v])
	}
	return b.String(), nil
}

// Parse decodes a markl-id wire string. For GOOS=wasip1 this uses an inline
// blech32 implementation derived from piggy's algorithm (no dewey dependency).
func Parse(s string) (ID, error) {
	if s == "" {
		return ID{}, fmt.Errorf("markl: empty id")
	}
	var purpose, body string
	if idx := strings.IndexByte(s, '@'); idx >= 0 {
		purpose = s[:idx]
		body = s[idx+1:]
	} else {
		body = s
	}
	format, payload, err := blech32Decode(body)
	if err != nil {
		return ID{}, err
	}
	return ID{
		Purpose: purpose,
		Format:  format,
		Payload: payload,
		Raw:     s,
	}, nil
}

// Build encodes purpose, format, and payload as a markl-id wire string.
// Unlike the host version, format validation against the registry is skipped
// (WASM is verify-only; no format registry is loaded).
func Build(purpose, format string, payload []byte) (string, error) {
	body, err := blech32Encode(format, payload)
	if err != nil {
		return "", err
	}
	if purpose != "" {
		return purpose + "@" + body, nil
	}
	return body, nil
}
