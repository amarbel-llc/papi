package markl

import (
	"errors"
	"fmt"
	"strings"
)

// blech32 is the bech32 variant defined by madder RFC-0002 §3: BIP173 bech32
// with the separator changed from the last `1` to the last `-`. This is a
// faithful, decode-focused port of the reference codec
// (amarbel-llc/madder go/internal/alfa/blech32) — enough for papi to parse and
// (in tests) build markl-ids byte-identically to the upstream implementation.

const blechCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// blechGenerator is the BCH generator polynomial (RFC-0002 §3).
var blechGenerator = []uint32{
	0x3b6a57b2,
	0x26508e6d,
	0x1ea119fa,
	0x3d4233dd,
	0x2a1462b3,
}

// dataPortionMinWidth is the minimum length of the data part: at least one
// payload character plus the six-character checksum (RFC-0002 §3).
const dataPortionMinWidth = 7

var (
	// ErrMixedCase is returned when a markl-id mixes upper- and lower-case.
	ErrMixedCase = errors.New("markl: mixed case")
	// ErrSeparatorMissing is returned when the `-` separator is absent.
	ErrSeparatorMissing = errors.New("markl: separator '-' missing")
	// ErrDataTooShort is returned when the data portion is shorter than the
	// six-character checksum plus one payload character.
	ErrDataTooShort = errors.New("markl: data portion too short")
	// ErrInvalidCharacter is returned for a data character outside the charset.
	ErrInvalidCharacter = errors.New("markl: invalid character in data")
	// ErrInvalidChecksum is returned when the blech32 checksum does not verify.
	ErrInvalidChecksum = errors.New("markl: invalid checksum")
	// ErrNonZeroPadding is returned when 5→8-bit conversion leaves non-zero pad.
	ErrNonZeroPadding = errors.New("markl: non-zero padding")
)

func blechPolymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>i)&1 == 1 {
				chk ^= blechGenerator[i]
			}
		}
	}
	return chk
}

func blechHRPExpand(hrp string) []byte {
	h := strings.ToLower(hrp)
	ret := make([]byte, 0, len(h)*2+1)
	for i := 0; i < len(h); i++ {
		ret = append(ret, h[i]>>5)
	}
	ret = append(ret, 0)
	for i := 0; i < len(h); i++ {
		ret = append(ret, h[i]&31)
	}
	return ret
}

func blechVerifyChecksum(hrp string, data []byte) bool {
	return blechPolymod(append(blechHRPExpand(hrp), data...)) == 1
}

func blechCreateChecksum(hrp string, data []byte) []byte {
	values := append(blechHRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := blechPolymod(values) ^ 1
	ret := make([]byte, 6)
	for p := range ret {
		ret[p] = byte(mod>>(5*(5-p))) & 31
	}
	return ret
}

// convertBits regroups data from frombits-wide to tobits-wide groups. With
// pad=false (decode) it rejects a remainder that carries non-zero bits.
func convertBits(data []byte, frombits, tobits byte, pad bool) ([]byte, error) {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	maxv := byte(1<<tobits - 1)
	for idx, value := range data {
		if value>>frombits != 0 {
			return nil, fmt.Errorf("markl: invalid data range at %d: %d", idx, value)
		}
		acc = acc<<frombits | uint32(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	switch {
	case pad:
		if bits > 0 {
			ret = append(ret, byte(acc<<(tobits-bits))&maxv)
		}
	case bits >= frombits:
		return nil, ErrNonZeroPadding
	case byte(acc<<(tobits-bits))&maxv != 0:
		return nil, ErrNonZeroPadding
	}
	return ret, nil
}

// uniformCase reports whether s is entirely lower- or entirely upper-case
// (case-invariant characters such as digits, `@`, `-`, `_` count as either).
func uniformCase(s string) bool {
	return strings.ToLower(s) == s || strings.ToUpper(s) == s
}

// blech32Decode decodes a blech32 string into its human-readable part (the
// markl format) and payload bytes.
func blech32Decode(s string) (hrp string, payload []byte, err error) {
	if !uniformCase(s) {
		return "", nil, ErrMixedCase
	}
	pos := strings.LastIndexByte(s, '-')
	if pos < 1 {
		return "", nil, ErrSeparatorMissing
	}
	if pos+dataPortionMinWidth > len(s) {
		return "", nil, ErrDataTooShort
	}
	hrp = s[:pos]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, fmt.Errorf("markl: invalid hrp character %q", hrp[i])
		}
	}
	lower := strings.ToLower(s)
	five := make([]byte, 0, len(lower)-pos-1)
	for i := pos + 1; i < len(lower); i++ {
		d := strings.IndexByte(blechCharset, lower[i])
		if d == -1 {
			return "", nil, ErrInvalidCharacter
		}
		five = append(five, byte(d))
	}
	if !blechVerifyChecksum(hrp, five) {
		return "", nil, ErrInvalidChecksum
	}
	payload, err = convertBits(five[:len(five)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}

// blech32Encode encodes payload bytes under hrp into a lower-case blech32
// string. Used to build markl-ids in tests/fixtures.
func blech32Encode(hrp string, payload []byte) (string, error) {
	five, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	hrp = strings.ToLower(hrp)
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('-')
	for _, p := range five {
		b.WriteByte(blechCharset[p])
	}
	for _, p := range blechCreateChecksum(hrp, five) {
		b.WriteByte(blechCharset[p])
	}
	return b.String(), nil
}
