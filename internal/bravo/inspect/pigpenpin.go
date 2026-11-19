//go:build !wasip1 && !(js && wasm)

package inspect

import (
	"bytes"
	"fmt"
	"strings"

	"code.linenisgreat.com/hyphence/go/hyphence"
	"code.linenisgreat.com/papi/internal/0/markl"
)

// Signer pinning for the pigpen resolver (papi#54;
// docs/plans/2026-11-19-pigpen-key-pinning-design.md). The pin set lives in
// the pointer's locator, `<origin>#signer=<id>[,<id>]`, where each id is a
// slot-9A markl-id (piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…) taken from a
// card at a sitting.

// pigpenSignerFragmentKey is the only fragment key a locator may carry.
const pigpenSignerFragmentKey = "signer="

// ParsePigpenLocator splits a papi-http pigpen locator into the origin that
// papi.NewClient takes and its signer pin set (compressed P-256 points). A
// locator with no `#` has no pins. Anything after a `#` must be exactly
// `signer=<id>[,<id>]`; a malformed fragment is an error here, before any
// fetch, so a mistyped pin can never degrade to an unpinned resolve.
func ParsePigpenLocator(locator string) (origin string, pins [][]byte, err error) {
	origin, fragment, hasFragment := strings.Cut(locator, "#")
	if !hasFragment {
		return locator, nil, nil
	}
	list, ok := strings.CutPrefix(fragment, pigpenSignerFragmentKey)
	if !ok {
		return "", nil, fmt.Errorf("locator fragment %q: want signer=<markl-id>[,<markl-id>]", fragment)
	}
	for _, raw := range strings.Split(list, ",") {
		id, perr := markl.Parse(raw)
		if perr != nil || id.Purpose != markl.PurposePIVAuth || id.Format != markl.FormatSSHEcdsaNistp256Pub {
			return "", nil, fmt.Errorf("locator signer pin %q: want a %s@%s markl-id",
				raw, markl.PurposePIVAuth, markl.FormatSSHEcdsaNistp256Pub)
		}
		pins = append(pins, id.Payload)
	}
	return origin, pins, nil
}

// errPigpenSignerNotPinned: a pin set was given and the document carries no
// slot-9A key from it. A hard failure naming the keys the document did offer,
// so the operator can tell a legitimate rotation (re-pin at a card sitting)
// from an attack.
type errPigpenSignerNotPinned struct{ seen []string }

func (e *errPigpenSignerNotPinned) Error() string {
	if len(e.seen) == 0 {
		return "signer not pinned: the document carries no slot-9A key"
	}
	return "signer not pinned: the document's slot-9A key(s) " + strings.Join(e.seen, ", ") +
		" match none of the pinned signer(s)"
}

type pigpenCandidateKey struct {
	id    string
	point []byte
}

// pigpenCandidateKeys returns the document's auth-key lines a signature may be
// verified against: with no pins only the first (the unpinned behaviour);
// with pins every line whose point is pinned, in document order.
func pigpenCandidateKeys(lines []hyphence.MetadataLine, pins [][]byte) []pigpenCandidateKey {
	if len(pins) == 0 {
		if id, point, ok := findPigpenAuthKey(lines); ok {
			return []pigpenCandidateKey{{id, point}}
		}
		return nil
	}
	var out []pigpenCandidateKey
	for _, k := range pigpenAuthKeys(lines) {
		for _, pin := range pins {
			if bytes.Equal(k.point, pin) {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

func pigpenAuthKeys(lines []hyphence.MetadataLine) []pigpenCandidateKey {
	var out []pigpenCandidateKey
	for _, l := range lines {
		if l.Prefix != '-' {
			continue
		}
		id, err := markl.Parse(l.Value)
		if err != nil || id.Purpose != markl.PurposePIVAuth || id.Format != markl.FormatSSHEcdsaNistp256Pub {
			continue
		}
		out = append(out, pigpenCandidateKey{l.Value, id.Payload})
	}
	return out
}

// pigpenUnpinnedKeyIDs returns the document's auth-key ids that are not among
// the already-tried candidates.
func pigpenUnpinnedKeyIDs(lines []hyphence.MetadataLine, tried []pigpenCandidateKey) []string {
	var ids []string
next:
	for _, k := range pigpenAuthKeys(lines) {
		for _, t := range tried {
			if bytes.Equal(k.point, t.point) {
				continue next
			}
		}
		ids = append(ids, k.id)
	}
	return ids
}

func pigpenAuthKeyIDs(lines []hyphence.MetadataLine) []string {
	var ids []string
	for _, k := range pigpenAuthKeys(lines) {
		ids = append(ids, k.id)
	}
	return ids
}
