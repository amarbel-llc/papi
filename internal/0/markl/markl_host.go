//go:build !wasip1 && !(js && wasm)

package markl

import (
	"fmt"

	piggymarkl "code.linenisgreat.com/piggy/go/pkgs/markl"
	_ "code.linenisgreat.com/piggy/go/pkgs/markl_registrations"
)

// Parse decodes a markl-id wire string via piggy's canonical RFC 0011 implementation.
func Parse(s string) (ID, error) {
	if s == "" {
		return ID{}, fmt.Errorf("markl: empty id")
	}
	var pig piggymarkl.Id
	if err := pig.Set(s); err != nil {
		return ID{}, err
	}
	return ID{
		Purpose: pig.GetPurposeId(),
		Format:  pig.GetMarklFormat().GetMarklFormatId(),
		Payload: pig.GetBytes(),
		Raw:     s,
	}, nil
}

// Build encodes purpose, format, and payload as a markl-id wire string.
// A registered format whose payload is the wrong size is rejected.
func Build(purpose, format string, payload []byte) (string, error) {
	var pig piggymarkl.Id
	if err := pig.SetMarklId(format, payload); err != nil {
		return "", err
	}
	if purpose != "" {
		if err := pig.SetPurposeId(purpose); err != nil {
			return "", err
		}
	}
	return pig.StringWithFormat(), nil
}
