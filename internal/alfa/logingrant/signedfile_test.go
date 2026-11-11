package logingrant

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"code.linenisgreat.com/papi/internal/0/markl"
)

func signedFile(t *testing.T) (file, text []byte, sig string) {
	t.Helper()
	text = goodText(t)
	sig, err := SignGrant(context.Background(), newCard(t), "", text)
	if err != nil {
		t.Fatal(err)
	}
	return MarshalSigned(text, sig), text, sig
}

func TestSignedFileRoundTrip(t *testing.T) {
	file, text, sig := signedFile(t)
	if !bytes.HasPrefix(file, text) || !strings.HasSuffix(string(file), "grant-sig: "+sig+"\n") {
		t.Fatalf("unexpected file shape:\n%s", file)
	}
	gotText, gotSig, err := ParseSigned(file)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if !bytes.Equal(gotText, text) || gotSig != sig {
		t.Error("round trip changed the text or signature")
	}
}

func TestParseSignedRefusals(t *testing.T) {
	file, text, sig := signedFile(t)
	authSig, err := markl.Build(markl.PurposeAuthSig, markl.FormatEcdsaP256Sig, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":                nil,
		"text only":            text,
		"signature line empty": append(append([]byte(nil), text...), []byte("grant-sig: \n")...),
		"junk after signature": append(append([]byte(nil), file...), []byte("more\n")...),
		"blank line before":    append(append(append([]byte(nil), text...), '\n'), []byte("grant-sig: "+sig+"\n")...),
		"two signature lines":  append(append([]byte(nil), file...), []byte("grant-sig: "+sig+"\n")...),
		"no final newline":     bytes.TrimSuffix(file, []byte("\n")),
		"not a markl id":       append(append([]byte(nil), text...), []byte("grant-sig: nonsense\n")...),
		"wrong purpose":        append(append([]byte(nil), text...), []byte("grant-sig: "+authSig+"\n")...),
		"malformed grant":      append([]byte("papi login-grant v2\n"), []byte("grant-sig: "+sig+"\n")...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseSigned(data); err == nil {
				t.Errorf("accepted:\n%s", data)
			}
		})
	}
}
