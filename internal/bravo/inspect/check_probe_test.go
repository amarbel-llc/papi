package inspect

import (
	"crypto/elliptic"
	"encoding/json"
	"testing"

	"code.linenisgreat.com/papi/internal/0/markl"
)

// The §5.1 unknown-recipient probe must send a WELL-FORMED recipient: a
// malformed one makes a conforming server answer 400, which the probe then
// reports as a failure (papi#69).
func TestUnknownRecipientProbeIsWellFormed(t *testing.T) {
	body, err := unknownRecipientChallengeBody()
	if err != nil {
		t.Fatalf("unknownRecipientChallengeBody: %v", err)
	}
	var req struct {
		Recipient string `json:"recipient"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("probe body is not JSON: %v (%s)", err, body)
	}
	if !recipientGrammar.MatchString(req.Recipient) {
		t.Fatalf("probe recipient %q does not match the §5.1 recipient grammar", req.Recipient)
	}
	id, err := markl.Parse(req.Recipient)
	if err != nil {
		t.Fatalf("probe recipient %q does not parse as a markl-id: %v", req.Recipient, err)
	}
	if id.Purpose != "piggy-recipient-v1" || id.Format != "pivy_ecdh_p256_pub" {
		t.Fatalf("probe recipient purpose/format = %q/%q", id.Purpose, id.Format)
	}
	if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), id.Payload); x == nil {
		t.Fatalf("probe recipient payload is not a compressed P-256 point: %x", id.Payload)
	}
}
