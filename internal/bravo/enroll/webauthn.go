package enroll

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"code.linenisgreat.com/papi/internal/0/markl"
	"code.linenisgreat.com/papi/internal/0/webauthn"
	"code.linenisgreat.com/papi/internal/alfa/papi"
)

// MadeCredential is what fido2-cred(1) -M prints for a new credential: the
// attestation format, the authenticator data (already unwrapped from its CBOR
// byte string), the credential id, and the attestation signature and
// certificate. ClientDataHash is the hash papi passed in.
type MadeCredential struct {
	Fmt            string
	AuthData       []byte
	CredentialID   []byte
	AttSig         []byte
	X5C            []byte
	ClientDataHash []byte
}

// BuildWebAuthnBlock turns a made credential into a receipt's webauthn member.
// It checks the registration against the enroll policy, cross-checks the
// credential id fido2-cred printed against the one in the authenticator data,
// and signs the binding claim with the new card's slot-9A key.
func BuildWebAuthnBlock(ctx context.Context, signer Signer, newCard Card, rpID string, made MadeCredential) (*papi.ReceiptWebAuthn, error) {
	reg, err := webauthn.NewRegistration(made.Fmt, made.AuthData)
	if err != nil {
		return nil, fmt.Errorf("webauthn registration: %w", err)
	}
	cred, err := reg.Credential(rpID, webauthn.EnrollPolicy)
	if err != nil {
		return nil, fmt.Errorf("webauthn registration: %w", err)
	}
	if len(made.CredentialID) != 0 && string(made.CredentialID) != string(cred.ID) {
		return nil, fmt.Errorf("webauthn registration: fido2-cred's credential id does not match the authenticator data's")
	}
	att := reg.AuthData.Attested
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	claim := papi.WebAuthnBindingClaim(rpID, credID, att.COSEKey, newCard.SSHID)
	sig, err := signMarkl(ctx, signer, newCard.GUID, []byte(claim), markl.PurposeProofSig)
	if err != nil {
		return nil, fmt.Errorf("webauthn binding (new card slot-9A): %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return &papi.ReceiptWebAuthn{
		Visibility:   "public",
		Label:        "yubikey-fido2-" + guid8(newCard.GUID),
		GUID:         newCard.GUID,
		RPID:         rpID,
		CredentialID: credID,
		PublicKey:    b64(att.COSEKey),
		Alg:          -7,
		AAGUID:       hex.EncodeToString(att.AAGUID[:]),
		CredProtect:  reg.AuthData.CredProtect,
		Discoverable: false,
		UVPolicy:     map[string]string{"tier1": "discouraged", "tier2": "required"},
		Registration: papi.ReceiptWebAuthnRegistration{
			Fmt:            made.Fmt,
			AuthData:       b64(reg.RawAuthData),
			ClientDataHash: b64(made.ClientDataHash),
			AttSig:         b64(made.AttSig),
			X5C:            b64(made.X5C),
		},
		Binding: papi.ReceiptSelfProof{Claim: claim, Sig: sig},
	}, nil
}
