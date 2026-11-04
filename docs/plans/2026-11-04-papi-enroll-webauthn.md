# One enrollment per card: `papi enroll` provisions PIV and a WebAuthn credential (amarbel-llc/circus#414)

Question (amarbel-llc/circus#414): the operator wants some linenisgreat.com pages
gated by a WebAuthn assertion from the same YubiKey PAPI already knows as their
card, so that personal "in case of emergency" travel documents can be read from
any device that has WebAuthn and the key. How should `papi enroll` (PIV card
init) and the WebAuthn credential stay in step, so there is one thing to
provision per card? This is a design note plus a card-free spike. No card was
used and nothing was deployed.

Operator decisions (2026-11-04), taken as given here: one command in one sitting
(two PIN prompts are fine). Two tiers on the FIDO2 side: **tier 1** gates data on
a touch (user presence, UP), **tier 2** on a touch plus the PIN (user
verification, UV), and both tiers use the same PIN. The rpId is `linenisgreat.com`.
Credential public keys are published in the served document, like the 9A/9D
keys. A lost key is removed by a deploy from another trusted card, and a spare is
enrolled. Enroll hosts are Linux (twerk, nikulin, maybe flic). YubiKey 5 series
only. Direction "option D": `papi enroll` runs PIV init, then a CTAP FIDO2
phase, and writes one receipt. Browser registration is the fallback.

Evidence labels: **VERIFIED** (source cited), **UNVERIFIED** (not checked, or
needs hardware), **R** (read in this repo at `fresh-fig` after ab85cc2).

Sources actually consulted:

- libfido2 1.17.0: the `fido2-cred(1)`, `fido2-assert(1)` and
  `fido_cred_set_authdata(3)` pages, `src/fido/param.h`, and
  `regress/assert.c`, all read from the nixpkgs source tarball
  `/nix/store/wab572ar…-libfido2-1.17.0.tar.gz`. clarabell separately fetched
  `fido2-cred(1)` from developers.yubico.com; it matches.
- WebAuthn Level 3 §7.2, "Verifying an Authentication Assertion"
  (w3.org/TR/webauthn-3/#sctn-verifying-assertion). clarabell fetched it on
  2026-11-04 and relayed steps 10–24.
- **Not obtained:** the CTAP 2.1/2.2 spec text. My web fetch (chrest) was denied
  under dontAsk, and clarabell's own fetch from fidoalliance.org was also denied.
  So every CTAP-behaviour claim below is UNVERIFIED unless it cites libfido2.

## Short answer

Yes. The receipt can carry the WebAuthn credential the same way it carries the
9A and 9D keys, with no change to how trust works.

1. `papi enroll` gets a FIDO2 phase after the PIV phase. Through libfido2's
   tools, it makes **one** ES256, **non-discoverable** credential on the new
   card, with **credProtect level 2** (`userVerificationOptionalWithCredentialIDList`)
   and with UV at creation.
2. The credential id and COSE public key go in a new `webauthn` block of a
   **`papi-enroll-receipt-v2`**.
3. The new card's slot-9A key signs a **binding claim** that names the
   credential and the card's 9A key. The trusted card's attestation already
   covers the whole receipt, `webauthn` block included.
4. The deploy splices the block into a new `piggy.webauthn_credentials[]`.

The tiers are a per-page assertion policy, not separate credentials. A tier-1
page asks for `userVerification: "discouraged"`, and the server requires only
UP. A tier-2 page asks for `"required"`, and the server requires UP and UV. The
UV bit is signed by the authenticator, so the server can enforce tier 2 against
the same credential. The spike (`internal/0/webauthn`) implements and tests
exactly this verifier logic.

## 1. What exists today (R)

- **Enroll:** `internal/bravo/enroll`. `BuildReceipt` (`enroll.go:51`) composes
  the receipt from `ReadCard` read-back (`card.go:80`). `bindingClaim`
  (`enroll.go:110`) builds the claim, which the new card's 9A signs through
  `Signer.SignSlot9A`. That signer is `piggy sign-bytes`, or the agent
  (`agent.go`). Provisioning is `piggy card init` (`provision.go:386`). Every
  device step is an exec `Runner`/`InteractiveRunner`, which makes it testable
  without a card.
- **Receipt:** `internal/alfa/papi/receipt.go`, `papi-enroll-receipt-v1`.
  `CanonicalReceiptInput` strips `attestation` and JCS-canonicalizes the rest,
  so any new top-level member is covered by the trusted card's attestation with
  no change to the canonicalization.
- **FDR-0001** (`docs/features/0001-…`): the slot roles, the layering rule
  ("piggy mints keys and signs bytes; papi gives those bytes their papi
  meaning"), and the receipt schema. **RFC-0001** §2 (visibility/ACL
  projection), §3 (principal registry), §5 (handshake and sessions), §12.3
  (state-mutating provisioning is out of scope). **FDR-0007:** the wasm client
  core has to stay network-free and TUI-free. A WebAuthn verifier it might
  expose must therefore be stdlib-only, and the spike is.
- **Gated pages:** the `sitemap` is an ordinary document node (RFC-0001 §1,
  `/papi/sitemap`). Gating is §2 projection: `visibility: "private"` plus an
  `acl` of principal ids or groups. So the natural way to gate pages by tier is
  **groups minted onto the session** (§4 below), not a new gating mechanism.
- **piggy:** it has no CTAP or FIDO2 primitive. A search of
  `/home/sasha/eng/repos/piggy` for fido, ctap and webauthn finds only reader
  names and piggy's FDR-0004, which states "piggy never touches the FIDO2
  applet" (LUKS uses `systemd-cryptenroll`). VERIFIED (R in piggy).

## 2. Receipt v2

`papi-enroll-receipt-v2` is the v1 receipt plus one member. The v1 members are
unchanged, so a v1 verifier rejects v2 on the schema tag rather than misreading
it.

    "webauthn": {                                 // → piggy.webauthn_credentials[]
      "visibility": "public",
      "label": "yubikey-fido2-<guid8>",
      "guid": "<HEX>",                            // the PIV GUID this credential is bound to
      "rp_id": "linenisgreat.com",
      "credential_id": "<base64url>",
      "public_key": "<base64url COSE_Key>",       // byte-exact from authData (AttestedCredential.COSEKey)
      "alg": -7,                                  // ES256 only
      "aaguid": "<hex>",
      "cred_protect": 2,
      "discoverable": false,
      "uv_policy": { "tier1": "discouraged", "tier2": "required" },
      "registration": {                           // evidence: lets verify-receipt re-derive the fields above
        "fmt": "packed",
        "auth_data": "<base64url>",
        "client_data_hash": "<base64url>",
        "att_stmt": "<base64url CBOR>"
      },
      "binding": {
        "claim": "papi-enroll-receipt-v2 binds webauthn linenisgreat.com credential <credential_id> key sha256:<hex(SHA-256(public_key))> to piggy-piv_auth-v1@…<9A>",
        "sig": "papi-proof-sig-v1@ecdsa_p256_sig-…"   // new card's slot-9A over the claim bytes
      }
    }

- **The binding claim is signed by the new card's 9A.** It reuses the §9.3
  `papi-proof-sig-v1` purpose, the same signature mechanism as v1's
  `self_proof`, so no new markl purpose is needed. Trust is unchanged: the
  binding proves the holder of the new card's 9A asserted this credential, the
  attestation proves an already-published card authorized the whole receipt,
  and the deploy gate checks both.
- **FIDO attestation cannot provide this binding.** YubiKey 5 produces a
  `packed` statement chained to a Yubico batch certificate. It proves "a
  YubiKey model X made this key", not "the same device as PIV GUID G".
  UNVERIFIED that no YubiKey-5 FIDO attestation field ties it to the PIV
  applet; I know of none. `fido2-cred -V` itself does **not** validate the
  attestation certificate: "In the case of Basic Attestation, the validity of
  the authenticator's attestation certificate is *not* verified" (VERIFIED,
  `fido2-cred(1)` CAVEATS). The spike parses `attStmt` but does not verify it.
- **The remaining gap is "same physical device"**, which the binding and
  attestation signatures cannot prove. It is closed procedurally (§3 step 3,
  the one-device rule). An operator could only get a second device's credential
  into the receipt by plugging it in on purpose, and the receipt is still
  attested by a trusted card.
- **`registration.client_data_hash`** is a domain-separated hash that papi
  chooses: `SHA-256("papi-webauthn-reg-v1\n" ‖ rp_id ‖ "\n" ‖ guid ‖ "\n" ‖ <9A id>)`.
  The authenticator's packed attestation signature covers authData ‖ cdh, so the
  registration evidence names the card it was made for. This is a nice-to-have:
  nothing relies on it for trust.

## 3. The enroll FIDO2 phase

`papi enroll <domain>` (new card) and `papi enroll <domain> --add-webauthn
--new-guid <G>` (card already enrolled) share the phase. The order puts the
trusted card last, so during the FIDO2 phase only the new card is plugged in:

1. PIV phase as today: pick the card, run `piggy card init`, read back. **PIN
   prompt #1** is the new card's PIV PIN. In `--add-webauthn` mode this step is
   skipped, and the published 9A for GUID G is read back and matched against
   `/papi/piggy-ids`.
2. `self_proof` signed by the new card's 9A, as today (PIN policy `once`, so it
   is cached).
3. **Preflight.** `fido2-token -L` must list **exactly one** FIDO device, and
   PC/SC must list **exactly one** card, whose GUID is the new card's. If either
   check fails, papi refuses and tells the operator to unplug the other keys.
   `fido2-token -I` reads the AAGUID and options. papi refuses a non-YubiKey-5
   AAGUID, using an allowlist the operator maintains, and refuses `alwaysUv=true`,
   because that would make tier 1 impossible. UNVERIFIED: the exact
   `fido2-token -I` output shape, and whether a sysfs walk (hidraw parent USB
   device == the CCID reader's USB device) could replace "exactly one" with a
   positive same-device check.
4. **FIDO2 PIN.** If the applet has no PIN, run `fido2-token -S`. If it already
   has one, for example from piggy FDR-0004's LUKS `hmac-secret` enrollment,
   reuse it and **never reset** the applet. A FIDO2 reset destroys every FIDO2
   credential, including a LUKS keyslot's. That FIDO2 reset wipes all
   credentials is from memory, UNVERIFIED here. A PIN is never put in argv:
   libfido2 prompts on the tty (VERIFIED, `fido2-cred(1)`).
5. **Make the credential:** `fido2-cred -M -v -c 2 -i <param> <dev> es256`, with
   no `-r` (non-discoverable) and no `-h` (no hmac-secret). The input is the
   cdh, the rp id, a user name, and a random 32-byte user id; the output is fmt,
   CBOR authData, credential id, attestation signature, and x5c (VERIFIED, the
   INPUT/OUTPUT FORMAT sections of `fido2-cred(1)`; `-c` takes the decimal
   level, and `fido/param.h` defines `FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0x02`).
   **PIN prompt #2** is the FIDO2 PIN, plus a touch. papi then parses the
   output with `internal/0/webauthn`. `UnwrapByteString` handles libfido2's
   CBOR-wrapped authData; `RegistrationPolicy{RequireUV: true,
   RequireCredProtect: 2, RequireDeviceBound: true}` rejects a credential where
   UV did not happen, credProtect was not honoured, or the credential is
   backup-eligible.
6. **Self-check tier 1 on the hardware:**
   `fido2-assert -G -t up=true -t uv=false`, sending the new credential id and
   asking for a touch only. The resulting assertion is verified with
   `TierTouch`. This turns the UNVERIFIED claim "credProtect 2 allows a UP-only
   assertion when the credential id is supplied, even with a PIN set" into
   something every enrollment proves. If it fails, the enrollment aborts before
   anything is written. A tier-2 self-check would cost another PIN prompt, so it
   is optional (`--check-uv`).
7. **Binding claim** signed by the new card's 9A, with the PIN still cached.
8. Present the **trusted card** and attest, exactly as in v1. In
   `--add-webauthn` mode, see question 3. Write the receipt.

The PIN count is the new card's PIV PIN, the FIDO2 PIN (entered twice if it is
being set for the first time), and the trusted card's PIV PIN. That is more than
two; see question 8.

**Browser registration fallback:** the site serves a
`navigator.credentials.create()` page with `rp.id = linenisgreat.com`,
`residentKey: "discouraged"`, `userVerification: "required"`, and
`extensions: {credentialProtectionPolicy: "userVerificationOptionalWithCredentialIDList",
enforceCredentialProtectionPolicy: true}`. The extension input names are from
memory, UNVERIFIED. The page shows the attestationObject, and
`papi enroll --add-webauthn --from-browser <file>` builds the v2 block from it,
skipping steps 3–6. Whether this fallback is worth building at all is a
question for the operator.

### Tooling: shell out to libfido2's tools (recommended)

- **Shell out** to `fido2-token`, `fido2-cred` and `fido2-assert`. This matches
  how papi already drives `piggy` and `pivy-tool` through `Runner`, keeps papi's
  Go build cgo-free, and keeps the wasm packages clean. libfido2 is in nixpkgs
  (`libfido2` 1.17.0, VERIFIED with `chix which`), so it is a runtime dependency
  of papi's wrapper/devshell with **no flake lock bump**.
- **github.com/keys-pub/go-libfido2** is cgo over libfido2. papi's
  `buildGoApplication` would need `CGO_ENABLED=1` plus libfido2 headers and
  libs. Any package that imported it would have to be kept out of the
  `papi-verify-wasm` and `papi-client-wasm` import graphs, and it would make
  cross and static builds harder. Its maintenance status is UNVERIFIED.
  Not recommended.
- **A pure-Go CTAP-HID client** would avoid cgo, but it means new USB/HID parsing
  that papi would own. UNVERIFIED which libraries exist. Not now.
- **Linux hidraw access:** the enroll host's user needs read/write on
  `/dev/hidraw*` for the YubiKey, which on NixOS means udev rules (for example
  libfido2's or the YubiKey ones). UNVERIFIED for twerk, nikulin and flic; this
  is a hand-off.

## 4. The two tiers

| Question | Recommendation | Evidence |
|---|---|---|
| One credential or two? | **One.** The tier is chosen per assertion by the RP. Two credentials (tier 2 at credProtect 3) would add nothing the server cannot already enforce, because UV is a signed flag in authData. It would double what is published and revoked, and add a second make-credential prompt. | WebAuthn L3 §7.2 step 17: "If user verification was determined to be required, verify that the UV bit … is set. Otherwise, ignore the value of the UV flag." VERIFIED (clarabell fetch). The spike's `TestVerifyAssertionTiers` shows one credential serving both tiers. |
| credProtect level | **2** (`UV_OPTIONAL_WITH_ID`). Level 3 (`UV_REQUIRED`) would make tier 1 impossible. Level 1 (`UV_OPTIONAL`) would let a non-discoverable credential be used without UV, which is the same as level 2 for our use, but level 2 is the honest declaration. | The constants are VERIFIED (`fido/param.h`: `0x01/0x02/0x03`). The level semantics (2 = usable without UV only when the credential id is in the allowList; 3 = UV always) are **UNVERIFIED**, because the CTAP text was not obtained. Enroll step 6 checks this on hardware every time. |
| Discoverable (resident)? | **No.** Assertions always send `allowCredentials` with the published ids. No resident slot is used, and level 2's "with credential ID" path is exactly the path we use. | `fido2-cred -r` / `fido2-assert -r` semantics VERIFIED (`fido2-cred(1)`, `fido2-assert(1)`). YubiKey resident slot limits: UNVERIFIED, not needed. |
| UV at registration | **Required** (`-v`). | `fido2-cred(1)` `-v`, VERIFIED. That makeCredential needs a PIN once one is set (unless `makeCredUvNotRqd`) is UNVERIFIED; it is moot because we always do UV. |
| Tier 1 assertion | Browser: `userVerification: "discouraged"`. Server: `TierTouch` (UP required, UV ignored). | §7.2 steps 16–17, VERIFIED. That browsers send `uv=false` for "discouraged" and the YubiKey then does touch only with a PIN set is **UNVERIFIED** (hardware/browser). |
| Tier 2 assertion | Browser: `"required"`. Server: `TierPIN` (UP and UV). | §7.2 step 17, VERIFIED. |
| Same PIN for both | Tier 1 uses no PIN, and tier 2 uses the FIDO2 PIN. Whether "same PIN" means "FIDO2 PIN = PIV PIN value" is question 1. | FIDO2 and PIV PINs are separate: piggy FDR-0004, VERIFIED (R). |
| hmac-secret / largeBlob | Not used. | Only signatures are needed. |
| signCount | The verifier enforces it when a count is supplied. The site is stateless (git is the durable state, and only challenges and sessions live in tmp JSON), so it **cannot track counts durably**. Recommendation: don't enforce, or keep a best-effort count in tmp. | §7.2 step 22: "a signal, but not proof … RP-specific", VERIFIED. |
| BE/BS | Reject `BE=1` at registration (device-bound only), and reject `BS` without `BE` always. | §7.2 step 18, VERIFIED. |

**CLI-made credential, browser assertion:** §7.2 verifies an assertion using
only the stored credential record (public key and rpId) and the *assertion's
own* clientDataJSON. Nothing from the registration ceremony's client data is
used, so a credential made by `fido2-cred` with a papi-chosen cdh verifies like
any other (VERIFIED from the step list; the spike's
`TestBrowserAssertionOfCLIMadeCredential`). A CTAP client sets rpId freely and
supplies the cdh itself; the authenticator never sees an origin (VERIFIED from
the interface: `fido2-cred` input line 2 is a free "relying party id (UTF-8
string)" and line 1 is the client data hash). Whether a browser on another
device finds this non-discoverable credential is UNVERIFIED on hardware. It
should, given `allowCredentials` with its id and `rpId: linenisgreat.com`. This
is the first thing to try when a card is available.

**Tier groups on the session (proposal):** a successful WebAuthn assertion mints
a §5 session whose principal carries `authenticated` plus `assurance-touch`, and
for UV also `assurance-pin`. A tier-1 page is `visibility: "private", acl:
["assurance-touch"]`, and a tier-2 page uses `acl: ["assurance-pin"]`. This
needs no change to §2 projection, only new group sources in §3 and §5. Whether a
PIV sign-challenge session also gets both groups is question 2.

## 5. The spike: `internal/0/webauthn` (VERIFIED by tests)

`internal/0/webauthn` is stdlib only: no new go.mod dependency, no cgo, and no
gomod2nix change. It sits in `internal/0` because it imports nothing internal
(the dagnabit tier rule). Contents:

- `cbor.go`: a strict CBOR subset decoder (major types 0–5 with definite
  lengths, plus false/true/null). It rejects tags, floats, indefinite lengths,
  duplicate keys, int64 overflow, length overflow, and nesting deeper than 8.
  It also provides `UnwrapByteString` for libfido2's tool output.
  `fxamacker/cbor` is the alternative if the decoder ever needs more. It is not
  needed now.
- `webauthn.go`: `ParseAuthenticatorData` (flags, signCount, attested
  credential, an ES256/P-256 COSE key checked on-curve, extensions, and
  rejection of trailing bytes); `ParseAttestationObject`; and
  `Registration.Credential` with a `RegistrationPolicy` (rpIdHash, UP, UV,
  credProtect level, device-bound, BE/BS). Assertions go through
  `VerifyAssertion` (rpIdHash, the BE/BS rule, policy flags, an ECDSA
  signature over authData ‖ cdh, signCount), `VerifyBrowserAssertion`, and
  `CheckClientDataJSON` (§7.2 steps 10–13: type, challenge, exact origin
  allowlist, crossOrigin). `TierTouch` and `TierPIN` are the two policies.
- Tests were written first and confirmed failing before any code existed. The
  fixtures are deterministic: a fixed P-256 scalar, with authData and a "none"
  attestationObject built in the test. One vector is published: **libfido2
  1.17.0 `regress/assert.c`**, a valid ES256 assertion (`es256_pk`, `cdh`,
  `authdata`, `sig`, rp `localhost`, flags 0x00, signCount 3). It verifies under
  a no-flags policy and is correctly rejected by `TierTouch`, because it has no
  UP. I found no WebAuthn L3 test-vector appendix; clarabell could not confirm
  one either.
- Not in the spike: verifying packed attestation, the CTAP device I/O, and the
  receipt v2 types. These are the next step once the questions are answered.

## 6. Amendments needed (listed, not written)

**FDR-0001** (`docs/features/0001-papi-new-yubikey-enrollment.md`):

- the receipt-v2 schema and its `webauthn` block;
- the FIDO2 phase and its order (trusted card last);
- `--add-webauthn` (and `--from-browser`);
- the one-device rule;
- libfido2 as a runtime tool;
- new tuning levers: credProtect level, discoverable, AAGUID allowlist,
  tier-1 self-check, `--check-uv`;
- limitations: no FIDO2 reset, signCount not tracked, FIDO attestation not
  verified;
- `papi verify-receipt` re-derives `credential_id`/`public_key` from
  `registration.auth_data` and verifies `binding`.

**RFC-0001**:

- §1: a new `piggy.webauthn_credentials[]` member, the projected endpoint
  `GET /papi/webauthn-credentials`, and the `/papi/piggy-ids` interplay (none:
  credential ids are not markl ids, unless a purpose is minted; see below).
- §3: the registry maps a credential id to a principal.
- §4.1: discovery `auth.webauthn: {rp_id, tiers}`.
- A new §5.5, the WebAuthn assertion scheme:
  - `POST /papi/auth/challenge {method:"webauthn", tier}` returns a challenge
    and the `allowCredentials` ids;
  - `POST /papi/auth/response {challenge_id, credential_id, authenticator_data,
    client_data_json, signature}`;
  - the server verifies with §7.2 steps 10–22, using the identity domain's
    origins, and mints a session with the tier groups.
- §12.3 stays as it is: the credential arrives by deploy, not by a registration
  endpoint, so it is not a server-side registration surface. The browser
  fallback's `create()` page only *displays* the attestationObject and stores
  nothing.
- Security Considerations:
  - anyone holding the key passes tier 1;
  - credential ids are public;
  - no clone detection without signCount state;
  - the origin allowlist and rpId suffix rules (subdomain origins under
    `linenisgreat.com` are permitted by WebAuthn rpId rules; from memory,
    UNVERIFIED);
  - phishing resistance comes from the browser's origin binding, which a
    CLI-made credential keeps for browser assertions.
- Amendment History.

**ADR-0006** (markl purposes): only needed if the public key is published as a
markl id (for example `papi-webauthn-v1@cose_es256_pub-…`) rather than as
base64url COSE. The binding signature reuses `papi-proof-sig-v1`. Recommendation:
plain base64url COSE for v0, because browsers and verifiers consume COSE
directly.

**FDR-0007** (wasm client): optionally expose `webauthn.VerifyAssertion` through
`papiCall`. It is already wasm-safe.

## 7. Hand-offs (not edited here)

- **circus `sites/linenisgreat/api`:**
  - the §5.5 endpoints, with challenges in tmp JSON like the existing schemes;
  - an assertion verifier (port the spike's checks, or call papi's wasm or Go
    verifier), noting the existing ES256 verifier takes raw `r‖s` while
    WebAuthn signatures are ASN.1 DER;
  - discovery `auth.webauthn`;
  - session tier groups;
  - gated sitemap and page nodes;
  - the front-end `navigator.credentials.get()` page, with `allowCredentials`
    and a per-tier `userVerification`;
  - splicing `webauthn_credentials[]` into papi.json;
  - extending `just papi-verify-keys` to verify v2 receipts;
  - the signCount decision.
- **circus infra (enroll hosts twerk, nikulin, flic):** libfido2 on PATH, and
  hidraw udev access for YubiKeys.
- **piggy (questions only):**
  - Should a generic, papi-agnostic FIDO2 primitive (make-credential /
    get-assertion over CTAP) live in piggy, in keeping with FDR-0001's "piggy
    mints keys and signs bytes"? Or does FIDO2 stay outside piggy, as piggy
    FDR-0004 has it, with papi shelling to libfido2? This note recommends the
    latter for now.
  - Can piggy expose a reader-to-USB-device mapping, to make the
    "same physical device" check positive instead of "exactly one key
    plugged in"?
  - Should piggy FDR-0004's LUKS flow and this flow share a FIDO2-PIN-setup
    step?

## 8. Questions for the operator

1. **"Same PIN for both tiers":** does that mean (a) tier 1 uses no PIN, tier 2
   uses the FIDO2 PIN, and there is one FIDO2 PIN per card? Or (b) the FIDO2 PIN
   is set to the same value as the PIV PIN? With (b), enroll could prompt once
   and set both, at the cost of one secret guarding two applets.
2. Does a PIV sign-challenge session (§5.2, PIN `once` + touch `cached`) also
   satisfy tier 2, or only tier 1, or neither? Is PIV policy UV-equivalent?
   UNVERIFIED.
3. **`--add-webauthn` on an already-published card:** may the card's own
   published 9A serve as the attestation key, so that only one card is needed?
   Or must a *second* trusted card attest, as in v1?
4. **signCount:** accept that it is not enforced (the site is stateless), or
   allow a best-effort count in tmp JSON?
5. **Tier-1 threat model:** anyone who finds the key can read tier-1 pages. Is
   that acceptable for the documents intended there?
6. Should a FIDO2 attestation check also run (pin Yubico's root, check the
   packed chain and the AAGUID allowlist) as "genuine YubiKey 5" assurance? It
   does not bind the credential to PIV.
7. Is the browser registration fallback wanted at all, or is CLI-only enough?
8. The actual PIN count is the new card's PIV PIN, the FIDO2 PIN (twice if it is
   being set), the trusted card's PIV PIN, plus an optional tier-2 self-check.
   Is that acceptable for "one sitting"?
9. **Origins:** only `https://linenisgreat.com`, or subdomains too?

## 9. First things to check when a card is available (UNVERIFIED today)

- `fido2-cred -M -v -c 2` on a YubiKey 5 with a PIN set reports credProtect 2
  in authData.
- `fido2-assert -G -t up=true -t uv=false` with the credential id succeeds,
  without a PIN, on a PIN-protected key (credProtect 2).
- A browser on a second device, with `allowCredentials=[id]`,
  `userVerification:"discouraged"`, asks only for a touch. With `"required"` it
  asks for the PIN, and the server sees UV.
- The `fido2-token -I` output carries the AAGUID and `alwaysUv`.
