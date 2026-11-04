# One enrollment per card: `papi enroll` provisions PIV and a WebAuthn credential (amarbel-llc/circus#414)

Question (amarbel-llc/circus#414): the operator wants some linenisgreat.com pages
gated by a WebAuthn assertion from the same YubiKey PAPI already knows as their
card, so that personal "in case of emergency" travel documents can be read from
any device that has WebAuthn and the key. How should `papi enroll` (PIV card
init) and the WebAuthn credential stay in step, so there is one thing to
provision per card? This is a design note plus a card-free spike. No card was
used and nothing was deployed.

Operator decisions (2026-11-04), taken as given here: one command in one sitting
(the brief said two PIN prompts are fine; v1 actually needs 3–7, accepted
under Q8, with a one-prompt design in §10). Two tiers on the FIDO2 side: **tier 1** gates data on
a touch (user presence, UP), **tier 2** on a touch plus the PIN (user
verification, UV), and both tiers use the same PIN. The rpId is `linenisgreat.com`.
Credential public keys are published in the served document, like the 9A/9D
keys. A lost key is removed by a deploy from another trusted card, and a spare is
enrolled. Enroll hosts are Linux (twerk, nikulin, maybe flic; confirmed
2026-11-04). YubiKey 5 series only. Direction "option D": `papi enroll` runs PIV
init, then a CTAP FIDO2 phase, and writes one receipt. Browser registration is
a later fallback; the CLI comes first (§8 Q7).

Further answers (2026-11-04, relayed by circus/eager-holly/clarabell) are
recorded in §8: "same PIN" means the FIDO2 PIN is set equal to the PIV PIN
(Q1); a PIV session also satisfies tier 2 (Q2); the tier-1 risk is accepted
(Q5); browser fallback later (Q7). The operator then ruled on the rest: a
second trusted card attests `--add-webauthn` (Q3); signCount and the
attestation chain are not enforced and are flagged for a later security audit
(Q4, Q6); v1 keeps its PIN prompts (Q8, §9); origin `https://linenisgreat.com`
only (Q9); D1–D3 kept.

**Status:** implementation — the enroll FIDO2 phase and the server side —
waits for the operator's go and the remaining blocker in §10 (the `-P`
command-line exposure). The later one-prompt
change takes option B (§10).
Only the card-free spike (§5) exists.

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

The tiers are a per-page assertion requirement, not separate credentials. A
tier-1 page asks for `userVerification: "discouraged"`, and the server requires
only UP. A tier-2 page asks for `"required"`, and the server requires UP and UV.
The UV bit is signed by the authenticator, so the server can enforce tier 2
against the same credential. The spike (`internal/0/webauthn`) implements and
tests exactly this verifier logic: `VerifyAssertion` always requires UP and
returns the `Assurance` the assertion proves (`AssuranceTouch` or
`AssurancePIN`), and the caller gates on `got >= required`.

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
  the piggy repo for fido, ctap and webauthn finds only reader
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
  `fido2-cred(1)` CAVEATS). The spike requires `attStmt` to be present but
  neither keeps nor verifies it; the receipt's `registration.att_stmt` evidence
  is built by the enroll phase from `fido2-cred`'s output. The spike keeps what
  the block above needs from authData: `AttestedCredential.COSEKey` (the
  byte-exact `public_key`), `AAGUID` (`aaguid`), `CredentialID`, and
  `AuthenticatorData.CredProtect` (`cred_protect`).
- **No PIN is recorded.** Q1's answer (FIDO2 PIN = PIV PIN, §8) changes nothing
  in the receipt: the block names neither PIN, and nothing in it depends on
  their values.
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
4. **FIDO2 PIN = PIV PIN** (operator answer, Q1). The FIDO2 PIN is set to the
   same string as the new card's PIV PIN, so the operator remembers one PIN per
   card. The cost is accepted with the answer: a leak of one is a leak of both,
   so one secret guards two applets. The FIDO2 phase does not hold a PIN
   (libfido2 prompts on the tty, VERIFIED `fido2-cred(1)`; papi's existing
   optional `--pin` is the exception, see §9), so "equal" is an instruction
   to the operator plus a check, not something papi copies:
   - **No FIDO2 PIN yet:** run `fido2-token -S`, telling the operator to type
     the PIV PIN just used in step 1. The make-credential in step 5 then asks
     for it again, so a typo in `-S` that the confirmation prompt did not catch
     shows up as a failed PIN there (and the operator fixes it with `-C`).
   - **A FIDO2 PIN exists and is already the PIV PIN:** nothing to do; step 5
     proves it.
   - **A FIDO2 PIN exists and differs** (for example from piggy FDR-0004's LUKS
     `hmac-secret` enrollment): papi stops and offers `fido2-token -C` (change
     PIN: old PIN, then the PIV PIN as the new one). It **never resets** the
     applet: a FIDO2 reset destroys every FIDO2 credential, including a LUKS
     keyslot's (from memory, UNVERIFIED). That a PIN change keeps existing
     credentials, and that a LUKS keyslot enrolled with `fido2-with-client-pin`
     then unlocks with the new PIN, is UNVERIFIED; check it on hardware before
     relying on it. If the operator declines the change, enroll aborts before
     anything is written rather than leave the card with two PINs.
   papi cannot compare the two PINs itself; whether they match is known only
   from the operator typing the PIV PIN at the FIDO2 prompt and it succeeding.
5. **Make the credential:** `fido2-cred -M -v -c 2 -i <param> <dev> es256`, with
   no `-r` (non-discoverable) and no `-h` (no hmac-secret). The input is the
   cdh, the rp id, a user name, and a random 32-byte user id; the output is fmt,
   CBOR authData, credential id, attestation signature, and x5c (VERIFIED, the
   INPUT/OUTPUT FORMAT sections of `fido2-cred(1)`; `-c` takes the decimal
   level, and `fido/param.h` defines `FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0x02`).
   **PIN prompt #2** is the FIDO2 PIN (the PIV PIN's value, Q1), plus a touch.
   papi then parses the
   output with `internal/0/webauthn`. `UnwrapByteString` handles libfido2's
   CBOR-wrapped authData; `RegistrationPolicy{RequireUV: true,
   RequireCredProtect: 2, RequireDeviceBound: true}` rejects a credential where
   UV did not happen, credProtect was not honoured, or the credential is
   backup-eligible.
6. **Self-check tier 1 on the hardware:**
   `fido2-assert -G -t up=true -t uv=false`, sending the new credential id and
   asking for a touch only. The resulting assertion must pass `VerifyAssertion`
   with at least `AssuranceTouch`. This turns the UNVERIFIED claim "credProtect 2 allows a UP-only
   assertion when the credential id is supplied, even with a PIN set" into
   something every enrollment proves. If it fails, the enrollment aborts before
   anything is written. A tier-2 self-check would cost another PIN prompt, so it
   is optional (`--check-uv`).
7. **Binding claim** signed by the new card's 9A, with the PIN still cached.
8. Present the **trusted card** and attest, exactly as in v1. In
   `--add-webauthn` mode a second trusted card attests too (RULED, Q3). Write
   the receipt.

§9 lists every PIN entry this phase asks for, in order.

**Browser registration fallback (later, Q7):** the operator wants the CLI path
first; this is recorded for when it is picked up. The site would serve a
`navigator.credentials.create()` page with `rp.id = linenisgreat.com`,
`residentKey: "discouraged"`, `userVerification: "required"`, and
`extensions: {credentialProtectionPolicy: "userVerificationOptionalWithCredentialIDList",
enforceCredentialProtectionPolicy: true}`. The extension input names are from
memory, UNVERIFIED. The page shows the attestationObject, and
`papi enroll --add-webauthn --from-browser <file>` builds the v2 block from it,
skipping steps 3–6. The operator answered "later, CLI first" (Q7).

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
| One credential or two? | **One.** The tier is chosen per assertion by the RP. Two credentials (tier 2 at credProtect 3) would add nothing the server cannot already enforce, because UV is a signed flag in authData. It would double what is published and revoked, and add a second make-credential prompt. | WebAuthn L3 §7.2 step 17: "If user verification was determined to be required, verify that the UV bit … is set. Otherwise, ignore the value of the UV flag." VERIFIED (clarabell fetch). The spike's `TestVerifyAssertionAssurance` shows one credential serving both tiers. |
| credProtect level | **2** (`UV_OPTIONAL_WITH_ID`). Level 3 (`UV_REQUIRED`) would make tier 1 impossible. Level 1 (`UV_OPTIONAL`) would let a non-discoverable credential be used without UV, which is the same as level 2 for our use, but level 2 is the honest declaration. | The constants are VERIFIED (`fido/param.h`: `0x01/0x02/0x03`). The level semantics (2 = usable without UV only when the credential id is in the allowList; 3 = UV always) are **UNVERIFIED**, because the CTAP text was not obtained. Enroll step 6 checks this on hardware every time. |
| Discoverable (resident)? | **No.** Assertions always send `allowCredentials` with the published ids. No resident slot is used, and level 2's "with credential ID" path is exactly the path we use. | `fido2-cred -r` / `fido2-assert -r` semantics VERIFIED (`fido2-cred(1)`, `fido2-assert(1)`). YubiKey resident slot limits: UNVERIFIED, not needed. |
| UV at registration | **Required** (`-v`). | `fido2-cred(1)` `-v`, VERIFIED. That makeCredential needs a PIN once one is set (unless `makeCredUvNotRqd`) is UNVERIFIED; it is moot because we always do UV. |
| Tier 1 assertion | Browser: `userVerification: "discouraged"`. Server: `VerifyAssertion` result `>= AssuranceTouch` (UP always required; a UV assertion also passes). | §7.2 steps 16–17, VERIFIED. That browsers send `uv=false` for "discouraged" and the YubiKey then does touch only with a PIN set is **UNVERIFIED** (hardware/browser). |
| Tier 2 assertion | Browser: `"required"`. Server: result `>= AssurancePIN` (UP and UV). | §7.2 step 17, VERIFIED. |
| Same PIN for both | Tier 1 uses no PIN; tier 2 uses the FIDO2 PIN, which enroll sets **equal to the PIV PIN** (operator, Q1, 2026-11-04). A leak of one is a leak of both. | FIDO2 and PIV PINs are separate applet secrets: piggy FDR-0004, VERIFIED (R). Keeping them equal is policy, set in §3 step 4. |
| hmac-secret / largeBlob | Not used. | Only signatures are needed. |
| signCount | The verifier enforces it when a count is supplied. The site is stateless (git is the durable state, and only challenges and sessions live in tmp JSON), so it **cannot track counts durably**. RULED (Q4): not enforced; flagged for a later security audit. | §7.2 step 22: "a signal, but not proof … RP-specific", VERIFIED. |
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

**Tier groups on the session:** a session carries one group per assurance
level it reaches, so the groups follow the `Assurance` ordering:

| Session minted by | `Assurance` | Groups |
|---|---|---|
| WebAuthn assertion, UP only | `AssuranceTouch` | `authenticated`, `assurance-touch` |
| WebAuthn assertion, UP + UV | `AssurancePIN` | `authenticated`, `assurance-touch`, `assurance-pin` |
| PIV sign-challenge (§5.2, PIN `once` + touch `cached`) | `AssurancePIN` (operator, Q2, 2026-11-04) | `authenticated`, `assurance-touch`, `assurance-pin` |

So `assurance-pin` is granted by either a UV WebAuthn assertion or a PIV
sign-challenge session. A tier-1 page is `visibility: "private", acl:
["assurance-touch"]`, and a tier-2 page uses `acl: ["assurance-pin"]`. This
needs no change to §2 projection, only new group sources in §3 and §5. Which
documents go in each tier is the operator's choice, made later (Q5).

## 5. The spike: `internal/0/webauthn` (VERIFIED by tests)

`internal/0/webauthn` is stdlib only: no new go.mod dependency, no cgo, and no
gomod2nix change. It sits in `internal/0` because it imports nothing internal
(the dagnabit tier rule). Contents:

- `cbor.go`: a strict CBOR subset decoder (major types 0–5 with definite
  lengths, plus false/true/null). It rejects tags, floats, indefinite lengths,
  duplicate keys, int64 overflow, length overflow, and nesting deeper than 8,
  all as `ErrMalformed`. It also provides `UnwrapByteString` for libfido2's
  tool output. `fxamacker/cbor` is the alternative if the decoder ever needs
  more. It is not needed now.
- `webauthn.go`: `ParseAuthenticatorData` (flags, signCount, attested
  credential, an ES256/P-256 COSE key checked on-curve, the credProtect
  extension output as `CredProtect`, and rejection of trailing bytes);
  `NewRegistration(fmt, authData)` (the CLI path: fido2-cred(1) prints fmt
  and authData as separate lines) and `ParseAttestationObject` (the browser
  path, which calls it); and `Registration.Credential` with a
  `RegistrationPolicy` (enroll-only checks: UV at registration, credProtect
  level, device-bound). Assertions go through `VerifyAssertion` (an ECDSA
  signature over authData ‖ cdh, signCount; on any error it returns zero
  authenticator data, since nothing in it is authenticated yet),
  `VerifyBrowserAssertion`, and `CheckClientDataJSON` (§7.2 steps 10–13:
  type, challenge, exact origin allowlist, crossOrigin; parsed strictly, so
  duplicate keys and case variants of those four keys are rejected). Both
  ceremonies share one check — rpIdHash, the
  BE/BS rule, and UP, which is always required — that yields the `Assurance`
  (`AssuranceTouch` or `AssurancePIN`) `VerifyAssertion` returns; callers gate
  on `got >= required`, and no setting turns the UP check off.
- Tests were written first and confirmed failing before any code existed. The
  fixtures are deterministic: a fixed P-256 scalar, with authData and a "none"
  attestationObject built in the test. One vector is published: **libfido2
  1.17.0 `regress/assert.c`**, a valid ES256 assertion (`es256_pk`, `cdh`,
  `authdata`, `sig`, rp `localhost`, flags 0x00, signCount 3). Its signature
  verifies (checked directly through the unexported signature helper), and
  `VerifyAssertion` correctly rejects it with `ErrUserNotPresent`, because it
  has no UP. I found no WebAuthn L3 test-vector appendix; clarabell could not confirm
  one either.
- Not in the spike: verifying packed attestation, the CTAP device I/O, and the
  receipt v2 types. These are the next step, and wait for the operator's go.

## 6. Amendments needed (listed, not written)

**FDR-0001** (`docs/features/0001-papi-new-yubikey-enrollment.md`):

- the receipt-v2 schema and its `webauthn` block;
- the FIDO2 phase and its order (trusted card last);
- `--add-webauthn` (and, later, `--from-browser`);
- the FIDO2-PIN-equals-PIV-PIN rule and the differing-PIN path (§3 step 4);
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
  - anyone holding the key passes tier 1 (accepted by the operator, Q5:
    tier 1 holds only low-sensitivity material);
  - one PIN guards both the PIV and FIDO2 applets (Q1);
  - a PIV sign-challenge session counts as tier 2 (Q2);
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
  - session tier groups, including `assurance-pin` on PIV sign-challenge
    sessions (Q2);
  - gated sitemap and page nodes;
  - the front-end `navigator.credentials.get()` page, with `allowCredentials`
    and a per-tier `userVerification`;
  - splicing `webauthn_credentials[]` into papi.json;
  - extending `just papi-verify-keys` to verify v2 receipts;
  - signCount is not enforced (RULED, Q4); do not build count tracking.
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

## 8. Operator questions: answered and defaulted

Answers and rulings were relayed by circus/eager-holly/clarabell on
2026-11-04. Every question is now answered or ruled. The operator also kept
three design choices as written: D1 credProtect level 2 (§2), D2 a
non-discoverable credential (§3 step 5), D3 ES256 only, one credential per
card. The one-prompt direction is B (§10). Implementation waits for the
operator's go and the remaining blocker listed in §10.

**Flagged for a later security audit** (operator, 2026-11-04): Q4 (signCount
not enforced) and Q6 (attestation chain not verified) are deliberate gaps, to
be reviewed by a later audit session (a fable-model session). They are not to
be implemented now; the receipt keeps the attestation statement so the Q6
check can run over existing receipts.

1. **"Same PIN for both tiers"** — ANSWERED 2026-11-04: the FIDO2 PIN is set
   **equal to the PIV PIN**; enroll sets both to the same string (§3 step 4,
   including the existing-and-different case). Cost, accepted: a leak of one is
   a leak of both. Tier 1 still uses no PIN.
2. **Does a PIV sign-challenge session satisfy tier 2?** — ANSWERED 2026-11-04:
   **yes.** A PIV session is treated as `AssurancePIN` and carries
   `assurance-pin` (§4, tier groups).
3. **`--add-webauthn` on an already-published card: may its own published 9A
   attest?** — RULED 2026-11-04: **no; a second trusted card attests, as in
   v1.** Reason: it keeps the one trust rule every receipt
   already follows (a *different*, already-trusted card authorizes it), so one
   compromised card plus its PIN cannot extend its own reach. Flipping it saves
   carrying a second card for `--add-webauthn`, at the cost of a new
   deploy-gate rule that accepts self-attested v2 receipts, and of letting
   whoever holds that card and its PIN publish a credential they control
   (still subject to the deploy).
4. **signCount** — RULED 2026-11-04: **not enforced; flagged for the later
   security audit.** The server
   passes a stored count of 0, which `VerifyAssertion` treats as "not
   tracked"; `Registration.Credential` likewise records 0 (a YubiKey's
   counter is global across credentials anyway). Reason: the site is stateless (git is the durable state), and a
   count kept only in tmp JSON resets whenever tmp does, so it would detect a
   clone only within one tmp lifetime while looking like a guarantee.
   Flipping it to a best-effort tmp count costs a state write on every
   assertion and a documented reset behaviour; it buys clone detection between
   resets.
5. **Tier-1 threat model** (whoever finds the key can read tier-1 pages) —
   ANSWERED 2026-11-04: **acceptable.** Tier 1 holds only low-sensitivity
   material; the operator chooses the documents for each tier later.
6. **FIDO2 attestation check (Yubico root, packed chain, AAGUID)** —
   RULED 2026-11-04: **not verified; flagged for the later security audit.** Enroll keeps the preflight
   AAGUID allowlist (a self-reported value from `fido2-token -I`) and records
   the attestation statement in the receipt's `registration` evidence, so a
   chain check can be added later and run against existing receipts. Reason:
   it proves "a genuine YubiKey model X", not "the card with PIV GUID G", so it
   adds no trust to the binding papi relies on. Flipping it costs pinning and
   maintaining Yubico's attestation root and an X.509 chain check in papi
   (stdlib `crypto/x509` suffices; no new dependency); it buys rejection of a
   non-YubiKey authenticator that lies about its AAGUID.
7. **Browser registration fallback** — ANSWERED 2026-11-04: **later; CLI
   first.**
8. **PIN count** (§9 lists the entries in order: 3–7). — RULED 2026-11-04:
   **v1 accepts the current prompts and adds no PIN handling; getting to one
   prompt is a wanted later improvement**, designed in §10; the operator
   chose option B.
9. **Origins** — RULED 2026-11-04: **only `https://linenisgreat.com`, exact
   match.** Reason: the smallest allowlist;
   `CheckClientDataJSON` matches exactly. Flipping it means listing each
   subdomain origin (the rpId stays `linenisgreat.com`); the cost is that a
   script-injection bug on any listed subdomain can then run assertion
   ceremonies for the gated pages.

## 9. PIN prompts (v1, as ruled under Q8)

Two cards take part: the **new** key and an already-**trusted** key. Each key
has two separately locked parts: the **PIV** part (the SSH, signing and
recipient keys) and the **FIDO2** part (website logins). Every prompt below
is a PIN typed by the operator, in order:

| # | Card, part | When | What it unlocks | Typings |
|---|---|---|---|---|
| 1 | new, PIV | always (in `--add-webauthn` mode: for the binding claim only) | provisioning, `self_proof` and the binding claim; 9A's PIN policy `once` keeps it for the rest of the session | 1 |
| 2 | new, FIDO2 | only if its FIDO2 PIN is not already the PIV PIN | setting the FIDO2 PIN to the PIV PIN: new + confirm if none is set; old + new + confirm if a different one is set | 0, 2 or 3 |
| 3 | new, FIDO2 | always | creating the login credential (plus a touch) | 1 |
| 4 | new, FIDO2 | always | none: the touch-only self-test asks for a touch, no PIN | 0 |
| 5 | new, FIDO2 | only with `--check-uv` | the PIN-login self-test (plus a touch) | 1 |
| 6 | trusted, PIV | always | the trusted key's attestation over the receipt | 1 |

Totals for a fresh card: **3** when the FIDO2 PIN already equals the PIV
PIN, **5** when no FIDO2 PIN is set, **6** when a different one is set, and
`--check-uv` adds 1: **3–7** in all. `--add-webauthn` has the same totals.

UNVERIFIED, to check before relying on these counts:

- That `fido2-token -S` and `-C` ask for the new PIN twice (enter, then
  confirm). This is from memory of libfido2, not its man page.
- How many entries row 1 really is on a fresh card. `piggy card init` asks
  for the new PIN twice (and the PUK likewise; see below), so row 1 is more
  than one typing there. The table counts the PIN used after init.

**Default PIN after init: answered 2026-11-04** by the read-only piggy
research session piggy/sunny-sycamore, from piggy's code and manpage, not
tested on a card, relayed by clarabell:

- A **completed** `piggy card init` does **not** keep the default PIN. It
  prompts for a new PIN twice, then changes it from the default; the PUK
  likewise (piggy `crates/piggy/src/card/engine.rs:673-692`,
  `doc/piggy.1.scd:561-569`, `601-603`). The comment at `main.go:2768` is
  true only until init completes.
- A **partly provisioned** card still has the default PIN. That happens after
  any failure in init's steps 1–5 (for example a missed touch while signing
  the 9A/9C certificate) or at the PIN prompt (declined or mismatched)
  (`engine.rs:268`, `doc/piggy.1.scd:580-583`). There is no flag to skip the
  PIN change.
- Still UNVERIFIED (per that session): whether `change_pin` enforces length or
  character limits; whether the `piggy manage` `card.init` JSON-RPC path
  behaves differently; whether the card refuses a new PIN equal to the
  default; and piggy RFC 0006's text (it was not read).

Round-2 findings from the same session (code reading only, relayed by
clarabell, 2026-11-04):

- **Even a completed init can leave the default.** piggy has no minimum PIN
  length and does not refuse the default: `pin_mgmt.rs:86-99` rejects only an
  empty PIN or one over 8 *bytes*. `card init` accepts `123456` as the new
  PIN if the operator types it; `engine.rs:706-735` checks only that the two
  entries match. So "the PIN is not the default" is not guaranteed after a
  completed init either, which is why the rule below must apply to every
  path.
- `piggy manage` `card.init` and the `card init` command share one engine, so
  the PIN steps and the state left by a partial failure are the same. They
  differ only in the frontend (JSON-RPC `secret.request`) and error codes
  (`-32050`). Whether the `jsonrpc.rs` frontend validates input is
  UNVERIFIED.
- piggy RFC 0006 does not say the default PIN gets replaced; that is stated
  only in code (`engine.rs:673`), piggy(1) and `pin_mgmt.rs:1-4`. piggy
  FDR 0006 and RFC 0007 §5.2 were not read.
- `card init` and `--allow-reprovision` start with a **blind VERIFY of the
  default PIN** (`engine.rs:629-630`), so on a card whose PIN was changed they
  use up a retry. There is no pre-check. This affects papi's
  `--allow-reprovision` path today.
- piggy does not store retry counts. The retry-counter read that uses no retry
  is described below.

So Q1 holds after a completed init only if the operator did not choose
`123456`. **Requirement for the FIDO2 phase:**
before setting a FIDO2 PIN from the PIV PIN (§3 step 4), enroll must
**refuse** if the new card's PIV PIN is still the factory default `123456`
(a partly provisioned card). It must also refuse if it cannot tell. How to
tell is open:

- Trust that the `piggy card init` papi just ran exited successfully. This
  does not cover `--new-guid` and `--add-webauthn`, which skip init.
- Ask the card directly. **Caution:** a PIV VERIFY with `123456` against a
  card whose PIN is *not* the default uses up one of its PIN retries, so a
  blind probe is unacceptable. A YubiKey 5 is believed to report "PIN is
  still default" through a metadata command that uses no retry (firmware 5.3
  and later, from memory, UNVERIFIED). piggy answered 2026-11-04
  (piggy/sunny-sycamore, read-only, from the files that session read, not a
  repo-wide search): piggy has **no** "PIN is default" read. piggy-piv's
  instruction list has no GET METADATA, and no `piggy` command, tool op or
  manage method reports PIN state. It does have a retry-counter read that
  uses no retry (`PinSession::pin_retries_remaining`, an empty VERIFY per
  SP 800-73-4 §3.2.1), but that cannot tell a default PIN from a changed one,
  and no command exposes it yet. A real check therefore needs new piggy work:
  a GET METADATA APDU plus a command surface. That would be YubiKey-only;
  whether generic PIV cards reject it cleanly is UNVERIFIED. Until then, the
  FIDO2 phase has no reliable check. A successful init does not rule out a
  chosen `123456`, and `--new-guid` and `--add-webauthn` skip init entirely.
  The options are new piggy work, or an operator decision to accept the gap.
  Short of either, enroll can only warn the operator not to use `123456`.

**Correction to earlier wording.** This note and the Q8 reply said "papi
never holds a PIN". That is true of the new FIDO2 phase as designed, but not
of papi today: `papi enroll --pin` (`main.go:2845`) and the other signing
commands (`signerFlags`, `main.go:350`) accept a PIV PIN and pass it to
`piggy sign-bytes -P <pin>` **as a command-line argument**
(`internal/bravo/enroll/card.go:60`). One flag value serves both cards, so it
only helps when the new and trusted cards share a PIN. A command-line
argument can be read by other processes on the host through
`/proc/<pid>/cmdline` while piggy runs. That is the Linux default; whether
the enroll hosts mount `/proc` with `hidepid` is UNVERIFIED. This existing
exposure is separate from v1 of this plan; a follow-up should move it to
stdin or piggy's RFC 0006 `secret.request`.

## 10. Toward one PIN prompt (later; direction for the operator to choose)

The operator wants enroll to ask for one PIN. Two limits apply to every
option:

- **The trusted key is a separate card with its own PIN.** Its prompt can
  only be shared with the new key's if both cards have the same PIN. That is
  the operator's choice per card, and it widens a single PIN leak to every
  card that shares it. Otherwise the floor is **two prompts: one per card**.
- **A fresh card is getting a new PIN.** Choosing a new PIN normally means
  typing it twice, to catch a typo before it locks the card. Dropping the
  confirmation saves a typing at the risk of a PIN the operator never meant.
  So "one prompt" on a fresh card is really "one new PIN, typed twice".

The FIDO2 typings (rows 2, 3, 5) all ask for the same value as the PIV PIN
(Q1), so removing them means something other than the operator must supply
it. The options:

**A. papi reads the PIN once and passes it on, for the run only.** papi reads
the PIN from the terminal without echo, keeps it in memory for the length of
the enroll run, and clears it on exit.
- Passing it on: to piggy, by answering piggy's RFC 0006 `secret.request`.
  papi RFC 0002 §3 item 4 already expects papi to be the responder, so this
  is the intended path. It must never go on a command line. To libfido2, the
  `fido2-*` command-line tools read the PIN from the terminal themselves.
  Whether they accept it any other way is UNVERIFIED. So papi would need one
  of: libfido2 through cgo, a pure-Go CTAP2 client over hidraw (CTAPHID
  framing plus the PIN protocol's key agreement, a sizeable new body of
  code), or driving `fido2-*` through a pseudo-terminal (fragile).
- Prompts left: 1 per card (2 typings on a fresh card); 1 in all only if the
  trusted key has the same PIN.
- Secret papi holds: the PIN, in papi's memory, for the length of the run
  (minutes). A crash dump or a debugger attached to papi as the same user
  could read it; Go cannot reliably wipe memory, so "cleared" is
  best-effort.
- What it takes: papi as an RFC 0006 frontend (moving off `piggy sign-bytes`
  and `card init` subprocesses), plus one of the three FIDO2 transports
  above.

**B. A helper process holds it (an agent or pinentry-style holder) for the
run.** A separate process, such as a piggy agent mode or a small pinentry,
takes the PIN once, answers each card request during the run, then exits.
papi never sees the PIN.
- Prompts left: the same as A.
- Secret papi holds: none. The helper holds it for the run.
- What it takes: the helper must also drive FIDO2. That puts a CTAP
  primitive in piggy, which is the open piggy question in §7 ("piggy mints
  keys and signs bytes", FDR 0001), or makes it a new tool. It is mostly
  piggy work, and it keeps papi's "never holds a PIN" rule.

**C. Set the FIDO2 PIN equal to the PIV PIN automatically.** This is not an
option on its own: setting it needs the value, so it rides on A or B. With
either, it removes row 2 entirely (0 typings instead of 2–3). Without them,
the closest is a separate one-time `papi`/piggy "align PINs" step done
before enroll, which moves the typings rather than removing them.

**D. Reuse the PIV PIN cache instead of retyping.** The card already keeps
9A's PIN for its session (policy `once`), which is why row 1 is asked once.
The FIDO2 part keeps its own lock and does not share that cache: row 3 needs
the FIDO2 PIN through the CTAP PIN protocol. That a YubiKey 5 offers no
cross-applet PIN sharing is UNVERIFIED, from memory. So D cannot remove the
FIDO2 rows; it only confirms that row 1 stays at one.

**E. Make the trusted key's step later or optional.** This is not a PIN
saving as such: the trusted key's signature is the trust rule (Q3). It is
listed only to rule it out.

**Chosen (operator, 2026-11-04, relayed by circus/eager-holly/clarabell):
B.** A helper holds the PIN for the run; papi holds nothing. Not implemented
yet.

**Blockers before implementation** (of this plan, not only of B):

1. ~~**Default PIN after `piggy card init`**~~ — **answered** 2026-11-04
   (§9): a completed init changes the PIN; a partly provisioned card keeps
   the default, so the FIDO2 phase must refuse it (§9, with the unverified
   parts listed there). piggy cannot currently check for a default PIN, so
   that check is an **open operator decision**: file the piggy work (a GET
   METADATA read plus a surface), or accept a warning in its place.
2. **Remaining blocker: the `-P <pin>` command-line exposure** (§9): `papi enroll --pin` and the
   other signing commands pass the PIV PIN to `piggy sign-bytes` in argv. That
   follow-up should land, or be explicitly deferred, before enroll grows a
   FIDO2 phase.

The recommendation as written before the choice: B if the operator wants papi to stay PIN-free (it is the
cleaner fit with the layering rule and makes the FIDO2 primitive piggy's,
which §7 already asks about). A if a papi-only change is wanted sooner:
first switch the PIV side to RFC 0006 `secret.request` (this also fixes the
`-P` command-line exposure above), then add a FIDO2 transport. Both get to
one prompt per card (two typings on a fresh card), and to one prompt in all
only if the operator also gives the trusted key the same PIN.

## 11. First things to check when a card is available (UNVERIFIED today)

- `fido2-cred -M -v -c 2` on a YubiKey 5 with a PIN set reports credProtect 2
  in authData.
- `fido2-assert -G -t up=true -t uv=false` with the credential id succeeds,
  without a PIN, on a PIN-protected key (credProtect 2).
- A browser on a second device, with `allowCredentials=[id]`,
  `userVerification:"discouraged"`, asks only for a touch. With `"required"` it
  asks for the PIN, and the server sees UV.
- The `fido2-token -I` output carries the AAGUID and `alwaysUv`.
- `fido2-token -C` (changing an existing FIDO2 PIN to the PIV PIN, §3 step 4)
  keeps existing FIDO2 credentials, and a LUKS keyslot enrolled with a client
  PIN then unlocks with the new PIN.
