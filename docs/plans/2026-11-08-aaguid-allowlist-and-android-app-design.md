# Design notes: per-instance AAGUID allowlist (papi#92) and a papi Android app (papi#93)

Status: design only. No code, no RFC edit, nothing deployed. Written for the
operator, who is card-less and XMPP-only; the browser fallback and the server
side stay deferred (coordinator, 2026-11-08).

Labels: **O** = observed in the repo or a record read this session. **I** =
inference. **U** = an outside fact not verified here (no web fetch, no device).
Sources read: `internal/bravo/enroll/webauthn_phase.go`, plan
`2026-11-04-papi-enroll-webauthn.md`, the RFC-0001 Amendment 28 draft,
barker `docs/features/0001-operator-acts-from-the-phone.md` (a part, via
search and targeted reads; it is 1,110 lines), circus
`docs/features/0046-android-apps-and-tailnet-app-store.md` (all).

---

## Part 1. papi#92: a per-instance AAGUID allowlist

### What exists (O)

- `enroll.DefaultAAGUIDs` is a compiled-in list. It was empty when this note
  was written; it now holds one entry observed on the operator's key (see the
  webauthn plan §12, check 1), because no verifiable Yubico source could be
  read (`webauthn_phase.go:111-125`).
- `--webauthn-aaguid` adds a value at run time. The effective list passed to
  the phase is the default plus the flag values, normalized (lowercase, no
  dashes) (`webauthn_phase.go:123-127`, `194-197`).
- The check is in `preflight`, on the client at enroll time. An AAGUID not on
  the list is refused and the message names the value seen, so the operator
  can pass it back (`webauthn_phase.go:199-200`).
- The AAGUID is **self-reported**: papi keeps the packed attestation but does
  not verify it (plan Q6, flagged for the security audit). So the list stops an
  operator mistake (the wrong key plugged in), not a device that lies (I, from
  plan lines 515-524).

### Who needs the list (I)

| consumer | when | needs the list for |
| --- | --- | --- |
| `papi enroll` (client) | at enroll, before making a credential | refusing a model |
| the deploy that publishes the credential (server side, deferred) | when the credential is added to the source document | the same refusal, as a second check |
| `papi verify-receipt` / `inspect` | after the fact | showing which list admitted the card; not enforcing |

Only the first exists. The other two come with the server side.

### Where the list lives: options

| option | what it is | for | against |
| --- | --- | --- | --- |
| **A. Client config only** | a file or flag on the operator's machine | nothing to serve; works offline; no new trust in the server | every machine configures it; no single answer for "what does this instance admit"; same as `--webauthn-aaguid` with a file |
| **B. Served in the instance's signed source document (recommended)** | a public member of the PAPI source document, e.g. `piggy.webauthn.aaguids[]`, projected like other sections (FDR 0011) and covered by the §10 document signature | one place per instance; changes by deploy, no papi release; clients already fetch and verify the document; the same document already says which cards the instance trusts (`piggy-ids`) | a new RFC member (rides Amendment 28); needs a fetch at enroll time |
| C. A separate signed side document | its own path and signature | independent of the main document | a second signed artifact for a short list; more to pin |

Recommendation: **B**, with A's file kept only as the existing flag. Entry
shape (proposed, I):

    { "aaguid": "<32 hex>", "label": "YubiKey 5 NFC",
      "source": "<url the value was copied from>", "checked": "<date>" }

`source` and `checked` repeat the rule already set for `DefaultAAGUIDs`: no
value without a citation and a date, in a reviewed change.

### Fetch and pin

- **Fetch**: enroll already talks to the domain (`RequireAddable` reads
  `/papi/piggy-ids`, O). It would read the document (or the projected
  `GET /papi/webauthn-policy`, name not decided) and verify the §10
  signature against the domain's slot-9A key, the same way other clients do.
  RFC-0001 §14 and §15 already describe pin-on-first-fetch (TOFU) of the
  signing key (O, grep lines 1395 and 1493).
- **Pin**: no client-side persistent pin is needed. The list is read fresh at
  each enroll. What is pinned is the **evidence**: the receipt records which
  list admitted the card, as a digest of the canonical (JCS) list plus the
  domain it came from. `verify-receipt` can then show "admitted under list
  sha256:…". This is an optional receipt-v2 member (open question 3).
- **Offline or unreachable**: fail closed for the instance list, but still
  allow the default plus `--webauthn-aaguid`. That keeps an offline enroll
  possible when the operator names the model explicitly (I).

### Precedence

Effective allow set = built-in default ∪ instance list ∪ `--webauthn-aaguid`.
Rules:

1. **Union, not override.** The instance widens the default; the flag widens
   it for one run. No layer silently removes another's entry.
2. **An instance `deny` list wins over everything**, including the flag. This
   is how an instance retires a model found weak without a papi release. The
   flag cannot override it (otherwise it is a footgun). The refusal names the
   deny entry's `reason`.
3. **Empty default stays valid.** With nothing in any layer, behaviour is
   today's: refuse, name the AAGUID seen, require `--webauthn-aaguid`.
   Seeding the default is still blocked on someone with a browser copying
   Yubico's published list in a reviewed commit (coordinator ruling,
   2026-11-08); the operator's own key's AAGUID from `fido2-token -I` at
   hardware check 1 can seed the first entry (plan §12).
4. **A wrong AAGUID in the instance list is a trust decision of the instance,**
   the same as the instance's `piggy-ids`. The server being compromised
   widens the allow set, but the AAGUID is self-reported anyway, so this adds
   little beyond the existing Q6 gap (I).

### Sequencing

Depends on Amendment 28 (the `piggy.webauthn_credentials[]` member and the
deploy splice), so it is server-side work and stays deferred. Client work after
that is small: fetch, verify, union, and the optional receipt member.

### Open questions for the operator (papi#92)

1. **Is "instance list widens, deny list narrows" the intended precedence?**
   Or should an instance be able to make its list exclusive (ignoring the
   built-in default)? Exclusive is stricter but means a papi release cannot
   add a model for instances that chose it.
2. **Unreachable instance**: fail closed on the instance list (proposed) or
   fall back to default plus flag with a warning?
3. **Record the admitting list in the receipt?** Proposed as an optional v2
   member (no schema bump); say if you want a v3 instead.
4. **Document member or separate path?** Proposed member plus projection;
   option C costs a second signature.
5. **Who maintains an instance list** and with what review? The built-in one
   is a reviewed commit; the instance one is a deploy of the source document.

---

## Part 2. papi#93: a papi Android app

### What `papi enroll` does today (O), step by step

1. **Provision / PIV state**: provisioning a blank card and reading PIV
   state go through `piggy` subprocesses (`enroll/provision.go`, `card.go`).
2. **New card's slot-9A key signs a binding claim** (`piggy manage`
   `sign_bytes`, PIN through `secret.request`).
3. **Trusted card attests** over the receipt's JCS-canonical bytes
   (`PiggySignBytesSigner`).
4. **FIDO2 phase** (`--webauthn`): set the FIDO2 PIN, make one non-discoverable
   credProtect-2 ES256 credential, prove a touch-only assertion, optionally a
   PIN assertion. Runs through `libfido2`'s CLI tools, not a library, and
   needs exactly one card and one FIDO device attached.
5. **Receipt v2** is built and the new card's 9A key signs the WebAuthn
   binding claim; the operator publishes through a deploy.

### What could run on a phone

| step | on a phone? | what it takes |
| --- | --- | --- |
| PIV reads, provisioning APDUs | yes (I) | barker already chose an in-app card agent speaking PIV over NFC (Android IsoDep) or USB-C (CCID), using piggy-piv's `ApduTransport` seam and an OpenSSL-free build (O, barker FDR 0001 Decision 1, option A) |
| slot-9A `sign_bytes`, trusted-card attestation | yes (I) | the same transport; the PIN on the app's own PIN pad, not the system keyboard (O, barker Decision 1 step 3) |
| default-PIN check | yes once piggy can read it (I) | linenisgreat/piggy#353 (GET METADATA) lands in the Rust card code, which the phone links |
| FIDO2 credential and assertions | **hard** | needs a CTAP2 client in the app. `libfido2` is a C library and papi shells out to its tools (O), which Android does not offer. Options: Yubico's Android SDK (barker rates it a fallback for transport only, licence and API unverified, O); a Rust CTAP2 client; or Android's platform FIDO2 API. The platform API ties a credential to an app and RP through Digital Asset Links (U), while papi makes a credential for `linenisgreat.com` with its own client-data hash (O, plan §4), so it is probably unsuitable (I) |
| receipt build and verify | yes (I) | papi's Go code does not run on Android as is. Choices: the existing js/wasm client core (FDR 0007, O) in a WebView; gomobile; or a Rust port. Which is cheapest is a measurement, not a guess |
| publishing (deploy of the source document) | no | stays on a workstation or fleet host; the phone produces a receipt and hands it over (I) |

### Tap count and sequencing (I, unmeasured)

Today's enroll needs two cards in sequence (trusted, then new) and refuses
unless exactly one is attached for the FIDO2 phase. On a phone each is a tap:
roughly trusted-card attest, new-card 9A sign (PIN), FIDO2 set PIN, make
credential (PIN, touch), touch-only assertion, optional PIN assertion. That is
plausibly six to eight taps, not a measured number. Barker's own NFC flow
already costs two taps per act (attest, then PIN and sign) because a positive
attestation may not cross card removal (O, Decision 1 steps 2 and 4).

### The blocking unknown (O)

Barker's open question **P5**: does a YubiKey treat an NFC tap as satisfying a
touch policy, and does attestation answer over NFC? It is unresolved and
scheduled for barker's phase 1 hand pass with a throwaway card. papi's
touch-only tier depends on the same kind of fact for FIDO2 user presence over
NFC (U). Neither project should start phone UI before P5 is answered. USB-C
removes the question but needs a card and an OTG port.

### Link to barker FDR 0001 (O/I)

- **Shared pieces**: `barker-core` (Rust: act protocol, RFC 0012 checks, sshsig,
  attestation-bundle verification) and the card transport (Kotlin implementing
  piggy-piv's trait, planned to be rewritten as a Flutter plugin if barker goes
  Dart) are the natural shared base. A papi app would add a CTAP2 client and
  the receipt logic, not a new transport.
- **Slot mismatch (I)**: barker's operator acts use slot **9C** (PIN-always,
  touch-always) under RFC 0012; papi's trusted-card attestation and binding
  claim use slot **9A**. One card holds both, but they are different keys with
  different policies, so a papi approval is not a barker act as is.
- **Barker as the approval surface (I)**: the least new work is for barker to
  sign "approve this enrollment" as an operator act while a workstation does
  the enrollment. That does not need papi on the phone, but it is no help when
  the operator has no workstation, which is the case the issue describes.

### Three shapes, smallest first (I)

1. **Approve-only**: barker shows the enrollment and the trusted card signs
   over XMPP; the desktop `papi enroll` does the rest. Needs a papi act
   namespace in barker's registry. No CTAP2.
2. **Add-WebAuthn-only** (the phone version of `--add-webauthn`): the card is
   already enrolled; the phone does the FIDO2 phase and emits the
   `webauthn` block, still needing a second card or a prior receipt for the
   trusted attestation. This is the smallest piece that needs CTAP2.
3. **Full enroll on the phone**: all of the table above. The largest, and the
   one that depends on P5, on the CTAP2 client, and on the receipt-logic
   decision.

### Distribution (O, circus FDR 0046; proposed, not built)

The app would be another consumer of the tailnet app store: a Nix-built
**unsigned** APK, a test channel (an `.test` applicationId, test key at rest
on krone, unattended), and a stable channel signed at an attended
`circus app release` with the card; phones use the F-Droid client against
`apps.starbrandshoes.com`, repository fingerprint pinned. Built on nikulin,
never on flic. Phase 1 of FDR 0046 (the pigsty tracer bullet) is not done, so
nothing here can ship yet. An app that creates trust anchors for the operator
should be on the **stable** channel only after the attended signing step; the
test channel is for development.

### Decision points (I)

- **Own app or a screen in barker?** Shared Rust core and transport argue for
  one codebase; keeping the enrollment tool out of the chat client argues for
  two apps over a shared crate. Barker's phase 6 (keep the Java fork, rewrite
  in Dart, or add a Dart companion) decides the UI language, so deciding now
  would be premature.
- **Whose lane is each piece**: card transport and `barker-core` are barker's;
  the store and signing are circus's (FDR 0046); papi owns the receipt format,
  the enroll logic and the WebAuthn verification. Cross-repo asks go to those
  sessions, not from here.

### Open questions for the operator (papi#93)

1. **Which shape first** (approve-only, add-WebAuthn-only, or full enroll)?
   Recommend approve-only, because it needs no CTAP2 and no P5 answer beyond
   barker's own.
2. **Own app, or a papi screen inside barker?** Recommend deciding after barker
   phase 6.
3. **Does the phone get the FIDO2 phase at all?** Today it needs a CTAP2
   client written or adopted; is a hardware key plugged into a workstation an
   acceptable fallback for that one phase?
4. **Trusted-card slot**: is a papi attestation to be a 9A signature as today,
   or should it become a 9C operator act so barker's flow applies unchanged?
   That changes the receipt's trust story and needs an RFC amendment.
5. **USB-C or NFC first**, given P5 is open?
6. **Is the phone ever the only device** during an enroll (no workstation)? If
   not, shape 1 or 2 is enough and the receipt-logic question goes away.

### Not done here

No measurement of tap counts, no NFC test, no check of any Android API, no
read of the full barker record. Every **U** above needs a source before it
guides a choice.
