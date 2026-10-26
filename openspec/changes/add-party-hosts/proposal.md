# add-party-hosts

> **ACTIVE BUILD**

**Rigor:** architecture

Steer residue is `steer.md` in this change (2026-10-25). Protocol
blast. Advise reader is Astra before act.

## Campaign authority

User instruction 2026-10-25: "activate and run". Grant covers
`add-party-hosts` only. Bounds: hostname-per-party, operator registry,
dual dCBOR and X.509 holder certificate, local-group CA whose HTTPS
certificate is the group entry, boundary slot reserved and rejected
when present. Out of scope stays the proposal list (no core OP, no
URN-grant acceptance of WebAuthn, no keyspace kind, no reputation
evaluator).

## Preparation

2026-10-25. Upstream: no party standard. Anchors:
`docs/standards/identikey-auth-challenge-v1.md` §1 (passkeys are not
this proof) and §5 (fingerprint), `docs/standards/identikey-oidc-urn-grant-v1.md`
§1 and §7 (WebAuthn assertion is not the grant),
`docs/standards/identikey-auth-platform-backends.md` (resident key
required, authenticator attachment unset). Outcome: still valid at first preparation.
Authority: the grant above.

2026-10-25 amend after Astra send-back, then a second amend after
`reviews/2026-10-25-advise-2.md`. Contract revised, not re-planned.
Bounds unchanged. Fresh advise is owed before act. The reconciled
contract is `design.md` and `specs/identikey-party/spec.md`.

## Why

One IdentiKey endpoint (the deployment behind
`iro.id.vm.worldtree.network`) authenticates people with passkeys and
then speaks OIDC to ordinary clients. Password managers file a passkey
under the WebAuthn relying party id, which is a hostname. A single host
and every `localhost` port therefore share one passkey pile.
1Password cannot tell those parties apart.

The endpoint can still be one process. Each party gets its own
hostname, so each party gets its own passkey. The same hostname is the
HTTPS entry of a local group, and the group CA issues a dual
certificate (dCBOR and X.509) for the holder who registered there.

## What

- ADD capability `identikey-party`.
- Living file after act: `docs/standards/identikey-party-v1.md`.
  This repo's spec surface is `docs/standards/`. This packet lives
  under `openspec/changes/` so advise can see a banner. Fold does not
  create `openspec/specs/identikey-party/`.
- Party host grammar, operator registry, WebAuthn ceremony parameters,
  local-group CA, host HTTPS entry certificate, dual holder certificate,
  and the reserved boundary slot.
- A pointer, during act, from the OIDC URN grant's "what this spec is
  not" section to this standard. The grant's rejection of WebAuthn
  assertions stays.

Capabilities: `identikey-party` (ADDED). `identikey-auth-challenge`,
`identikey-keyspace`, and `identikey-capability` are not modified.

## Impact

- Capabilities: ADDED `identikey-party`
- ADRs: none

## User journey & surfaces

No new UI because this change is a wire standard. The surfaces it
names already exist: a party origin in the browser, a passkey in the
password manager, an HTTPS connection into the local group, and an
IdentiKey verifier that already checks a challenge response.

Working: an operator-registered party serves a ceremony at its host.
The password manager stores a passkey under that host. The group CA
issues the host certificate and the holder's dual certificate.
Failed: an unknown host gets no ceremony and no certificate. A
certificate that carries a boundary, or a chain that does not end at
the configured local group anchor, fails verification.
Empty: a deployment with no registered parties serves no party origin.
Off: a verifier with no local group anchor configured does not accept
party certificates.

## Out of scope

- identikey-core OP, registry storage, and ceremony HTTP routes.
  Product work, tracked when a core change opens.
- Evaluating reputation boundaries or smart-contract policy. The slot
  is reserved here and rejected when present.
- Trusting any CA above the configured local group anchor.
- A WebAuthn assertion as an OIDC URN grant (`identikey-oidc-urn-grant-v1` §1 and §7).
- New `identikey-log` kinds, keyspace ops, or an OIDC `guilds` claim.
- Filled cryptographic fixtures. The standard names the vectors act must hook.
