# add-party-sign-in

> **ACTIVE BUILD**

**Rigor:** architecture

Steer residue is `steer.md` (2026-10-26). Protocol blast. Advise reader
is Astra before act. Extracted from bead ikp-hdj.

## Campaign authority

User instruction 2026-10-26: "activate and run" on pinned intention
`use-party-passkey`. Grant covers `add-party-sign-in` (ikp-hdj): amend
`identikey-party-v1` with sign-in via `credentials.get`, an explicit
add, `excludeCredentials`, and `signalAllAcceptedCredentials`. It does
not reopen host grammar, the dual certificate, the local-group anchor,
or the URN grant. ikp-cgp stays a human check of two production hosts.
Do not check it from this grant.

## Preparation

2026-10-26. Upstream: `docs/standards/identikey-party-v1.md` §4 (ceremony
parameters, stable `user.id`, resident key, `rp.id` = party host) and
§5 (enrollment after a ceremony). Observation `e81dfd7`: 1Password
split `alice.localhost` from `bob.localhost`, and a second `create` on
`alice.localhost` saved another passkey with the same label. Outcome:
still valid at first preparation. This change adds the sign-in path. It does not reopen the
host rule, the dual certificate, or the local-group anchor.

2026-10-26 amend after `reviews/2026-10-26-advise.md`. Sign-in requires
WebAuthn assertion verification and a fresh challenge. An add to an
existing holder requires that holder's session. A same-vault create
may replace the authenticator's credential for the stable user id.
Signaling is best-effort in the browser. Fresh advise is owed before act.

## Why

A party page that only calls `credentials.create` mints a passkey on
every visit. The password manager files it under the party host. The
browser will not say whether a vault already holds one. The application
database is that list. Sign-in has to use a stored passkey when the
credential id is in the database and the relying party is this host.
Creating another passkey is a separate control.

## What

- MODIFY capability `identikey-party`.
- Living file after act: `docs/standards/identikey-party-v1.md`.
  Fold does not create `openspec/specs/identikey-party/`.
- Add the sign-in ceremony, the explicit add, `excludeCredentials`,
  and `signalAllAcceptedCredentials`.

## Impact

- Capabilities: MODIFIED `identikey-party`
- ADRs: none

## User journey & surfaces

No new UI because this change amends the ceremony rules. The surface
is the party origin in the browser and the password manager's list for
that host.

Working: a return visit calls `credentials.get`. A passkey whose
credential id is stored for this party host signs the session in.
Failed: a credential id the database does not hold is rejected. A
cancel stays on the page.
Empty: a holder with no stored passkey sees the add control.
Off: the add control is the only call to `credentials.create`.

## Out of scope

- The core ceremony page and its database. Later bead.
- The production two-host 1Password check on `add-party-hosts`.
- The OIDC URN grant, keyspaces, and the dual-certificate binding.
