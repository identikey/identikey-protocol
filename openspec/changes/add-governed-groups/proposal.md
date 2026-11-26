# add-governed-groups

> **PENDING**

**Rigor:** architecture

Steer residue is `steer.md` in this change (2026-11-26). Protocol blast.
Advise is owed before act. Nothing here is activated.

## Why

Two integrations stalled at the same question. Mjolnir must decide whether
a guild authorized a Forgejo organization to own CI VMs. Lightning Admin
must add and remove people who administer a router group. Both verifiers
need the current state of a group and proof that the group approved one
action. Today nothing produces those inputs. A keyspace v1 log is a file
on one admin's laptop. A guild has no identity of its own. No witness
exists, so the governance contract accepted in identikey-core (ADR-013)
cannot authorize anything, even for a one-owner guild. The Forgejo proof
profile takes a "trusted prior checkpoint" that no flow can supply.

A group is an XID whose controller is a policy instead of a person. This
change specifies the wire for that object.

## What

- ADD capability `identikey-group`.
- Living file after act: `docs/standards/identikey-group-v1.md`. This
  repo's spec surface is `docs/standards/`. Fold does not create
  `openspec/specs/identikey-group/`.
- Group XID derived from the founding entry, so a verifier configured
  with the XID alone can authenticate the whole log.
- A linear, hash-chained group log on `identikey-log`, five `group.*`
  kinds, one predecessor per entry.
- Roster principals are member XIDs with their current approval keys.
- One authorization mechanism, `quorum(k, role)`, evaluated per action.
- Settlement by a witness receipt per entry, a witness-signed head for
  freshness, and an exit witness that can settle only a witness
  replacement.
- Delegate-first action: the log records the digest of a detached,
  scoped, expiring grant. The group holds no signing key in v1.
- A state digest in every entry and a bundle encoding for transport.

Capabilities: `identikey-group` (ADDED). `identikey-keyspace`,
`identikey-capability`, and `identikey-auth-challenge` are not modified.

## Impact

- Capabilities: ADDED `identikey-group`
- ADRs: none in this repo. identikey-core ADR-013 decision 1 and the
  living requirement "Stable collective XID" in
  `identikey-core/openspec/specs/keyspace-governance/spec.md` describe a
  key-derived guild XID with a separate binding proof. This change
  derives the XID from the founding entry instead. That is a changed
  commitment. It needs a human decision and a core amendment before act
  (see `design.md`, "Identifier").

## User journey & surfaces

No new UI because this change is a wire standard. The surfaces it feeds
are a group command in the `ikey` CLI, the hosted approval page on the
IdentiKey OP, Lightning Admin's guild screens, and the Mjolnir owner
check. Those are separate changes in their own repos.

Working: a founder signs a founding entry and the witness settles it.
Anyone holding the group XID fetches the log, replays it, and reads the
roster, the policy, and the live grants. An owner proposes an entry,
enough distinct owners sign it, the witness settles it, and the head
moves. A relying party is shown a grant, checks its digest against the
log, checks a fresh head, and acts.
Empty: an XID with no fetchable log is unknown. A verifier does not act.
Failed: too few approvals, a missing receipt, two receipts at one
sequence, a stale head, a revoked grant, or an unknown mechanism each
give pending, conflict, or reject. None of them falls back to a single
admin.
Off: a verifier that does not implement `identikey-group` v1 refuses
group evidence.

## Out of scope

- Shared keys and secret release under a governed group. Keyspace v1
  stays as specified. A later change adds key epochs to the group log
  (detached wrap sets, per the Eudaemon and FOKS notes in `design.md`).
- Migration of an existing keyspace v1 log to a governed group. The
  version cut the core contract requires is not defined here.
- A group signing key, FROST, and plain group signatures.
- Registry or chain settlement. The witness is the only settlement
  mechanism in v1.
- Member-only (private) logs. `visibility` is reserved with one value.
- Groups as members of groups, and nesting.
- Rebasing `forgejo-ci-owner-v1` onto a grant scope. Recommended in
  `design.md`. Tracked as a follow-up once this contract is accepted.
- identikey-core registrar (replica, proposal inbox, witness), HTTP
  routes, the CLI, the managed-account approval ceremony, and an OP
  token whose `sub` is a group XID. Product work in identikey-core.
- Filled cryptographic fixtures. The standard names the vector hooks.
