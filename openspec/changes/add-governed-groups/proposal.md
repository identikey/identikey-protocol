# add-governed-groups

> **ACTIVE BUILD**

**Rigor:** architecture

Steer residue is `steer.md` in this change (2026-11-26). Protocol blast.
Activated 2026-11-27 by the user ("kick off the spike and write it up"),
after the advise accept in `reviews/2026-11-26-advise-4.md`. The grant
covers spike H1 and the owed work in `tasks.md`. It does not cover the
out-of-scope list there.

Preparation 2026-11-27: still valid. The accepted contract is `9252484`
and nothing in `design.md` or the delta changed after it except the H1
result. Two commits landed since: `d9121ae` (the key derivation
convention) and `16b06a1` (the keyspace wrap key). The convention says
the digests in `identikey-group` are hashes of public data and are not
key derivation, so the SHA-256 labels here stand. Spike H1 is go
(`docs/spikes/add-governed-groups-h1/finding.md`). It found no reason
to change the contract, so no fresh advise is owed.

Preparation 2026-11-26: revised. Inputs are the user's two decisions
(founding-entry XID, Forgejo profile reissued as a grant scope) and the
NAOMS hive read, both recorded in `steer.md`. The contract at `d3f4a01`
plus this note is the one the first advise read. It was sent back
(`reviews/2026-11-26-advise.md`, R1 to R9). The contract was revised
for all nine, with the user's decisions on R1, R2, R3, and R6 recorded
in `steer.md`. A second advise sent it back again on five
statements that claimed more than the design gives
(`reviews/2026-11-26-advise-2.md`, S1 to S5). The contract was revised
for all five without a change of design. A third advise resolved four
of them and sent back one (`reviews/2026-11-26-advise-3.md`, T1: the
verifier-clock assumption behind the staleness bound). That is now
stated. The fourth advise accepted it
(`reviews/2026-11-26-advise-4.md`).

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
  `k` is a number, `majority`, or `all`.
- Every key signs the entry that adds it. A change to a member's keys
  needs every rule that names a role the member holds. The `policy`
  rule is the root of the group.
- Every entry after the founding one expires.
- A trusted witness in v1, with what it can and cannot do stated, and a
  reserved `anchor` mechanism for a later canonical store.
- Grants are delegation under bounded staleness. No durable install is
  authorized by this standard.
- Settlement by a dated witness receipt per entry, a witness-signed
  head for freshness, and an exit witness that can settle only a witness
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
  commitment, decided by the user on 2026-11-26 (see `design.md`,
  "Identifier"). Three more living requirements there need amending:
  "Collective control evidence", "Handoff phases are independently
  abortable", and "Freshness witness for new authority" (see
  `design.md`, "Map to the core governance contract").
  The core amendments are a separate change in identikey-core and are
  owed before this standard is relied on there.

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
Failed: too few approvals, a missing receipt, two settled entries at
one sequence, a stale head, a revoked grant, or an unknown mechanism each
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
- Reissuing `forgejo-ci-owner-v1` as a grant scope, and the ordered
  consume record a durable owner binding needs. Decided by the user on
  2026-11-26. A follow-up change in this repo once this contract is
  accepted, then a rework of the verifier in identikey-core. Mjolnir's
  owner binding waits for it.
- The anchor: a single canonical store for a group's current head.
  Reserved here, specified later.
- identikey-core registrar (replica, proposal inbox, witness), HTTP
  routes, the CLI, the managed-account approval ceremony, and an OP
  token whose `sub` is a group XID. Product work in identikey-core.
- Filled cryptographic fixtures. The standard names the vector hooks.
