# steer add-governed-groups

**When.** 2026-11-25 and 2026-11-26
**Depth.** standard

## Decided

- A group is an XID whose controller is a policy instead of a person (user).
- `quorum(k, role)` is the authorization mechanism to build first (user).
  One authoritative key is 1-of-1. Any member is 1-of-role.
- Delegate-first. No group signing key in v1 (user).
- The hosted OP is the default witness, and a group must be able to
  change its witness (user).
- Roster entries are member XIDs. The keyspace v1 roster predates XIDs (user).
- The group log is readable, accessible, and verifiable. A simple
  default now: a hash chain (user).
- The first `identikey` group is founded with Duke's XID as the only
  owner. A second owner follows shortly (user).

## Auto-logged

- Spec path `docs/standards/identikey-group-v1.md`. Capability
  `identikey-group`. No `openspec/specs/` living tree in this repo.
- New kinds are `group.*`. Keyspace v1 kinds and bytes are untouched.
- Public-read logs only in v1. `visibility` reserved.
- Shared keys and secret release are a later change.

## Skipped / still open

- **XID derivation.** `design.md` derives the group XID from the
  founding entry. ADR-013 in identikey-core says a dedicated inception
  key plus a binding proof. Recommended: founding-entry derivation.
  Human decision owed.
- **Forgejo profile.** Keep `forgejo-ci-owner-v1` as its own transcript,
  or reissue it as a grant scope. Recommended: reissue. No production
  binding exists yet.
- FROST, Registry settlement, private logs, groups as members.

## Feeds change

Write `add-governed-groups` as the architecture change for this
protocol landing. Wire: founding-entry XID, linear witnessed log, member
XIDs with keys, `quorum(k, role)` per action, witness receipt and head,
exit witness, detached grants.

Research read for this change: FOKS (go-foks `05a7027`, white paper
`3860270`) and the Eudaemon white paper. What each contributed is in
`design.md`, "Prior art".
