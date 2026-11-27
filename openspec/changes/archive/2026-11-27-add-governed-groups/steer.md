# steer add-governed-groups

**When.** 2026-11-25 and 2026-11-26 (two passes on the 26th)
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
- The group XID is derived from the founding entry (user, 2026-11-26).
  This departs from identikey-core ADR-013 decision 1. The core
  amendment is a separate change there.
- `forgejo-ci-owner-v1` is reissued as a grant scope (user,
  2026-11-26). A follow-up change in this repo.
- From the NAOMS hive read, proposed by the author and confirmed by
  the user on 2026-11-26:
  - `k` may be a number, `majority`, or `all`.
  - Incoming governing members and new keys sign the entry that adds
    them.
  - The role guard also covers a change to the keys of a member who
    holds the role. Before this, an admin could re-key an owner's seat.
  - Every entry after the founding one expires, and a receipt carries
    the witness's time.
  - A stranded rule stays unmet. No recovery path bypasses a rule.
- After the advise send-back (`reviews/2026-11-26-advise.md`), decided
  by the user on 2026-11-26:
  - R1: grants in this standard are bounded-staleness delegation only.
    The ordered consume record for a durable install is designed in the
    Forgejo reissue change, and Mjolnir's owner binding waits for it.
  - R2: the `policy` rule is the root. Other rules are protected
    against roster edits and are subordinate to it.
  - R3: every key signs the entry that adds it, for every member. A
    policy change may change what a role can do without fresh consent.
  - R6: v1 starts with a trusted witness, stated as trusted, including
    that it can end a group in one case. The stronger level is
    optional: a single canonical store to check for the truth. The
    path to it is paved now (`mech.anchor`, `none` in v1).

- 2026-11-27, user: keys are self-describing, for algorithm agility.
  Hardware and enclaves sign with P-256, and post-quantum keys must
  stay possible. The default (Ed25519) is called out and is the cheap
  form. v1 still accepts Ed25519 only. Recorded as K1 in `tasks.md`.
  The form `Key := bstr / { "alg", "key" }`, with the default bare, is
  the author's reading of "cheaper to use the default".

- 2026-11-27, user, confirming two author proposals (P1 and P4 in
  `tasks.md`):
  - A verifier stores an unsupported finding only for an unreadable
    entry that the prior `policy` quorum approved and the witness in
    office settled. The alternatives were a receipt alone, or never
    storing for an unknown kind.
  - An exit receipt is admissible only when the entry changes the
    witness and nothing else in the state, so it keeps every grant.
    The user's words: the exit receipt allows exit only, "a singular
    action".
- 2026-11-27, user, direction for the next step after this change
  lands: the exit key is the first key in a group that the members
  hold themselves and no trusted party holds. That becomes the default
  for anything a group does not want a witness to have authority over.
  It has to be rotated and handed out again as membership changes, and
  a quorum over it is wanted. The user asked for an outline of the
  steps from one shared key toward that, along three lines: security,
  convenience and recoverability against self-custody, and single
  against group decisions. Not designed in this change.

## Auto-logged

- Spec path `docs/standards/identikey-group-v1.md`. Capability
  `identikey-group`. No `openspec/specs/` living tree in this repo.
- New kinds are `group.*`. Keyspace v1 kinds and bytes are untouched.
- Public-read logs only in v1. `visibility` reserved.
- Shared keys and secret release are a later change.

## Skipped / still open

- FROST, Registry settlement, private logs, groups as members.
- Group-scoped member identifiers (NAOMS writes a per-hive pseudonym,
  never the root identity). Not in v1. The roster bytes already allow
  it. Decide with private logs.
- Whether tooling proposes `majority` as the default rule.

## Feeds change

Write `add-governed-groups` as the architecture change for this
protocol landing. Wire: founding-entry XID, linear witnessed log, member
XIDs with keys, `quorum(k, role)` per action with numeric and formula
thresholds, acceptance by incoming holders, entry expiry, witness
receipt and head, exit witness, detached grants.

Research read for this change: FOKS (go-foks `05a7027`, white paper
`3860270`), the Eudaemon white paper, and NAOMS hives (original and
Rust rewrite). What each contributed is in `design.md`, "Prior art".
