# Tasks

- [x] Human decision: group XID derived from the founding entry, or the ADR-013 inception key with a binding proof. Decided 2026-11-26: founding entry. Recorded in `steer.md`.
- [x] Human decision: reissue `forgejo-ci-owner-v1` as a grant scope, or keep its own transcript. Decided 2026-11-26: reissue. Recorded in `steer.md`.
- [ ] Advise on this change (protocol blast). Accept before act. The reader checks the reading of ADR-013 decision 4 in `design.md`, "Head and freshness", and the five NAOMS-derived rules listed in `steer.md` under "Decided".
- [ ] Send-back `reviews/2026-11-26-advise.md` (reader `astra-arch-review`). Each item is owed before a fresh advise by the same reader:
  - [ ] R1 Ordered consumption for a durable binding. Human decision owed.
  - [ ] R2 Policy replacement and the per-rule protection. Human decision owed.
  - [ ] R3 Acceptance when a policy change makes a role governing. Human decision owed.
  - [ ] R4 A complete, deterministic reducer and state definition.
  - [ ] R5 The exact signed bytes and the signature verification profile.
  - [ ] R6 Witness exit, freshness trust, and freeze semantics. Human decision owed.
  - [ ] R7 The lockout guard and the signature budget. Follows R3.
  - [ ] R8 A requirement-by-requirement map to the core governance contract.
  - [ ] R9 Receipt identity when one entry has receipts with different times.
- [ ] Fresh advise after preparation
- [ ] Spike H1: co-sign one `identikey-log` op with two non-actor keys and verify each. Record the result in `design.md`.
- [ ] Write `docs/standards/identikey-group-v1.md` from this change's design and delta. Copy the domain labels, the body maps, and the fixed limits.
- [ ] Add the standard to the table in `docs/standards/README.md`.
- [ ] Add a pointer from `docs/standards/identikey-keyspace-v1.md` §12 to the new standard. Keyspace v1 text otherwise stays as it is.
- [ ] Name fixture hooks in the standard: founding XID, each kind, quorum accept and reject, `majority` and `all`, role and key guard, lockout guard, acceptance present and missing, expiry, receipt, receipt time order, equivocation, exit receipt, head rollback, grant live / revoked / voided / kept, state digest mismatch, unknown mechanism, unknown threshold form.

Out of scope, not owed here:

- Amending identikey-core ADR-013 decision 1 and the living requirement "Stable collective XID". A core change. The XID decision is made.
- Reissuing `forgejo-ci-owner-v1` as a grant scope. A follow-up change in this repo after this standard is accepted, then the verifier rework in identikey-core.
- Spike H2 (a `bc-xid` document with no inception key). Belongs to the core change that projects a group XID document.
- identikey-core registrar, HTTP routes, the `ikey group` CLI, the managed-account approval ceremony.
- A verifier crate. A separate change after this standard is accepted.
- Key epochs and secret release on the group log.
- Migration of a keyspace v1 log.
- Filled signature vectors beyond the hooks.
