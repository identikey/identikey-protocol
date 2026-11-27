# Tasks

- [x] Human decision: group XID derived from the founding entry, or the ADR-013 inception key with a binding proof. Decided 2026-11-26: founding entry. Recorded in `steer.md`.
- [x] Human decision: reissue `forgejo-ci-owner-v1` as a grant scope, or keep its own transcript. Decided 2026-11-26: reissue. Recorded in `steer.md`.
- [x] Advise on this change (protocol blast). Accepted in `reviews/2026-11-26-advise-4.md` by `astra-arch-review` at `9252484`, after three send-backs. Accept before act. The reader checks the reading of ADR-013 decision 4 in `design.md`, "Head and freshness", and the five NAOMS-derived rules listed in `steer.md` under "Decided".
- [x] Send-back `reviews/2026-11-26-advise.md` (reader `astra-arch-review`). Each item is owed before a fresh advise by the same reader:
  - [x] R1 Ordered consumption for a durable binding. Decided: narrow to bounded-staleness delegation. `design.md` "What a head does not give"; delta "A grant is delegation under bounded staleness".
  - [x] R2 Policy replacement and the per-rule protection. Decided: the `policy` rule is the root. `design.md` "The policy rule is the root"; delta of the same name.
  - [x] R3 Acceptance when a policy change makes a role governing. Decided: every key signs the entry that adds it. `design.md` "Acceptance"; delta "Every key signs the entry that adds it".
  - [x] R4 A complete, deterministic reducer and state definition. Amended in `design.md` "Reducer" and the delta "Replay is a total function of the entries".
  - [x] R5 The exact signed bytes and the signature verification profile. Amended in `design.md` "Entry envelope" and "Signatures" and the delta "Member signatures are exact". H1 restated.
  - [x] R6 Witness exit, freshness trust, and freeze semantics. Decided: trusted witness in v1, anchor reserved. `design.md` "What the witness is trusted for", "Freeze", "Exit witness", "Anchor"; deltas on currentness and freeze.
  - [x] R7 The lockout guard and the signature budget. `design.md` "Lockout guard" and the limits; delta scenarios "All of forty-nine" and "Majority crosses the limit".
  - [x] R8 A requirement-by-requirement map to the core governance contract. Added as `design.md` "Map to the core governance contract". Its R1 and R6 rows stay open.
  - [x] R9 Receipt identity when one entry has receipts with different times. Receipt times are no longer compared. Amended in `design.md` "Settlement" and the delta.
- [x] Send-back `reviews/2026-11-26-advise-2.md` (same reader). Wording and consistency, no design change:
  - [x] S1 The root invariant is authorization of change by the prior `policy` rule.
  - [x] S2 `State.grants` may be empty; the no-op rule starts after founding.
  - [x] S3 Founding is exempt from the 16-key limit; old and added keys are defined; a key cannot move between members in one entry.
  - [x] S4 The old-bundle scenarios and the real staleness bound (`head_age` plus 60 seconds).
  - [x] S5 The anchor section states requirements for a later profile, not guarantees.
- [x] Send-back `reviews/2026-11-26-advise-3.md` (same reader). One item:
  - [x] T1 The clock assumption behind the staleness bound, and computed age against real time. `design.md` "The clock assumption"; delta "A grant is delegation under bounded staleness".
- [x] Fresh advise after preparation
- [x] Spike H1: co-sign one `identikey-log` op with two non-actor keys and verify each. Record the result in `design.md`. Go, 2026-11-27: `crates/identikey-log/tests/cosign.rs` and `docs/spikes/add-governed-groups-h1/finding.md`.
- [x] Write `docs/standards/identikey-group-v1.md` from this change's design and delta. Copy the domain labels, the body maps, and the fixed limits. Spell out the op's core map, the Gordian leaf and wrapper digest construction, the signature tag and layout, and the assertion digest order, or pin the format they come from. A Rust function name is not portable documentation.
- [x] Add the standard to the table in `docs/standards/README.md`.
- [x] Add a pointer from `docs/standards/identikey-keyspace-v1.md` §12 to the new standard. Keyspace v1 text otherwise stays as it is.
- [x] Name fixture hooks in the standard: founding XID, each kind, quorum accept and reject, `majority` and `all`, role and key guard, lockout guard, acceptance present and missing, expiry, receipt, receipt time order, equivocation, exit receipt, head rollback, grant live / revoked / voided / kept, state digest mismatch, unknown mechanism, unknown threshold form, the sign digest against the content hash, co-signers, an unattributable signature, an elided entry, each reducer rejection, two receipts for one entry, the rule limit of 48, an anchor adoption, a stored freeze.
- [ ] ASK: unsupported-entry rule. Found 2026-11-27 while writing the standard (§15, marked there as an open issue). The contract says a verifier that meets an entry it cannot implement stores "unsupported" for the group and keeps to it. It does not say what the verifier must have verified about that entry first. As written, anyone who can hand a verifier a bundle can stop that verifier for the group with a made-up entry. A freeze, by contrast, is stored only after two settlement records verify. Recommended: store the finding only when every check v1 can make passes, including a receipt under the admissible witness key and approvals that meet the prior `policy` rule; otherwise reject the evidence and store nothing. That is a contract change, so it needs the user's decision and a fresh advise by `astra-arch-review`.

Out of scope, not owed here:

- Amending identikey-core: the living requirements "Stable collective XID", "Collective control evidence", "Handoff phases are independently abortable", and "Freshness witness for new authority", and the ADR-013 text that points at them. A core change. The XID decision is made.
- Reissuing `forgejo-ci-owner-v1` as a grant scope, with the ordered consume record for the owner binding. A follow-up change in this repo after this standard is accepted, then the verifier rework in identikey-core.
- The anchor: which canonical store, its trust rules, and its bytes. A later change.
- Spike H2 (a `bc-xid` document with no inception key). Belongs to the core change that projects a group XID document.
- identikey-core registrar, HTTP routes, the `ikey group` CLI, the managed-account approval ceremony.
- A verifier crate. A separate change after this standard is accepted.
- Key epochs and secret release on the group log.
- Migration of a keyspace v1 log.
- Filled signature vectors beyond the hooks.
