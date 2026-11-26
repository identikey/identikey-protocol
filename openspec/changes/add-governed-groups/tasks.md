# Tasks

- [ ] Human decision: group XID derived from the founding entry, or the ADR-013 inception key with a binding proof. Record it in `steer.md`.
- [ ] Human decision: reissue `forgejo-ci-owner-v1` as a grant scope, or keep its own transcript. Record it in `steer.md`.
- [ ] Advise on this change (protocol blast). Accept before act. The reader checks the reading of ADR-013 decision 4 in `design.md`, "Head and freshness".
- [ ] Spike H1: co-sign one `identikey-log` op with two non-actor keys and verify each. Record the result in `design.md`.
- [ ] Write `docs/standards/identikey-group-v1.md` from this change's design and delta. Copy the domain labels, the body maps, and the fixed limits.
- [ ] Add the standard to the table in `docs/standards/README.md`.
- [ ] Add a pointer from `docs/standards/identikey-keyspace-v1.md` §12 to the new standard. Keyspace v1 text otherwise stays as it is.
- [ ] Name fixture hooks in the standard: founding XID, each kind, quorum accept and reject, role guard, lockout guard, receipt, equivocation, exit receipt, head rollback, grant live / revoked / voided / kept, state digest mismatch, unknown mechanism.

Out of scope, not owed here:

- Amending identikey-core ADR-013 decision 1 and the living requirement "Stable collective XID". A core change, after the XID decision.
- Spike H2 (a `bc-xid` document with no inception key). Belongs to the core change that projects a group XID document.
- identikey-core registrar, HTTP routes, the `ikey group` CLI, the managed-account approval ceremony.
- A verifier crate. A separate change after this standard is accepted.
- Key epochs and secret release on the group log.
- Migration of a keyspace v1 log.
- Filled signature vectors beyond the hooks.
