# Member-held authority in a group

Direction notes, written 2026-11-27 after `identikey-group-v1` was
accepted. This is not a standard. It records where the group work
stands, what the user decided about the next steps, and what an
implementer should know before starting. Tracks `ikp-1zx`.

## Where things stand

- `docs/standards/identikey-group-v1.md` is the living contract. It is
  a wire standard only. No code implements it yet.
- The change that produced it is archived at
  `openspec/changes/archive/2026-11-27-add-governed-groups/`. Its
  `design.md` has the reasoning, `steer.md` has every user decision,
  and `reviews/` has the seven architecture reviews.
- The byte construction of a co-signed entry is checked by
  `crates/identikey-log/tests/cosign.rs` (spike H1,
  `docs/spikes/add-governed-groups-h1/finding.md`).

## The question this note is about

In v1 a trusted witness orders a group's entries. The group can leave a
witness that refuses service by using the exit key (§9.4). That key is
the first key in a group that the members hold themselves and no
trusted party holds.

The user's direction, 2026-11-27: member-held keys become the default
for anything a group does not want a witness to have authority over.
The key has to be rotated and handed out again as membership changes,
and a quorum over it is wanted.

## Three facts to start from

1. **The quorum is already there.** The exit key never acts alone. The
   entry it settles still needs the `policy` quorum, signed with the
   members' own keys. A person who holds only the exit key cannot
   capture a group. The worst they can do is freeze it, and only when
   the owners have signed two different entries at one sequence.
2. **Rotation needs the witness.** Replacing the exit key is an
   ordinary `group.policy` entry, settled by the witness in office. The
   exit path cannot replace it. Once the witness is hostile, the exit
   key the group has is the one it keeps.
3. **The real dependency is the approval keys.** If an owner's approval
   key is held for them by the operator who also runs the witness, that
   operator can withhold both, and the exit key is useless. This is an
   inference from identikey-core's custody tiers (the managed tier
   holds the signing key and signs after a passkey assertion). No group
   approval ceremony exists yet to check it against.

One rule sorts the options. Signing authority never needs a shared
secret, because a list of signatures does the job. Only secrecy needs a
shared secret. The exit key is authority, so wrapping one copy of it to
each member is the weakest fit for this key.

## The steps

| Step | What changes | Who decides | If a key is lost | New wire |
|---|---|---|---|---|
| 0 | One exit key, one holder. v1 as written. | One person fires an approved exit | The group depends on its witness to leave it | No |
| 1 | The exit key wrapped to each owner. A new key and new wraps on a membership change. | Any one owner | Any other owner has it | Yes: the first key epoch on the group log |
| 2 | Every owner lists a self-held approval key beside any managed key | Unchanged | The managed key still works day to day | No |
| 3 | Quorum exit: the exit receipt is k-of-role signatures by members' own keys | The group | The others re-key the seat | Yes: a new settlement mechanism |
| 4 | Hardware-bound member keys (P-256) | Unchanged | The others re-key the seat | Yes: a new mechanism |
| 5 | A threshold key (FROST) | The group, as one signature | Reshare | Yes |
| 6 | The anchor: one canonical store for the current head | Not about keys | Not about keys | Yes |

Shared secrets are a separate track: wraps with epochs first, then
threshold decryption so that no single member can open the secret.

## Decided

The user, 2026-11-27, on the author's recommendation:

- Step 2 comes first, then step 3.
- Step 1 is kept for the secrets track, where a real secret needs it.
  It is not built for the exit key, because step 3 removes that key.

Steps 4 to 6 are not ordered yet.

## Notes for step 2 (self-held approval keys)

- No wire change. A member may list up to 8 keys (§5.4), so one seat
  can carry a managed key for daily use and a self-held key for the
  override.
- The added key signs the entry that adds it (§8.5). The ceremony that
  adds a self-held key therefore needs that key present.
- The test to state in tooling: can the `policy` rule be met using only
  keys that the witness's operator does not hold? If not, the group
  cannot leave that witness, whatever its exit key. Say so at founding.
- This is the user's exit test applied to a group: a user can leave
  with keys and data intact, without permission.
- It is product work in identikey-core and the `ikey` CLI. It lands
  with the founding ceremony, which does not exist yet.

## Notes for step 3 (quorum exit)

- It is plain multisig, which the co-signing spike already proved. No
  new cryptography.
- It arrives as a new `settle` value. To a v1 verifier the adopting
  policy entry is unreadable, and once established it stops that
  verifier for the group (§15). Every v1 verifier a group relies on has
  to be upgraded before the group adopts it.
- The adoption entry itself is signed and settled under the old rules:
  current-mechanism signatures, and a receipt from the outgoing
  witness. An exit receipt cannot stand in for that receipt.
- Open design questions:
  - Is the exit rule its own rule in the policy, and may it be stricter
    than `policy`?
  - Do the approvals and the exit receipt collapse into one act? The
    same people sign both. What is left of the receipt is the moment of
    firing and a time, and the time is the signers' own word.
  - The lockout guard has to cover the exit rule.
  - Two exits at one sequence still freeze the group. With `majority`,
    two conflicting quorums always share a member, so the entries name
    who signed both.
- Keep the confirmed scope: an exit changes the witness and nothing
  else, so it keeps every grant.

## Notes for whoever writes the verifier

All of this is in the standard. It is collected here because each item
was a mistake waiting to happen.

- Parse a key as the `Key` type and accept only the bare 32-byte form
  under the v1 mechanisms. Any map is an invalid key, including an
  Ed25519 key written as a map (§2.2).
- Compare and sort keys by their encoded bytes, not the raw 32 bytes.
  For v1 keys the result is the same.
- Read `kind` first, then `mech` and `visibility`, before the
  closed-map rule (§15). Otherwise a later policy looks malformed
  instead of unreadable, and the clean stop is lost.
- Check that a key is a canonical, non-weak curve point before using it
  (§2.1). Do not call `identikey_log`'s generic `verify`: it rejects a
  co-signed op, and it panics on an actor key that is not a curve point
  (`ikp-o70`, open).
- An unreadable entry is stored as "unsupported" only when the prior
  `policy` quorum approved it and the witness in office settled it.
  Anything less is rejected as evidence and nothing is stored.
- Fixture notes from the reviews, for when the hooks in §17 are filled:
  keep `unreadable-rival` in both delivery orders, include a valid
  64-key founding and a separate all-of-49 rejection, and keep the
  three adoption cases (valid, no outgoing receipt, a later-layout
  signature attached).

## Still unconfirmed

- The first `identikey` group is founded with the user's XID as the
  only owner. The XID assumed is the owner recorded for the production
  OP in identikey-core's `CLAUDE.md`. The user has not confirmed that
  it is the one to use.
- Whether tooling proposes `majority` as the default rule.

## Order of work

1. Fix `ikp-o70`. Small, and the verifier must not inherit the panic.
2. The verifier crate with filled vectors (`docs/standards/vectors/group-v1/`).
   Everything else depends on it.
3. Amend identikey-core's governance contract: four living requirements
   and the ADR-013 text. The list is in the standard, §16. It can run
   beside 2.
4. Reissue `forgejo-ci-owner-v1` as a grant scope, with the ordered
   consume record. Mjolnir's owner binding waits on this.
5. identikey-core: registrar, witness, the `ikey group` commands, and
   the approval ceremony. Step 2 above lands here, and the first group
   is founded.
6. Step 3 above, as a protocol change.
