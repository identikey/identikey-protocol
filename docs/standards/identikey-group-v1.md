# IdentiKey Group v1

**Status:** Draft spec. Test-vector hooks named; fixtures not filled.
**Date:** 2026-11-27
**Does not implement:** a crate in this workspace. Entries ride
[`identikey-log`](../../crates/identikey-log). The co-signature
construction in §4 is checked by `crates/identikey-log/tests/cosign.rs`.
No verifier crate exists yet.
**Does not specify:** shared keys, secret release, a group signing key,
a registry, or private logs.
**Not yet relied on by identikey-core:** four requirements of the core
governance contract need amending first (§16).

A group is an XID whose controller is a policy instead of a person.
This document specifies that object: its identifier, its log, how an
entry is authorized and settled, how a reader knows the log is fresh,
and how the group delegates.

Product word is **guild**. This standard says **group** for the governed
actor. A **keyspace** is a shared-key lineage
([`identikey-keyspace-v1.md`](identikey-keyspace-v1.md)). A group is not
a keyspace. A group may later control one.

Statements here are requirements on a verifier unless they are marked
as notes or as advice to tooling. "Fails" and "is rejected" mean the
verifier rejects the evidence it was given.

---

## 1. The three acts

A group does three things. Each is an entry on its log.

1. Change itself: roster, roles, rules, witness.
2. Delegate: issue or revoke a scoped, expiring grant.
3. Release secrets. Not in v1.

A group does not sign day to day. A member, a router, or a service acts
with its own key and a grant. Only issuing the grant is a governed
action. v1 defines no group signing key, and a member's signature is
never the group's signature.

---

## 2. Conventions

- **Bytes.** XIDs, keys, digests, and signatures are raw bytes in every
  structure here. Text forms follow
  [`encoding-conventions.md`](encoding-conventions.md).
- **dCBOR.** Every map in this document is deterministic CBOR as in
  [`dcbor-determinism.md`](dcbor-determinism.md): shortest integer
  form, definite lengths, and map keys sorted by their encoded bytes.
  The order in which a map is written in this document is not its
  order on the wire.
- **Transcripts.** A signed transcript is a domain label in ASCII, one
  zero byte, then the fields concatenated with no padding and no
  separator. `u64` is an unsigned 64-bit big-endian integer.
- **Time.** Unix seconds, unsigned.
- **Hashes.** SHA-256, and unkeyed BLAKE3 with 32 bytes of output. Each
  use says which. These are hashes of public data, not key derivation
  ([`key-derivation.md`](key-derivation.md)).
- **Lengths.** An XID, a key, a digest, and an entry hash are 32 bytes.
  A signature is 64 bytes. A salt is 16 bytes. A nonce is 32 bytes.

### 2.1 Ed25519 profile

Every signature in this standard is Ed25519 and is checked the same
way. This is the profile of `forgejo-ci-owner-v1`.

- A key is valid when its 32 bytes decode to a curve point. A key is
  weak when that point has small order. A weak or invalid key is
  rejected wherever it appears: on a roster, as a witness key, as an
  exit key.
- Verification is strict: the scalar `S` is canonical, neither the key
  nor `R` has small order, and the equation is checked without cofactor
  multiplication. This is `verify_strict` in `ed25519-dalek` 2.x.
- A verifier checks that a key is valid before it uses the key. Some
  libraries abort on a key that is not a point.

No other signature algorithm is accepted in v1. An ML-DSA signature on
an entry fails.

---

## 3. Identifier

```
xid = SHA-256( "identikey/group/xid/v1" 0x00 || founding_bytes )
```

`founding_bytes` is the entry bytes (§4.2) of the group's `group.found`
entry. The founding body carries a 16-byte random `salt`. It does not
carry the XID.

- A verifier configured with the XID alone authenticates the founding
  entry by recomputing the hash. Replay then gives the roster, the
  rules, and the witness. No trusted checkpoint is supplied from
  outside.
- Nobody holds an inception private key. There is nothing to destroy
  and nothing a founder can keep. A second founding entry is a
  different XID.
- Roster, rule, key, and witness changes do not move the XID.
- The hash authenticates the founding entry. It does not show that a
  given log is current. Currentness rests on the witness and a fresh
  head (§10).

The founding entry's BLAKE3 entry hash is the log's internal id for
parent links. It is not a second public identifier.

---

## 4. Entry

An entry is an `identikey-log` operation, format version 4, with one or
more attached signatures.

| Kind | Role |
|---|---|
| `group.found` | Founding entry. Sequence 0. No parent. |
| `group.roster` | Add, change, or drop members, their keys, their roles. |
| `group.policy` | Replace the policy: rules, witness, exit key. |
| `group.delegate` | Record the digest of a grant. |
| `group.revoke` | Revoke a grant by digest. |

The log is a chain, not a DAG. Each entry after the founding one has
exactly one parent, the previous settled entry, and a sequence one
greater than its parent's. Two entries with one parent are a fork. They
are never merged.

### 4.1 Core map

The entry's content is one dCBOR map of exactly seven pairs. On the
wire the keys sort in this order.

| Key | Value |
|---|---|
| `hlc` | array of two unsigned integers. The log requires it. This standard does not read it. |
| `body` | byte string: the canonical dCBOR of the body map for the kind (§5) |
| `kind` | text: one of the five kinds |
| `type` | text: `ball.action` |
| `actor` | byte string, 32 bytes: the proposer's key |
| `parent-hashes` | array of 32-byte strings. Empty for `group.found`. Exactly one otherwise: the parent's entry hash. |
| `format-version` | unsigned integer `4` |

`ball.action` is the log format's frozen type string. It is part of the
hashed bytes.

A group entry has nothing else. The log format also defines optional
assertions (`deps`, `nacks`, `target-fp`, `timestamp`), salted
assertions, and elision, in which an assertion is replaced by its
digest. A group entry carries none of them. An entry with any
assertion on its content, or with an elided element anywhere, fails,
even though its signatures may still verify.

### 4.2 Three values from the content

They are different bytes. Confusing them is the likeliest
implementation error.

| Name | Definition | Used for |
|---|---|---|
| entry bytes | `D8 C8 D8 C9` followed by the core map | the XID, as `founding_bytes` |
| `entry_hash` | BLAKE3 of the entry bytes | parent links, receipts, heads |
| `sign_digest` | SHA-256 of SHA-256 of the core map | what members sign |

The entry bytes are the core map as a Gordian Envelope leaf: CBOR tag
200 (envelope) around tag 201 (leaf). `entry_hash` is the log's
`content_hash`.

`sign_digest` is the Gordian digest of the wrapped envelope. A leaf's
digest is SHA-256 of the CBOR it holds, without the envelope tags 200
and 201. Here that is the core map alone. A wrapper's digest is SHA-256
of the 32-byte digest it wraps.

### 4.3 Signed entry

A signed entry is the envelope that wraps the content and carries one
`'signed'` assertion per signature.

```
signed entry = D8 C8                      ; tag 200
               array of 1 + n items       ; n signatures
               entry bytes                ; the wrapped content
               assertion * n              ; ascending assertion digest

assertion    = A1 03                      ; map of one pair, key 3
               D8 C9                      ; tag 201 (leaf)
               D9 9C 54                   ; tag 40020 (signature)
               82 02                      ; array [2, ...], 2 = Ed25519
               58 40 <signature: 64 bytes>

assertion digest = SHA-256( SHA-256( D9 9C 40 03 )
                         || SHA-256( D9 9C 54 82 02 58 40 <signature> ) )
```

`3` is the Gordian known value `'signed'`. As a digest input it is
tagged 40000, which gives the four bytes `D9 9C 40 03`.

- Each signature is Ed25519 over the 32 bytes of `sign_digest`. It is
  not over `entry_hash`.
- Assertions are ordered by ascending assertion digest, compared as
  bytes. This is the **wire order** of the signatures. It is not the
  order in which the members signed.
- A signed entry is exactly these bytes. A verifier rejects any other
  encoding of the same entry: another order, a repeated assertion, an
  assertion with another predicate, an elided element, or CBOR that is
  not deterministic. An implementation that decodes with a Gordian
  Envelope library re-encodes what it decoded and requires the result
  to equal the bytes it was given.
- A signed entry is at most 65,536 bytes.

Signatures carry no key identifier. Transport supplies one key per
signature, in wire order (§13).

### 4.4 Checking the signatures

The **old keys** of an entry are the keys of the roster before the
entry, under any member. The **added keys** are the keys of the roster
after the entry that are not old keys. The **candidate keys** are both.
For the founding entry every key of its roster is an added key, and
there are no old keys.

A key is old or added, never both, and each signature is counted once.
An old key that the entry removes can still sign, because approvals are
judged against the state before the entry.

For an entry presented with keys `K[0..n)` and signatures `S[0..n)` in
wire order:

- `S[i]` verifies under `K[i]` over `sign_digest`.
- Every `K[i]` is a candidate key.
- No key appears twice.
- `actor` is a key of a member in the state before the entry, or in the
  founding roster for the founding entry, and it is one of `K`.

If any of these fails, the entry as presented is rejected. A signature
by a key outside the candidate keys is not skipped. That verdict is
about the evidence. It says nothing about the group.

A signature by an old key is an **approval**. It counts once per
member, however many of that member's keys sign, toward each rule whose
role the member held in the state before the entry. A signature by an
added key is an **acceptance** (§8.5). It is not an approval.

Note. The `identikey-log` crate's generic `verify` checks every
signature against `actor`, so it rejects every co-signed group entry. A
group verifier does not call it. Ed25519 signing is deterministic, so
one key signing twice yields one assertion. A second, different
signature by one key is possible with randomized signing and is
rejected by the rule above.

---

## 5. Bodies and state

```
Member  := { "xid": bstr,          ; 32 bytes
             "keys": [+ bstr],     ; 32-byte Ed25519, the member's approval keys
             "roles": [+ tstr] }

Rule    := { "k": uint / "majority" / "all", "role": tstr }

Policy  := { "mech": { "auth": "quorum-v1",
                       "settle": "witness-v1",
                       "anchor": "none",
                       "release": "none" },
             "rules": { "roster": Rule, "policy": Rule,
                        ? "delegate": Rule, ? "revoke": Rule },
             "witness": { "key": bstr },   ; 32-byte Ed25519
             ? "exit": bstr,               ; 32-byte Ed25519
             "visibility": "public" }

State   := { "seq": uint, "roster": [Member], "policy": Policy,
             "grants": [bstr] }            ; standing grant digests,
                                           ; may be empty

FoundBody    := { "v": 1, "salt": bstr, "roster": [Member],
                  "policy": Policy, "state": bstr }
RosterBody   := { "group": bstr, "seq": uint, "exp": uint,
                  ? "set": [Member], ? "drop": [bstr], "state": bstr }
PolicyBody   := { "group": bstr, "seq": uint, "exp": uint,
                  "policy": Policy, ? "keep": [bstr], "state": bstr }
DelegateBody := { "group": bstr, "seq": uint, "exp": uint,
                  "grant": bstr, "state": bstr }
RevokeBody   := { "group": bstr, "seq": uint, "exp": uint,
                  "grant": bstr, "state": bstr }
```

`group` is the XID. `seq` is the prior `seq` plus one. `exp` is the
last moment the entry may be settled (§8.6). The founding entry has
none of the three.

### 5.1 State digest

```
state = SHA-256( dCBOR(State) )
```

`State` is the state after the entry is applied. A verifier whose
replay gives a different digest rejects the entry, even if its
signatures and its receipt are valid. Two implementations cannot drift
without noticing.

`State` does not contain the XID, so the founding entry can carry its
own state digest. A v1 verifier replays from the founding entry.
Starting from a later entry needs a trust anchor this standard does not
define.

### 5.2 Shape rules

For every body and for `State`:

- Every map is closed. An unknown key at any depth fails.
- Every array is sorted ascending and has no duplicate: `roster` and
  `set` by `xid`; `keys`, `drop`, `grants`, and `keep` bytewise;
  `roles` bytewise as UTF-8. dCBOR does not sort arrays, so this
  standard does.
- The optional arrays are `set`, `drop`, and `keep`. One that would be
  empty is omitted, and a present empty one fails.
- `roster`, `keys`, and `roles` are required and never empty.
- `State.grants` is required and may be empty. It is `[]` at founding,
  after the last grant is revoked, and after a policy change that keeps
  none.
- `xid`, `group`, a key, a grant digest, and `state` are 32 bytes. The
  founding `salt` is 16 bytes.
- A role is 1 to 32 bytes from `a-z`, `0-9`, and `-`.
- Integers are unsigned and fit in 64 bits.

### 5.3 Mechanisms

A policy names four mechanism slots and a visibility. v1 accepts
exactly these values.

| Slot | v1 value | Meaning |
|---|---|---|
| `mech.auth` | `quorum-v1` | §8 |
| `mech.settle` | `witness-v1` | §9 |
| `mech.anchor` | `none` | reserved, §9.5 |
| `mech.release` | `none` | no secret release |
| `visibility` | `public` | the log is readable by anyone who has it |

Any other value fails closed (§15). A `k` that is not a number,
`"majority"`, or `"all"` fails.

### 5.4 Limits

Fixed in v1.

- A roster holds at most 256 members. A member holds at most 8 keys.
- An entry after the founding one carries at most 64 signatures by old
  keys and adds at most 16 keys, each of which signs. That is 80
  signatures at most.
- The founding entry is exempt from the limit of 16. Its roster holds
  at most 64 keys, all of them sign, and it carries no other signature.
- No rule may need more than 48 members (§8.4).
- A signed entry is at most 65,536 bytes.

Evidence over a limit is rejected, not truncated. A verifier given 65
signatures by old keys does not count the first 64. A roster of 256
members does not mean 256 signatures can be carried. A large group
governs through a smaller role.

---

## 6. Replay

Replay is a function of the entries alone. It reads no clock and no
grant body. Two verifiers that replay one bundle a year apart compute
the same state digest at every sequence.

`State.grants` is the set of standing grants: digests issued and not
since revoked or voided. Whether a standing grant can be used now is a
separate question that needs its body and a clock (§11).

| Kind | Result |
|---|---|
| `group.found` | `seq` 0, the given roster and policy, no grants |
| `group.roster` | Members in `drop` are removed. Members in `set` replace a member with the same `xid` or are added. |
| `group.policy` | The policy is replaced. `grants` becomes `keep`, or empty when `keep` is absent. |
| `group.delegate` | `grant` is added to `grants`. |
| `group.revoke` | `grant` is removed from `grants`. |

Each of these fails:

- A `group.roster` entry with neither `set` nor `drop`.
- An `xid` in both `set` and `drop`.
- A `drop` that names no present member.
- A `set` member identical to the member already present, even when
  the same entry changes another member.
- A key that is under one member before the entry and under a
  different member after it. A key moves between members in two
  entries: it is removed in one and added in a later one.
- A `keep` digest that is not in the prior `grants`. A voided or
  revoked grant cannot be restored by `keep`.
- A `group.delegate` whose digest is already standing.
- A `group.revoke` whose digest is not standing.
- An entry after the founding one whose result equals the prior state
  apart from `seq`. A `group.policy` entry with the same policy that
  keeps every standing grant is such a no-op. One with the same policy
  that keeps fewer grants changes the state and is valid: it voids the
  rest.

There are no tombstones. A digest that was revoked or voided may be
delegated again, under the `delegate` rule. That is a new issuance of
the same body, and the state alone is enough to continue replay.

The roster rules (§7) and the guards (§8) then apply to the result.

---

## 7. Roster

A principal is a member XID. Keys are how a principal approves. Several
keys on one member are several devices of one principal. Approvals are
counted per member XID, not per key.

- A key appears under at most one member.
- A member key is never the witness key or the exit key.
- The log asserts that a key speaks for an XID. It does not prove it.
  The quorum that admitted the member vouches for that link. A relying
  party that wants more resolves the member's own XID document. The log
  verifies without resolving any member's document, online or offline.

A member's key change is a `group.roster` entry. The group approves it,
and the role and key guard (§8.3) applies. A member cannot re-key its
own seat alone: a holder of a copied key could then sign a rival
rotation first.

Roles are labels with no built-in order. A member may hold several.

On the wire `xid` is 32 bytes. In v1 it is the member's XID. A later
profile can put a group-scoped identifier there for members who should
not be linkable across groups, without changing these bytes. That
belongs with private logs and is not in v1.

---

## 8. Authorization: quorum-v1

An entry is approved when approvals (§4.4) come from enough distinct
members who hold `role` in the state before the entry. With `n` such
members, enough is:

| `k` | Needed |
|---|---|
| a number | that number |
| `"majority"` | `floor(n/2) + 1` |
| `"all"` | `n` |

A number goes stale as the roster grows. A group declared as "everyone
agrees" and written as `k: 2` is 2-of-9 seven members later. The two
named forms are recomputed from the roster at every entry.

| Entry | Rule |
|---|---|
| `group.found` | its own `policy` rule, against its own roster |
| `group.roster` | `roster`, plus the role and key guard (§8.3) |
| `group.policy` | `policy` |
| `group.delegate` | `delegate` |
| `group.revoke` | `revoke` |

An absent `delegate` or `revoke` rule makes that action unavailable. A
`group.delegate` entry signed by every member still fails when the
policy has no `delegate` rule.

The proposer is a member and signs. Its signature counts like any
other.

No failure falls back to a single administrator.

### 8.1 Founding

The founding entry is signed by every key in its roster (§8.5). For it,
those signatures count as its members' approvals, and it meets its own
`policy` rule against its own roster. A founder cannot name a member
who has not agreed.

### 8.2 The policy rule is the root

Whoever can pass the `policy` rule controls the group. A `group.policy`
entry can rewrite every other rule, replace the witness and the exit
key, and void every grant. A high threshold on `delegate`, `revoke`, or
`roster` does not bind the members who can pass `policy`. With
`policy: 1 of admin` and `delegate: 2 of owner`, one admin can replace
the policy with `delegate: 1 of admin` and then delegate alone. That is
valid.

The root is changed only by the root. Changing the `policy` rule needs
the `policy` rule as it stood before the entry. So does any
`group.roster` entry that changes who holds its role or what keys they
have. Members who cannot pass the rule cannot change it or its holders.

An authorized change may hand power to members who could not pass the
rule before. Two owners under `policy: 2 of owner` can lower it to 1,
and then either governs alone. Three owners under `majority` can have
two of them drop the other signer and the third, and the one who
remains governs alone. Both are valid. The members who could pass the
rule chose it.

The other rules are protected against roster edits by §8.3 and are
subordinate to `policy`. A group that wants an action to be harder than
a policy change cannot have that in v1.

Advice to tooling: warn when another rule is stricter than `policy`.
The stricter rule gives less protection than it appears to.

### 8.3 Role and key guard

Roles have no order, so "you cannot grant a role above your own" is
restated without one.

A role `R` is **affected** by a `group.roster` entry when the set of
members holding `R` differs between the state before and the state
after, or when a member who holds `R` in both has a different set of
keys. Dropping a member affects every role that member held.

A `group.roster` entry must satisfy, in addition to the `roster` rule,
every rule that names an affected role. Each is judged against the
state and the policy before the entry.

Through a roster change, the power to pass a rule is gained only by
passing that rule. An admin under `roster: 1 of admin` cannot mint
owners when `policy` is `2 of owner`. The same admin cannot put its own
key on an owner's seat.

### 8.4 Lockout guard

An entry is rejected when, in the resulting state, for any rule:

- its role has no holder, or
- a numeric `k` is zero or greater than the number of distinct members
  holding the role, or
- the number of members the rule needs is greater than 48.

All three always apply, to every kind of entry, the founding entry
included.

The third keeps every rule within the signatures one entry can carry.
`"all"` therefore allows at most 48 holders, and `"majority"` at most
95. A roster entry that would add the 96th holder of a `"majority"`
role is rejected.

What the guard promises: each rule, taken alone, can be met by one
entry. It does not promise that several rules can be met together. A
roster entry that changes owners under `roster: 40 of admin` and
`policy: 40 of owner`, with no member in both roles, would need 80
approvals and cannot be carried. The `policy` rule alone can always be
met, so the group repairs such a combination with a `group.policy`
entry.

### 8.5 Acceptance

- Every added key signs its entry, whatever roles its member holds. In
  a founding entry that is every key.
- A member who gains a role in a `group.roster` entry signs that entry
  with at least one of its keys.

Nobody is on the roster without agreeing to it, and no key is on the
roster that has not signed. So no key ever counts toward a rule before
it has been shown to work, whichever entry later makes its role matter.

An acceptance is not an approval. With `roster: 2 of owner`, an entry
that adds a new owner and is signed by one existing owner and the new
member is not approved.

Adding a member needs the member present, with a key, at the time of
the entry. The flow is invite, accept, admit.

One exception, stated plainly: a `group.policy` entry can change what a
role is able to do, and it asks no fresh consent from the members who
hold that role. A member agrees to join a group whose root rule can do
that. A member who does not want a new power can ask to be dropped.

### 8.6 Expiry

An approval cannot be withdrawn. Without a limit, a proposal one owner
signed and abandoned could be completed months later by a second
signature, including one from a key stolen in the meantime.

Every entry after the founding one carries `exp`. A receipt whose time
is later than `exp` is not a settlement record (§9). An expired
proposal is dead. Its signers sign a new one if they still want it.
Silence and lapse never approve. An approval is a signature over one
entry's `sign_digest` and cannot be reused on another entry.

An entry settled in time stays effective. A verifier that replays the
log long after `exp` reaches the same result.

### 8.7 Lost keys

A member who loses a key is re-keyed by the other holders: a
`group.roster` entry under the `roster` rule and the role and key
guard, signed by the new key. The lost key takes no part.

When too few holders are left to meet a rule, that rule cannot be met
and nothing lowers it. The group keeps its last state. Live grants run
to their expiry, and a head can still be signed. A stranded `roster`,
`delegate`, or `revoke` rule can be replaced by a `group.policy` entry
while the `policy` rule can still be met. If the `policy` rule itself
is stranded, the group cannot recover, and its members found a new
group under a new XID. v1 has no recovery path that bypasses a rule,
because any such path is a second, weaker rule.

Advice to tooling: say when a rule has no slack, so that one lost
member strands it. That is always so for `"all"`, and for a role with
one holder. A sole owner should list two keys held in different places.

---

## 9. Settlement: witness-v1

Approval is not settlement. An entry is effective only when it is
valid, approved, and settled. A witness records one successor per
predecessor.

```
receipt = Ed25519(
  "identikey/group/settle/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 )
```

`time` is the witness's clock at settlement.

The **admissible key** for an entry is the witness key of the policy in
force before the entry. For the founding entry it is the witness the
entry names. Where §9.4 allows, the prior policy's exit key is also
admissible, with its own label.

A **settlement record** for an entry is any receipt that verifies under
an admissible key over that entry's transcript, with `time` not later
than the entry's `exp`. The founding entry has no `exp`, and any time
settles it.

- Several receipts for one entry are one settlement record, whatever
  their times, and whichever admissible key signed them. A retry by the
  witness is harmless. A bundle carries one receipt per entry, and
  which one it carries does not change replay.
- Receipt times are never compared with each other, with a parent's
  receipt, or with a head. The time dates the entry for a reader. It is
  the witness's statement and is not part of the state digest.
- An approved entry with no settlement record is **pending**. State
  stays at the predecessor. A receipt by another key, or one whose
  transcript names another group, is not a settlement record.
- A receipt on an entry that fails validation is not a settlement
  record. It is evidence of a faulty witness, and it does not block a
  valid entry at that sequence.
- Given two approved entries with one parent and one settlement record,
  the entry with the record is effective and the other is rejected, in
  either arrival order.
- Two settlement records for different entries at one sequence freeze
  the group at the predecessor (§9.3). Arrival order does not choose.

An honest witness validates an entry before it signs, and signs at most
one entry per `(xid, seq)`.

### 9.1 What the witness is trusted for

`witness-v1` is one operator. A v1 verifier trusts it for three things:
ordering, its clock, and currentness.

What a witness cannot do, whatever it signs: author an entry, change
the roster or the rules, issue or restore a grant, or make an entry
effective that lacks its approvals. The hosted witness cannot take a
group over.

What a dishonest witness can do:

- **Refuse.** It settles nothing. The exit key answers this (§9.4).
- **Backdate.** A receipt's time is the witness's word. An approved
  entry that was never settled stays settleable by a dishonest witness
  after its `exp` has passed in the world. Expiry protects against an
  honest witness completing a stale proposal. It does not bind a
  dishonest one, and this standard does not detect the backdating.
- **Freeze.** If two approved entries exist at one sequence, it can
  settle both, or settle one while the exit key settles the other. It
  cannot invent the second entry. The owners must have signed it.
- **Hide.** It can sign a fresh head over an old entry and so conceal a
  later revocation from a verifier that has not seen the later entries.

### 9.2 A retired witness

A witness that the group has replaced keeps one power. It is still the
witness named in the states before its replacement, so it can sign a
fresh head over that old prefix. A verifier that has already accepted a
later head refuses it. A verifier meeting the group for the first time,
or restored from an old snapshot, cannot tell from the XID alone.

What limits this in v1:

- A verifier keeps the highest head it has accepted and never goes
  back.
- A valid chain that extends another is the more current of the two. A
  verifier given both uses the longer. A chain that runs past a witness
  replacement proves the old witness is retired, because the
  replacement entry is itself settled.
- A verifier meeting a group for the first time should fetch from more
  than one place.

These reduce the exposure. They do not remove it. A verifier on first
contact, shown only a valid bundle that ends before a witness
replacement, with a fresh head by the witness named there, accepts it.
Removing that needs a place every verifier can check (§9.5).

### 9.3 Freeze

Two settlement records for different entries at one sequence freeze the
group at the predecessor, whichever keys signed the receipts. In v1 a
freeze is permanent. No later entry, receipt, or witness replacement
clears it.

- A verifier that has verified both records stores the conflict (the
  XID, the sequence, both entry hashes) as durably as its highest head.
  It reports conflict for that group from then on, across restarts, and
  whatever bundle it is given later.
- Under a known conflict no grant is live and nothing new is
  authorized. What was done before stays done.
- A verifier that has seen only one of the two records carries on along
  that one. v1 has no way to tell it. The anchor is that way.
- The members found a new group under a new XID, and relying parties
  bind to the new one.

A hosted witness can therefore end a group in one case: the owners have
left an approved entry unsettled at the current sequence and then
approve a different one there. It still cannot capture the group.

### 9.4 Exit witness

`policy.exit` is a second key, held by the group's owners, distinct
from the witness key and from every member key.

```
exit_receipt = Ed25519(
  "identikey/group/exit/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 )
```

An exit receipt is admissible on one kind of entry only: a
`group.policy` entry whose policy differs from the prior policy in
`witness` and nothing else. The signing key is the prior policy's
`exit`. The `policy` rule still has to be met. On any other entry an
exit receipt is not a settlement record, and the entry is pending.

A hosted witness that refuses service cannot hold the group. The exit
key cannot order roster, rule, or grant entries. After a witness
replacement settles, heads for that entry and for later ones are signed
by the new witness.

The guarantee is conditional. The exit works when the witness refuses
and no other approved entry is outstanding at that sequence. If the
owners approved an ordinary entry there earlier and it was never
settled, a dishonest witness can settle that entry while the exit key
settles the replacement, and the group freezes. Waiting for the earlier
entry to expire does not help, because the witness can backdate.

Two different witness replacements at one sequence, each with an exit
receipt, are also two settlement records and freeze the group. The exit
key is held by the owners, so that is the owners' own fault.

Advice to tooling: say at founding that a group without `exit` depends
on its witness to leave its witness. Show an owner any approved,
unsettled entry at the current sequence before the owner approves an
exit, and say that exiting then is a risk to the group.

### 9.5 Anchor

`mech.anchor` is `"none"` in v1. The slot is reserved for an optional,
stronger level: one canonical store that every verifier can check for
the truth about a group.

Nothing in this section is a guarantee of v1. A reserved slot protects
nobody. These are the requirements a later anchor profile has to meet:

- **Currentness.** A verifier of an anchored group can learn the
  current head from the anchor, including on first contact, without
  trusting a witness the group has retired. That needs a way to find
  and trust the store that does not depend on the bundle the verifier
  was handed.
- **One answer.** The anchor says which entry is authoritative at a
  sequence. That is canonical selection. It is not the same as
  publishing every conflict: a second settled sibling can be withheld
  from any store. A profile that also wants conflicts published says
  how.
- **Its own assumptions.** Which store, who runs it, how its answers
  are verified, and what happens when it is unavailable are all
  unspecified here. An anchor moves trust. It does not remove it.

What v1 does so that the later change is an upgrade and not a break:

- The mechanism slot exists, and a verifier fails closed on a value it
  does not know (§15).
- A group adopts an anchor with a `group.policy` entry that changes
  `mech.anchor`. A v1 verifier that reads that entry stops there,
  authorizes nothing further, and stores that fact for the group. A
  verifier that has stored it does not later check that group at the
  weaker level.
- That protection reaches only verifiers that have seen the adoption
  entry. A v1 verifier on first contact, shown only the prefix before
  adoption with a fresh head from the witness named there, accepts it.
- What an anchor would record is already the head's subject: the XID,
  the sequence, and the entry hash.
- The XID does not change when a group adopts an anchor.

---

## 10. Head and freshness

```
head = Ed25519(
  "identikey/group/head/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 || nonce )
```

`nonce` is 32 bytes. All zero means the head answers no challenge.

- A head is signed by the witness named in the state at the head's
  sequence. After a settled witness replacement at sequence 7, a head
  over sequence 7 by the outgoing witness is refused.
- A verifier rejects a head whose time is more than 60 seconds ahead of
  its own clock.
- A head's **age** is the verifier's clock minus the head's time, and
  zero when the head's time is ahead.
- A verifier keeps the highest head it has accepted per XID. It refuses
  a log that does not extend that head.
- A verifier that sent a nonce requires it back, uses the answer once,
  and forgets the nonce after the answer or after 300 seconds.
- A log that verifies without a head that meets the caller's freshness
  rule authorizes no new action.
- A relying party that checks a grant in use requires a head no older
  than the grant's `head_age` (§11).

### 10.1 What a head does not give

A head says what the witness saw at a time. It does not order a relying
party's action against a later revocation. A party can read a fresh
head, a revocation can settle a moment later, and the party can still
act inside `head_age`. A nonce does not close that gap.

So v1 grants are delegation under bounded staleness, and nothing more.

- The holder of a grant acts in its own name, with its own key. A
  relying party that honors the grant accepts that a recent revocation
  or policy change may not be visible to it. The group chose `head_age`
  when it issued the grant.
- A bundle that predates a revocation or a policy change still
  verifies. A verifier refuses it when it has accepted a later head, or
  when the head's age is greater than `head_age`. Otherwise the
  verifier cannot know, and that is the staleness the grant declares.
- This standard gives no authority for an action whose effect outlasts
  the check: installing a durable binding, releasing a secret, or
  anything else that must be consumed once and ordered against a
  handoff. Such an action needs an ordered consume record. v1 defines
  none. A profile that wants one defines it, and it is a prerequisite
  of that integration.

### 10.2 The clock assumption

The test a verifier applies is on computed age: the head's age, by the
verifier's own clock, is not greater than `head_age`. That test does
not by itself bound real time.

The bound in real time is `head_age` plus 60 seconds: a revocation or
policy change that settled longer ago than that is visible to the
relying party. It holds only when all three of these hold at the moment
of the check:

- the witness is honest about what is current,
- the witness's clock is right, and
- the verifier's clock is within 60 seconds of real time.

The 60 seconds is an allowance for clock error in the real-time bound.
It is not added to the computed-age test. A head with a computed age of
60 seconds passes a `head_age` of 60. One with a computed age of 61
seconds fails it.

Checking a head's time does not establish the third condition. The
check against a future time only shows that one signed time is not more
than 60 seconds ahead of the verifier. A verifier whose clock runs an
hour slow reads an hour-old head as fresh. A stale signed head cannot
tell a verifier that its own clock is wrong. Without a synchronized
verifier clock, v1 gives no finite bound in real time. A relying party
keeps its clock synchronized by its own means. This standard defines no
protocol for it.

---

## 11. Grants

```
Grant := { "v": 1, "group": bstr, "holder": { * tstr => any },
           "scope": { "kind": tstr, * tstr => any },
           "nbf": uint, "exp": uint, "head_age": uint, "salt": bstr }

grant_digest = SHA-256( "identikey/group/grant/v1" 0x00 || dCBOR(Grant) )
```

The log carries the digest. The holder carries the body and presents
it. A public log then shows that a grant exists and not who holds it or
what it covers. A `group.delegate` entry never carries the body.

`group` is the XID. The `salt` is 16 bytes. `head_age` is in seconds
and is at least 1. `nbf` and `exp` are Unix seconds. A body that breaks
these shapes is never live.

A grant is **standing** when its digest is in `State.grants`. A grant
is **live** for a relying party when all hold:

- its digest is standing in the state at the head,
- the presented body hashes to that digest, and its `group` is the XID,
- `nbf <= exp`, and `nbf <= now <= exp`,
- the head's age is not greater than `head_age`, and
- the verifier holds no conflict for the group (§9.3).

A policy change voids earlier grants unless it restates them in `keep`.
A revoked grant is refused once the relying party holds a head that
includes the revocation.

`holder` and `scope` are typed by profiles. This standard does not
interpret them. A grant is not a Biscuit: there is no group key to root
one. Capability semantics at the relying service stay with
[`identikey-capability-v1.md`](identikey-capability-v1.md) or with the
scope's profile.

A grant is not a wrap. A keyspace replica asked for a wrapped key on
the strength of a grant refuses.

---

## 12. Unsettled proposals

A proposal that is not yet settled does not travel in a bundle. It is
the signed entry and its keys, checked against the state at the head.
It is approved or not, and it is pending until a settlement record
exists.

---

## 13. Transport

```
Settled      := { "op": bstr,             ; signed entry, §4.3
                  "keys": [+ bstr],       ; one per signature, wire order
                  "by": "witness" / "exit",
                  "time": uint,
                  "receipt": bstr }       ; 64 bytes

LogBundle    := { "v": 1,
                  "entries": [+ Settled],
                  ? "rival": [+ Settled],
                  ? "head": { "seq": uint, "entry": bstr, "time": uint,
                              "nonce": bstr, "sig": bstr } }
```

The sorting rule of §5.2 covers bodies and `State`. It does not cover
a bundle: `keys` is in wire order, and `entries` is in sequence order.

`entries` is the whole chain in order, from sequence 0, with no gap. A
bundle that starts later or skips a sequence is rejected.

`rival` carries settled entries that compete with an entry in the chain
at the same sequence. A verifier checks a rival exactly as it checks a
chain entry, against the state at that sequence's predecessor. A rival
that verifies is a second settlement record there.

`by` says which label and which key the receipt uses. `head.entry` is
the entry hash at `head.seq`.

A bundle is self-verifying. Any copy is as good as another: the OP, a
mesh hub, a git repository, a file. Where a bundle is served is a
deployment matter and is not authority.

---

## 14. Verifier

Input: the group XID, a bundle, the verifier's stored record for that
XID if any, the current time, and optionally a nonce and a grant body.

Output, one of four:

| Verdict | Meaning |
|---|---|
| accept | with the state and the head |
| pending | an approved entry has no settlement record; state at the predecessor |
| conflict | two settlement records at one sequence; state at the predecessor |
| reject | with the failing evidence |

Collection, discovery, and storage of bundles sit outside the verifier.

What a verifier stores per XID, all of it with the same durability:

- the highest head it has accepted,
- a conflict it has verified: the sequence and both entry hashes,
- a sequence it could not read (§15).

For each entry, against the state at its predecessor:

1. The signed entry is the exact bytes of §4.3 and within the size
   limit. A kind the verifier does not implement is handled by §15.
2. For the founding entry, the entry bytes hash to the XID and there is
   no parent. For any other entry, `group` is the XID, `seq` is the
   prior `seq` plus one, and the one parent hash is the predecessor's
   entry hash.
3. The body meets the shape rules (§5.2). A mechanism value the
   verifier does not know is handled by §15.
4. The signatures check (§4.4) and the limits hold (§5.4).
5. The transition succeeds (§6) and the roster rules hold (§7).
6. The rule for the kind is met, with the role and key guard (§8.3),
   the lockout guard (§8.4), and acceptance (§8.5).
7. The verifier's own state digest equals the body's `state`.
8. The receipt is a settlement record (§9).

An entry that fails any of 1 to 7 is rejected, and a receipt on it
counts for nothing. An entry that passes them and has no settlement
record is pending.

Then, for the bundle: every rival is checked the same way, the head is
checked (§10), and the stored record is consulted. A grant body, when
given, is checked against the state at the head (§11).

---

## 15. Unsupported entries

A verifier that meets an entry it cannot implement, because of its kind
or because its policy names a mechanism value the verifier does not
know, stops at the predecessor.

- It reports the group as unsupported from that sequence. It may report
  the earlier state as history. It does not skip ahead.
- It authorizes no new action on the earlier state. A later entry
  exists that it cannot read, so the earlier state is not known to be
  current.
- It stores the XID and the sequence it could not read, and keeps
  reporting this for the group whatever shorter bundle it is given
  later, with whatever head.

A founding entry that names an unknown mechanism is a group the
verifier rejects outright.

Open issue. As written, this rule does not say what the verifier must
have checked about the unreadable entry before it stores the finding. A
freeze is stored only after two settlement records verify (§9.3). The
same care is owed here, or anyone who can hand a verifier a bundle can
stop that verifier for the group. Tracked in `add-governed-groups`.
An implementation should not build this rule until it is settled.

---

## 16. Relation to other standards

**Keyspace v1.** Unchanged. A keyspace v1 log written before this
standard replays to the same result. Group membership is not keyspace
membership. Group v1 does not wrap, release, or rotate a secret.

**Capability v1.** Unchanged. A grant is not a capability token.

**Forgejo CI owner proof v1.** That profile signs its own transcript
and takes a trusted prior checkpoint as input. Under this standard the
same decision is a grant with `scope.kind` `forgejo-ci-owner`, the
instance hostname, and the numeric organization id, and its trusted
inputs come from replay. The profile is to be reissued as a grant
scope. Installing an owner binding is a durable action, so a live grant
and a fresh head are not enough for it (§10.1). The reissue defines the
ordered consume record for that install.

**The identikey-core governance contract** (ADR-013 and
`identikey-core/openspec/specs/keyspace-governance/spec.md`). The
contract says approval, settlement, and freshness are separate facts,
unknown mechanisms fail closed, and there is no fallback to a single
admin. This standard keeps all three. "Core amendment" below means the
core text must change before core relies on this standard.

| Core requirement | Here |
|---|---|
| Explicit selectable governance | Implemented. The policy names four mechanism slots, unknown values fail closed, and the founding entry is the signed bootstrap. |
| Exact transition authorization | Implemented. A signature covers the kind, the group XID, the sequence, the parent, the action, and the resulting state digest. Distinct principals are counted under the prior policy. |
| Full governance handoff | Implemented for roster and policy. No group key exists, so no key is retired. |
| Optional predeclared recovery | Restricted. The only predeclared path is the exit key, and it replaces the witness and nothing else. Lost authority leaves governance unavailable, as the requirement allows. |
| Conflict and settlement semantics | Implemented by `witness-v1`. |
| Stable collective XID | Core amendment. The XID comes from the founding entry, and v1 binds no keyspace. |
| Governed collective action and identity control | Restricted to delegation. No group signing or authentication. Disclosure the requirement asks for: no party holds a whole secret, and ordering relies on one operator. |
| Registry authority is independent of discovery | No Registry. The statement it requires: the ordering authority of `witness-v1` is a single operator. |
| Version cut rejects legacy administering | Deferred. No keyspace v1 log is migrated here. |
| Collective control evidence | Core amendment. There is no identity document, binding proof, or keyspace checkpoint. The evidence is the XID, the log, and a head. |
| Handoff phases are independently abortable | Restricted. v1 has no secret and no control key to put into effect, so the four phases are: prepare is the unsigned entry, authorize is its signatures, effect is empty, and activate is settlement. An entry is abandoned before activation by letting it expire. Core amendment to admit this restricted profile. |
| Finality gates secret release | Settlement half implemented. Release is `none`. |
| Adapter evidence is one transition | Implemented. Four verdicts, stated maxima, and every receipt and head commits to one entry hash. |
| Freshness witness for new authority | Restricted. v1 offers no group signing, authentication, identity control, or secret release. A grant's holder acts in its own name under the staleness bound the grant declares. A durable installation needs an action-bound, ordered consume, which this standard does not define. Core amendment to say that delegated use under a declared bound is outside "new authority". |
| Pre-activation effects are not current | Nothing is staged in v1. A pending entry has no effect. |
| Migration finality is the outgoing descriptor | A witness replacement is settled by the outgoing witness. The exit path is the exceptional recovery the predecessor policy already authorized. No incoming-readiness evidence is asked of the new witness, which is a restriction: a group can name a witness that never answers. It then leaves by the exit key, if one is configured and usable and no competing entry is outstanding. |

Nothing downstream should rely on this standard for collective control
of an identity document until the four core amendments land: "Stable
collective XID", "Collective control evidence", "Handoff phases are
independently abortable", and "Freshness witness for new authority".

### 16.1 Why the XID is not a key

The core design gives a guild a dedicated inception key, an XID that is
the hash of that key, and a binding proof signed by it. A private key
cannot be shown to have been destroyed. A founder who keeps the
inception key can, after a full handoff, sign a second founding with a
different roster and a witness the founder controls. A verifier that
holds only the XID sees two founding entries that both verify, and can
tell them apart only with a checkpoint or a registry it already trusts.
Deriving the XID from the founding entry removes the rival. The core
decision that a guild XID is a stable identity distinct from a keyspace
lineage is kept.

---

## 17. Test-vector hooks

Named slots. Filled byte fixtures are not owed by `add-governed-groups`.
Each slot is one or more cases with an expected verdict.

| Slot | Covers |
|---|---|
| `found-xid` | Founding entry bytes, `entry_hash`, and the XID. A rival founding entry is a different XID. |
| `sign-digest` | Core map, `sign_digest`, and a signature over it. A signature over `entry_hash` is rejected. |
| `signed-entry-bytes` | Signed entry with three signers. Assertion digests and wire order. Two signing orders give the same bytes. |
| `co-signers` | Proposer plus two other owners, each verified under its own key. Proposer absent is rejected. |
| `signature-unattributable` | One extra signature by a key outside the candidate keys. Rejected as presented. |
| `signature-same-key-twice` | Two signatures by one key. Rejected. |
| `key-weak` | An added key that is a small-order point, and one that is not a point. Rejected. |
| `signature-ml-dsa` | An ML-DSA signature. Rejected. |
| `entry-elided` | A signature assertion elided, and a content assertion elided. Rejected though signatures verify. |
| `entry-shape` | A timestamp assertion, a second parent, a missing body, a non-canonical encoding. Each rejected. |
| `kind-found` | A founding entry, accepted, with `State.grants` empty. |
| `kind-roster` | Add, change, and drop. |
| `kind-policy` | Rules, witness, and exit key replaced. |
| `kind-delegate` | A digest becomes standing. |
| `kind-revoke` | A digest stops standing. The last one leaves `[]`. |
| `quorum-number` | 2 of 3 accepted. One owner plus a non-owner not approved. Two keys of one member count once. |
| `quorum-majority` | 2 of 5 not approved, 3 of 5 approved. |
| `quorum-all` | 3 of 4 not approved. |
| `quorum-rule-absent` | `group.delegate` with no `delegate` rule. Rejected. |
| `found-quorum` | Founding with a listed member unsigned. Rejected. |
| `policy-root` | An admin under `policy: 1 of admin` rewrites a stricter `delegate` rule, then delegates alone. Accepted. Owners lower their own threshold. Accepted. |
| `role-key-guard` | Admin mints an owner, drops an owner, re-keys an owner. Each rejected. Owners re-key an owner who lost a key. Accepted. |
| `lockout-guard` | A role left with no holder, `k` of zero, `k` above the holders, a removal that strands a rule. Each rejected. |
| `rule-limit-48` | `all` of 49 rejected. The 96th holder of a `majority` role rejected. |
| `acceptance-present` | A new member and a second key, each signing its entry. Accepted. |
| `acceptance-missing` | A new member unsigned, an added key unsigned, a promotion unsigned. Each rejected. Acceptance does not count as approval. |
| `policy-makes-role-governing` | A policy change names a role in a rule with no signatures from its holders. Accepted. |
| `expiry` | A receipt dated after `exp` is not a settlement record. One dated before stays effective on late replay. |
| `receipt` | Transcript bytes and a valid receipt. Wrong key and wrong XID are pending. |
| `receipt-invalid-entry` | A receipt on an entry without its quorum. Rejected, and it does not block a valid sibling. |
| `receipt-times-not-compared` | A child receipt dated before its parent's. Accepted. |
| `receipt-two-for-one-entry` | Two receipts for one entry at different times. Same chain and state from either. |
| `receipt-one-chooses` | Two approved siblings, one receipt, both arrival orders. |
| `equivocation` | Two settled siblings. Conflict, state at the predecessor. |
| `freeze-stored` | After a recorded conflict, a bundle with one sibling still reports conflict. A grant standing at the predecessor is refused. A later replacement does not clear it. |
| `exit-receipt` | A witness-only replacement settled by the exit key. Accepted, and later heads are by the new witness. |
| `exit-not-admissible` | An exit receipt on a roster entry, and on a replacement that also changes a rule. Pending. |
| `exit-conflict` | An exit races a settled ordinary entry. Two exits. Conflict. |
| `witness-is-member-key` | A policy whose witness key is a member key. Rejected. |
| `head` | Transcript bytes and a valid head. |
| `head-rollback` | A stored head at 9, a log ending at 7. Refused. |
| `head-future` | A head one hour ahead. Rejected. One 60 seconds ahead has age zero. |
| `head-nonce` | A different nonce. Refused. |
| `head-retired-witness` | A head by a replaced witness over the old prefix, against a stored later head. Refused. A head by the outgoing witness over the replacement entry. Refused. |
| `chain-longer-wins` | Two valid chains, one extending the other. The longer is used. |
| `grant-live` | Body, digest, window, and head age all good. |
| `grant-refused` | Altered body, another group's XID, outside the window, head too old, shape broken. |
| `grant-head-age-limit` | Computed age 60 passes `head_age` 60. Age 61 fails. |
| `grant-revoked` | Refused against a head that includes the revocation. |
| `grant-voided` | A policy change without `keep`. Refused. |
| `grant-kept` | A policy change with `keep`. Still live. |
| `grant-reissued` | Delegated, revoked, delegated again. Standing. |
| `state-digest-mismatch` | A wrong `state` with valid signatures and receipt. Rejected. |
| `reducer-rejections` | One case per rejection in §6, and one per shape rule in §5.2. |
| `mechanism-unknown` | A founding policy with another `settle` value. Rejected. |
| `threshold-form-unknown` | A `k` that is not a number, `majority`, or `all`. Rejected. |
| `kind-unknown` | An unknown kind at sequence 3. State at 2, nothing authorized, and still nothing when later given the shorter log with a fresh head. |
| `anchor-adoption` | A policy entry at sequence 5 with another `anchor` value. Stops at 4, stored, nothing authorized. |
| `limits` | 65 signatures by old keys, 17 added keys, a founding roster of 17 keys, of 64, of 65, an entry over 65,536 bytes. A removed key still approves. |
| `bundle-gap` | Entries 0, 1, 3. Rejected. |
| `replay-no-clock` | One bundle replayed at two times. Same state digests. |

Suggested path when filled: `docs/standards/vectors/group-v1/`.

---

## 18. Out of scope

- Shared keys, key epochs, and secret release on the group log
- A group signing key, FROST, and any threshold signature as evidence
- Migration of a keyspace v1 log
- The anchor: which canonical store, its trust rules, and its bytes
- Registry settlement, and a contract as a settlement mechanism
- Private logs and group-scoped member identifiers
- Groups as members of groups
- An ordered consume record, and with it the Forgejo reissue
- A registrar, HTTP routes, a CLI, and an approval ceremony
- A group XID document. Whether an XID document can be projected for an
  XID with no inception key is not yet verified.
- A verifier crate

---

## 19. Prior art

The reasoning is recorded with the change that introduced this
standard (`openspec/changes/add-governed-groups/design.md`, later under
`openspec/changes/archive/`). In brief:

- **FOKS.** Taken: member keys recorded in the group's own chain, the
  lockout guard, and invite, accept, admit. FOKS stops at one
  authoritative admin, private team chains, and no witness. Those three
  are this standard's subject.
- **Eudaemon.** Taken: a full state commitment in every entry, and
  detached bodies with only a digest on the chain. Not taken: an
  identifier that is a key fingerprint, and any step that reassembles a
  key.
- **NAOMS hives.** Taken: decisions counted over distinct persons under
  a closed rule set, thresholds recomputed from the roster, nothing
  keyed on who created the group, invite and accept, lost-key recovery
  attested by the other holders, and proposals that lapse. Its recorded
  costs of signing with a threshold key are the reason delegation comes
  first here.
