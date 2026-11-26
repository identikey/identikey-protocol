# Design: governed groups

## Status and boundaries

Proposed wire. Not accepted. The contract it implements is identikey-core
ADR-013 and `identikey-core/openspec/specs/keyspace-governance/spec.md`:
approval, settlement, and freshness are separate facts, unknown
mechanisms fail closed, and there is no fallback to a single admin.

This change covers identity, governance, and delegation. It does not
cover shared keys. `identikey-keyspace-v1.md` is unchanged.

Product word is still **guild**. This standard says **group** for the
governed actor. A keyspace is a shared-key lineage. A group may later
control one.

## The three acts

A group does three things. Each is an entry on its log.

1. Change itself: roster, roles, rules, witness.
2. Delegate: issue or revoke a scoped, expiring grant.
3. Release secrets. Not in this change.

A group does not sign day-to-day. A member, a router, or a service acts
with its own key and a grant. Only issuing the grant is a governed
action. This keeps the witness off the hot path.

## Identifier

```
xid = SHA-256( "identikey/group/xid/v1" 0x00 || founding_bytes )
```

`founding_bytes` is the canonical unsigned envelope of the `group.found`
op, the same bytes `identikey-log` hashes for `content_hash`. The body
carries a 16-byte random `salt`. The founding body does not carry the
XID.

Consequences:

- A verifier configured with the XID alone authenticates the founding
  entry by recomputing the hash. Replay then gives the roster, the
  rules, and the witness. No trusted checkpoint is supplied from outside.
- Nobody holds an inception private key. There is nothing to destroy
  and nothing a founder can keep.
- The identifier's link to the founding entry rests on a hash, not on a
  classical signature.
- Roster, rule, key, and witness changes do not move the XID.
- The hash authenticates the founding entry. It does not show that a
  given log is current. Currentness rests on the witness and a fresh
  head (see "Head and freshness").

### Why this departs from the accepted identity construction

ADR-013 decision 1 says the guild XID is a stable identity distinct
from a keyspace lineage. The construction is in the accepted core
design and the living requirements "Stable collective XID" and
"Collective control evidence": a dedicated inception key, the XID as
the hash of that key, and a binding proof signed by it that ties the
XID to a keyspace genesis. This change replaces that construction. It
keeps the decision: the group XID is still not a keyspace id.

A private key cannot be shown to have been destroyed. A founder who
keeps the inception key can, after a full handoff, sign a second
founding with a different roster and a witness the founder controls. A
verifier that holds only the XID sees two founding entries that both
verify. It can tell them apart only with a checkpoint or a registry it
already trusts. That is the "trusted prior checkpoint" the Forgejo
profile needs and nothing supplies. The ADR's rule "a second binding of
the same XID is a conflict" holds only for a verifier that has seen both.

Deriving the XID from the founding entry removes the rival. A different
founding entry is a different XID.

Decided 2026-11-26 (user): the group XID is derived from the founding
entry. That changes a commitment in another repo. Amending ADR-013
decision 1 and the living requirement "Stable collective XID" is a
separate change in identikey-core.

The `identikey-log` content hash of the founding entry (blake3) remains
the log's internal id for parent links. It is not a second public
identifier.

## Log

Entries are `identikey-log` ops (format version 4) with attached,
plural signatures.

| Kind | Role |
|---|---|
| `group.found` | Founding entry. Sequence 0. No parent. |
| `group.roster` | Add, change, or drop members, their keys, their roles. |
| `group.policy` | Replace the policy: rules, witness, exit key. |
| `group.delegate` | Record the digest of a grant. |
| `group.revoke` | Revoke a grant by digest. |

The log is a chain, not a DAG. Each entry after the founding one has
exactly one parent, the previous settled entry, and `seq` equal to the
parent's plus one. Two entries with one parent are a fork. They are
never merged.

A verifier that meets an entry it cannot implement, because of its kind
or because its policy names a mechanism value the verifier does not
know, stops at the predecessor. It reports the group as unsupported
from that sequence and authorizes no new action on the earlier state. A
later entry exists that it cannot read, so the earlier state is not
known to be current.

### Entry envelope

A group entry is an op with exactly this shape. Anything else fails.

- `kind`: one of the five above.
- `body`: present. The canonical dCBOR of the body map for that kind.
- `parent_hashes`: empty for `group.found`, exactly one otherwise.
- `deps` and `nacks`: empty. `target_fp` and `timestamp`: absent.
- `hlc`: present, as the log requires. This standard does not read it.
- No elided assertion, no salted assertion, and no assertion the log
  codec does not define. The codec skips an elided assertion and
  re-encodes to a different hash, so a group verifier rejects any entry
  whose decode reports an elision.

Three values come from the unsigned envelope. They are different bytes.

| Name | Definition | Used for |
|---|---|---|
| entry bytes | canonical CBOR of the unsigned envelope (`codec::encode`) | the XID, as `founding_bytes` |
| `entry_hash` | BLAKE3 of the entry bytes (`codec::content_hash`) | parent links, receipts, heads |
| `sign_digest` | SHA-256 Gordian digest of the wrapped unsigned envelope (`to_envelope(op).wrap().digest()`) | what members sign |

### Signatures

- Every attached signature is Ed25519 over the 32-byte `sign_digest`.
  It is not over `entry_hash`. Any other algorithm fails in v1,
  including ML-DSA.
- Verification is strict Ed25519, and every key is a valid, non-weak
  Ed25519 verification key. This is the same profile as receipts and as
  `forgejo-ci-owner-v1`.
- The candidate keys for an entry are the keys in the roster before the
  entry, plus the keys the entry adds. For the founding entry they are
  the keys of the founding roster.
- Signatures carry no key identifier. Transport supplies one key per
  signature, in wire order (`keys` in the bundle). Signature `i` must
  verify under key `i`. Key `i` must be a candidate key. No key appears
  twice. If any of these fails, the entry as presented is rejected.
  That verdict is about the evidence. It says nothing about the group.
- `Op.actor` is the proposer. It is a key of a member in the state
  before the entry (for the founding entry, in the founding roster),
  and it is one of the signers.
- A signature by a key of a member in the state before the entry is an
  approval. It counts once per member, however many of that member's
  keys sign, toward each rule whose role the member held in that state.
- A signature by a key the entry adds is an acceptance.

The log crate's generic `verify` checks every signature against
`Op.actor`. It rejects any co-signed group entry. A group verifier does
not call it. It reads the signatures and the digest and applies the
rules above.

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
             "grants": [bstr] }            ; live grant digests

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

`exp` is Unix seconds. It is the last moment the entry may be settled
(see "Expiry"). The founding entry has none.

`state` is `SHA-256` of the canonical dCBOR of `State` after the entry
is applied. A verifier whose replay gives a different digest rejects the
entry. Two implementations in different languages cannot drift without
noticing. `State` does not contain the XID, so the founding entry can
carry it. A v1 verifier replays from the founding entry. Starting from
a later entry needs a trust anchor this standard does not define.

Limits are fixed in v1:

- 256 members, and 8 keys per member.
- On one entry, at most 64 signatures by keys already on the roster,
  and at most 16 keys added, each of which signs. That is 80 signatures
  at most.
- A founding roster holds at most 64 keys. All of them sign.
- No rule may need more than 48 members (see "Lockout guard").
- 65,536 bytes for one signed entry.

Larger evidence is rejected, not truncated. A roster of 256 members
does not mean 256 signatures can be carried. A large group governs
through a smaller role.

### Reducer

Replay is a function of the entries alone. It reads no clock and no
grant body. `State.grants` is the set of standing grants: digests
issued and not since revoked or voided. Whether a standing grant can be
used now is a separate question that needs its body and a clock (see
"Grants").

Shape rules, for every body and for `State`:

- Every map is closed. An unknown key at any depth fails.
- Every array is sorted ascending and has no duplicate: `roster` and
  `set` by `xid`; `keys`, `drop`, `grants`, and `keep` bytewise; `roles`
  bytewise as UTF-8. dCBOR does not sort arrays, so this standard does.
- An optional array that would be empty is omitted. A present empty
  array fails. `keys` and `roles` are never empty.
- `xid`, `group`, a key, a grant digest, and `state` are 32 bytes. The
  founding `salt` is 16 bytes.
- A role is 1 to 32 bytes from `a-z`, `0-9`, and `-`.
- Integers are unsigned and fit in 64 bits.
- `group` is the XID. `seq` is the prior `seq` plus one.
- An entry whose result equals the prior state apart from `seq` fails.

Transitions:

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
- A `set` member identical to the member already present.
- A `keep` digest that is not in the prior `grants`. A voided or
  revoked grant cannot be restored by `keep`.
- A `group.delegate` whose digest is already standing.
- A `group.revoke` whose digest is not standing.

There are no tombstones. A digest that was revoked or voided may be
delegated again, under the `delegate` rule. That is a new issuance of
the same body, and the state alone is enough to continue replay.

The guards in "Authorization" then apply to the result.

## Roster

A principal is a member XID. Keys are how a principal approves. Several
keys on one member are several devices of one principal.

- A key appears under at most one member.
- A member key is never the witness key or the exit key.
- The log asserts that a key speaks for an XID. It does not prove it.
  The quorum that admitted the member vouches for that link. A relying
  party that wants more resolves the member's own XID document.

A member's key change is a `group.roster` entry. The group approves
it, and the role and key guard below applies. A member cannot re-key its own
seat alone: a holder of a copied key could then sign a rival rotation
first.

Roles are labels with no built-in order. A member may hold several.

On the wire `xid` is 32 bytes, and the log never proves the link from a
key to it. In v1 it is the member's XID. A later profile can put a
group-scoped identifier there for members who should not be linkable
across groups, without changing these bytes. That belongs with private
logs and is not in v1.

## Authorization: quorum(k, role)

An entry is approved when valid signatures over it come from keys of
enough distinct members who hold `role` in the state before the entry.
With `n` such members, enough is:

| `k` | Needed |
|---|---|
| a number | that number |
| `"majority"` | `floor(n/2) + 1` |
| `"all"` | `n` |

A number goes stale as the roster grows. A group declared as "everyone
agrees" and written as `k: 2` is 2-of-9 seven members later. The two
named forms are recomputed from the roster at every entry.

`Op.actor` is the proposer. It must be a member key and it must sign.
Its signature counts like any other.

| Entry | Rule |
|---|---|
| `group.found` | its own `policy` rule, against its own roster |
| `group.roster` | `roster`, plus the role and key guard below |
| `group.policy` | `policy` |
| `group.delegate` | `delegate` |
| `group.revoke` | `revoke` |

An absent `delegate` or `revoke` rule makes that action unavailable.

The founding entry is signed by every key in its roster (see
"Acceptance"). That meets its own `policy` rule, and it is the
incoming-control evidence ADR-013 asks for. A founder cannot name a
member who has not agreed.

### The policy rule is the root

Whoever can pass the `policy` rule controls the group. A `group.policy`
entry can rewrite every other rule, replace the witness, and void every
grant. A high threshold on `delegate`, `revoke`, or `roster` does not
bind the members who can pass `policy`. With `policy: 1 of admin` and
`delegate: 2 of owner`, one admin can replace the policy with
`delegate: 1 of admin` and then delegate alone. That is valid.

The root protects itself. No sequence of valid entries gives the power
to pass the `policy` rule to a set of members who could not already
pass it: a `group.policy` entry needs the rule, and so does any
`group.roster` entry that changes who holds its role or what keys they
have.

The other rules are protected against roster edits by the guard below,
and are subordinate to `policy`. A group that wants an action to be
harder than a policy change cannot have that in v1. Tooling should warn
when another rule is stricter than `policy`, because the stricter rule
then gives less protection than it appears to.

Every signature attached to an entry must be attributable (see
"Signatures"). A signature by a key outside the candidate keys rejects
the entry as presented. It is not skipped.

Coverage of the options discussed in steer:

| Option | Rule |
|---|---|
| One authoritative key | `k: 1`, one holder |
| Any member | `k: 1`, role held by all |
| Counted signatures | `k: n`, role held by owners |
| Majority or unanimity | `k: "majority"` or `k: "all"` |
| FROST | same rule, later, with one aggregate signature as evidence |
| Contract | later, as a `settle` mechanism |

### Role and key guard

Roles have no order, so "you cannot grant a role above your own" is
restated without one:

A `group.roster` entry that changes which members hold role `R`, or
that changes the keys of a member who holds `R`, must also satisfy
every rule that names `R`.

Through a roster change, the power to pass a rule is gained only by
passing that rule. An admin under `roster: 1 of admin` cannot mint
owners when `policy` is `2 of owner`. The same admin cannot put its own key on an
owner's seat. Dropping a member changes who holds that member's roles.

### Lockout guard

An entry is rejected when, in the resulting state, for any rule:

- its role has no holder, or
- a numeric `k` is zero or greater than the number of distinct members
  holding the role, or
- the number of members the rule needs is greater than 48.

FOKS offers the first two as an opt-in. Here all three always apply.

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

### Acceptance

- Every key signs the entry that adds it to the roster, whatever roles
  its member holds. In a founding entry that is every key.
- A member who gains a role in a `group.roster` entry signs that entry
  with at least one of its keys.

Nobody is on the roster without agreeing to it, and no key is on the
roster that has not signed. So no key ever counts toward a rule before
it has been shown to work, whichever entry later makes its role matter.
An acceptance signature is not an approval. It counts toward a rule
only when its member already held the rule's role before the entry.

Adding a member needs the member present, with a key, at the time of
the entry. The flow is invite, accept, admit.

One exception, stated plainly: a `group.policy` entry can change what
a role is able to do, and it asks no fresh consent from the members who
hold that role. A member agrees to join a group whose root rule can do
that. A member who does not want a new power can ask to be dropped.

### Expiry

An approval cannot be withdrawn. Without a limit, a proposal one owner
signed and abandoned could be completed months later by a second
signature, including one from a key stolen in the meantime.

Every entry after the founding one carries `exp`. A receipt whose time
is later than `exp` is not a settlement record. An expired proposal is
dead. Its signers sign a new one if they still want it. Silence and
lapse never approve.

### Lost keys

A member who loses a key is re-keyed by the other holders: a
`group.roster` entry under the `roster` rule and the role and key
guard, signed by the new key. The lost key takes no part.

When too few holders are left to meet a rule, that rule cannot be met
and nothing lowers it. The group keeps its last state. Live grants run
to their expiry, and a head can still be signed. If the stranded rule
is `policy` or `roster`, the group cannot recover, and its members
found a new group under a new XID. v1 has no recovery path that
bypasses a rule, because any such path is a second, weaker rule.

Tooling should say when a rule has no slack: one lost member strands
it. That is always so for `"all"`, and for a role with one holder. A
sole owner should list two keys held in different places.

## Settlement: witness-v1

Approval is not settlement (ADR-013 decision 3). A witness records one
successor per predecessor.

```
receipt = Ed25519(
  "identikey/group/settle/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 )
```

`entry_hash` is the entry's `identikey-log` content hash. `time` is the
witness's clock at settlement, in Unix seconds. Integers are
big-endian. Verification is strict Ed25519.

A settlement record for an entry is any receipt that verifies under
the admissible key over that entry's transcript with `time` not later
than the entry's `exp`. The founding entry has no `exp`, and any time
settles it.

Several receipts for one entry are one settlement record, whatever
their times, and whether they come from the witness or, where the exit
key is admissible, from the exit key. A retry by the witness is
harmless. A bundle carries one receipt per entry, and which one it
carries does not change replay. Receipt times are never compared with
each other, with a parent's receipt, or with a head. The time dates the
entry for a reader. It is the witness's statement and is not part of
the state digest.

- The witness validates an entry before it signs. It signs at most one
  entry per `(xid, seq)`.
- An approved entry with no receipt is pending. State stays at the
  predecessor.
- One receipt on a valid, approved entry is a settlement record. That
  entry is effective.
- Two settlement records for different entries at one sequence freeze
  the group at the predecessor. Arrival order does not choose.
- A receipt on an entry that fails validation is not a settlement
  record. It is evidence of a faulty witness.
- The founding entry is settled by the witness it names.

The witness holds no authority. It cannot author an entry. It can
order, and it can refuse.

### What the witness is trusted for

`witness-v1` is one operator. A v1 verifier trusts it for three things:
ordering, its clock, and currentness.

What a witness cannot do, whatever it signs: change the roster or the
rules, issue or restore a grant, or make an entry valid that lacks its
approvals. A receipt on an invalid entry is not a settlement record.
The hosted witness cannot take a group over.

What a dishonest witness can do:

- **Refuse.** It settles nothing. The exit key answers this (below).
- **Backdate.** A receipt's time is the witness's word. An approved
  entry that was never settled stays settleable by a dishonest witness
  after its `exp` has passed in the world. Expiry protects against an
  honest witness completing a stale proposal. It does not bind a
  dishonest one.
- **Freeze.** If two approved entries exist at one sequence, it can
  settle both, or settle one while the exit key settles the other. It
  cannot invent the second entry. The owners must have signed it.
- **Hide.** It can sign a fresh head over an old entry and so conceal
  a later revocation from a verifier that has not seen the later
  entries.

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

These reduce the exposure. They do not remove it. Removing it needs a
place every verifier can check (see "Anchor").

### Freeze

Two settlement records for different entries at one sequence freeze the
group at the predecessor. In v1 a freeze is permanent. No later entry,
receipt, or witness replacement clears it.

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

### Exit witness

`policy.exit` is a second key, held by the group's owners, distinct from
the witness key and from every member key.

```
exit_receipt = Ed25519(
  "identikey/group/exit/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 )
```

An exit receipt is admissible on one kind of entry only: a
`group.policy` entry whose policy differs from the prior policy in
`witness` and nothing else. The `policy` rule still has to be met.

This is the predeclared path ADR-013 allows for leaving a settlement
backend. A hosted witness that refuses service cannot hold the group.
The exit key cannot order roster, rule, or grant entries. A group
without `exit` depends on its witness to leave its witness, and tooling
should say so at founding.

The guarantee is conditional. The exit works when the witness refuses
and no other approved entry is outstanding at that sequence. If the
owners approved an ordinary entry there earlier and it was never
settled, a dishonest witness can settle that entry while the exit key
settles the replacement, and the group freezes. Waiting for the earlier
entry to expire does not help, because the witness can backdate.
Tooling should show an owner any approved, unsettled entry at the
current sequence before the owner approves an exit, and should say that
exiting then is a risk to the group.

Two different witness replacements at one sequence, each with an exit
receipt, are also two settlement records and freeze the group. The exit
key is held by the owners, so that is the owners' own fault.

After a witness replacement settles, heads for that entry and for later
ones are signed by the new witness.

### Anchor

`mech.anchor` is `"none"` in v1. The slot is reserved for an optional,
stronger level: one canonical store that every verifier can check for
the truth about a group.

An anchor holds at most one entry hash per `(xid, seq)`, keeps what it
holds, and is readable by anyone. A verifier of an anchored group asks
the anchor for the current head and refuses a log that disagrees. That
removes the three things v1 leaves to trust:

- A retired or dishonest witness cannot present an old prefix as
  current, even to a verifier meeting the group for the first time.
- A conflict is visible to every verifier, not only to the ones that
  happened to receive both records.
- With one more rule, the anchor's record at a sequence can choose
  between two settled siblings, so a witness can no longer end a group.

This is what ADR-013 calls a `registry-head` freshness witness. Which
store, its trust rules, and its bytes belong to a later change.

What v1 does so that the later change is an upgrade and not a break:

- The mechanism slot exists, and a verifier fails closed on a value it
  does not know.
- A group adopts an anchor with a `group.policy` entry that changes
  `mech.anchor`. A v1 verifier stops at that entry and authorizes
  nothing further. An anchored group is never checked at the weaker
  level by mistake.
- What an anchor would record is already the head's subject: the XID,
  the sequence, and the entry hash.
- The XID does not change when a group adopts an anchor.

## Head and freshness

```
head = Ed25519(
  "identikey/group/head/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 || nonce )
```

`nonce` is 32 bytes. All zero means the head answers no challenge. A
verifier rejects a head whose time is more than 300 seconds ahead of
its own clock. A head's age is the verifier's clock minus the head's
time.

A head is signed by the witness named in the state at the head's
sequence.

- A verifier keeps the highest head it has accepted per XID. It refuses
  a log that does not extend that head.
- A verifier that sent a nonce requires it back, uses the answer once,
  and forgets the nonce after the answer or after 300 seconds.
- A relying party that checks a grant in use requires a head no older
  than the grant's `head_age`.

### What a head does not give

A head says what the witness saw at a time. It does not order a relying
party's action against a later revocation. A party can read a fresh
head, a revocation can settle a moment later, and the party can still
act inside `head_age`. A nonce does not close that gap.

So v1 grants are delegation under bounded staleness, and nothing more:

- The holder of a grant acts in its own name, with its own key. A
  relying party that honors the grant accepts that a revocation or a
  policy change settled within the last `head_age` seconds may not be
  visible to it. The group chose that bound when it issued the grant.
- This standard gives no authority for an action whose effect outlasts
  the check: installing a durable binding, releasing a secret, or
  anything else that the core contract requires to be consumed once and
  ordered against a handoff ("Freshness witness for new authority",
  ADR-013 decision 4). Such an action needs an ordered consume record.
  A profile that wants one defines it, and it is a prerequisite of that
  integration.

This standard does not implement ADR-013 decision 4. Secret release is
`none`, and no consume record is defined here.

## Grants

```
Grant := { "v": 1, "group": bstr, "holder": { * tstr => any },
           "scope": { "kind": tstr, * tstr => any },
           "nbf": uint, "exp": uint, "head_age": uint, "salt": bstr }

grant_digest = SHA-256( "identikey/group/grant/v1" 0x00 || dCBOR(Grant) )
```

The log carries the digest. The holder carries the body and presents
it. A public log then shows that a grant exists and not who holds it or
what it covers.

A grant is standing when its digest is in `State.grants`. A grant is
live for a relying party when all hold:

- its digest is standing in the state at the head
- the presented body hashes to that digest, and its `group` is the XID
- `nbf <= exp`, and `nbf <= now <= exp`
- the head is no older than `head_age` seconds

The grant `salt` is 16 bytes. `head_age` is at least 1. A body that
breaks these shapes is never live.

A policy change voids earlier grants unless it restates them. That is
ADR-013's "a delegation dies at handoff unless the incoming policy
restates it."

`holder` and `scope` are typed by profiles. This standard does not
interpret them. A grant is not a Biscuit: there is no group key to root
one. Capability semantics at the relying service stay with
`identikey-capability-v1.md` or with the scope's profile.

### Forgejo CI ownership

`forgejo-ci-owner-v1` signs its own byte transcript and needs a trusted
checkpoint as input. Under this design the same decision is a grant with
`scope.kind` `forgejo-ci-owner`, the instance hostname, and the numeric
organization id, and its trusted inputs come from replay.

Decided 2026-11-26 (user): reissue the profile as a grant scope. The
profile is marked experimental and has no production binding. The
reissue is a follow-up change in this repo once this contract is
accepted, and the verifier in identikey-core is reworked after it.

Installing an owner binding is a durable action. A live grant and a
fresh head are not enough for it (see "What a head does not give").
Decided 2026-11-26 (user): the reissue change defines the ordered
consume record for that install, and Mjolnir's owner binding waits for
it. Lightning Admin's use of grants is bounded-staleness delegation and
does not.

## Transport

```
Settled      := { "op": bstr,             ; signed envelope
                  "keys": [+ bstr],       ; one per signature, wire order
                  "by": "witness" / "exit",
                  "time": uint,
                  "receipt": bstr }

LogBundle    := { "v": 1,
                  "entries": [+ Settled],
                  ? "rival": [+ Settled],
                  ? "head": { "seq": uint, "entry": bstr, "time": uint,
                              "nonce": bstr, "sig": bstr } }
```

`entries` is the whole chain in order, from sequence 0, with no gap. A
bundle that starts later or skips a sequence is rejected. `rival`
carries settled entries that compete with an entry in the chain at the
same sequence. A verifier checks a rival exactly as it checks a chain
entry, against the state at that sequence's predecessor. A rival that
verifies is a second settlement record there.

A proposal that is not yet settled does not travel in a bundle. It is
the signed op and its `keys`, checked against the state at the head.

A bundle is self-verifying. Any copy is as good as another: the OP, a
mesh hub, a git repository, a file. Where a bundle is served is a
deployment matter and is not authority.

## Verifier

Input: the group XID, a bundle, the verifier's stored head for that XID
if any, the current time, and optionally a nonce and a grant body.
Output: accept with state and head, pending, conflict, or reject with
the failing evidence. Collection, discovery, and storage sit outside.

## Map to the core governance contract

Each living requirement in
`identikey-core/openspec/specs/keyspace-governance/spec.md`, and what
this wire does with it. "Core amendment" means the core text must
change before core relies on this standard.

| Core requirement | Here |
|---|---|
| Explicit selectable governance | Implemented. The policy names four mechanism slots, unknown values fail closed, and the founding entry is the signed bootstrap. |
| Exact transition authorization | Implemented. A signature covers the kind, the group XID, the sequence, the parent (the prior accepted state), the action, and the resulting state digest. Distinct principals are counted under the prior policy. |
| Full governance handoff | Implemented for roster and policy. No group key exists, so no key is retired. |
| Optional predeclared recovery | Restricted. The only predeclared path is the exit key, and it replaces the witness and nothing else. Lost authority leaves governance unavailable, as the requirement allows. |
| Conflict and settlement semantics | Implemented by `witness-v1`. |
| Stable collective XID | Core amendment. The XID comes from the founding entry, and v1 binds no keyspace. |
| Governed collective action and identity control | Restricted to delegation. No group signing or authentication. Disclosure the requirement asks for: no party holds a whole secret, and ordering relies on one operator. |
| Registry authority is independent of discovery | No Registry. The statement it requires: the ordering authority of `witness-v1` is a single operator. |
| Version cut rejects legacy administering | Deferred. No keyspace v1 log is migrated here. |
| Collective control evidence | Core amendment. There is no identity document, binding proof, or keyspace checkpoint. The evidence is the XID, the log, and a head. |
| Handoff phases are independently abortable | Restricted. v1 has no secret and no control key to put into effect, so the four phases are: prepare is the unsigned entry, authorize is its signatures, effect is empty, and activate is settlement. An entry is abandoned before activation by letting it expire. The full machine returns with key release. Core amendment to admit this restricted profile. |
| Finality gates secret release | Settlement half implemented. Release is `none`. |
| Adapter evidence is one transition | Implemented. Four verdicts, stated maxima, and every receipt and head commits to one entry hash. |
| Freshness witness for new authority | Restricted. v1 offers no guild Sign, Auth, identity control, or secret release. A grant's holder acts in its own name under the staleness bound the grant declares. A durable installation needs an action-bound, ordered consume, which this standard does not define. Core amendment to say that delegated use under a declared bound is outside "new authority". |
| Pre-activation effects are not current | Nothing is staged in v1. A pending entry has no effect. |
| Migration finality is the outgoing descriptor | A witness replacement is settled by the outgoing witness. The exit path is the exceptional recovery "the predecessor policy already authorized". No incoming-readiness evidence is asked of the new witness, which is a restriction: a group can name a witness that never answers, and then leaves it by the exit key. |

Nothing downstream should rely on this standard for collective control
of an identity document until the core amendments land. There are four:
"Stable collective XID", "Collective control evidence", "Handoff phases
are independently abortable", and "Freshness witness for new authority".

## Prior art

**FOKS** (go-foks `05a7027`, white paper `3860270`).

- Taken: member keys recorded in the group's own chain, so it verifies
  without loading member chains. The lockout guard. Invite, accept,
  admit as the shape of the later inbox.
- Not taken: role-ordered permission levels, per-role key sequences,
  hidden Merkle locations. Useful when keys land.
- Where FOKS stops: one admin is authoritative, team chains are
  private so an outsider cannot verify current state, and there are no
  witnesses. Those three are this standard's subject.

**Eudaemon** (white paper, 2023).

- Its identifier is the master key's fingerprint, so the key can never
  rotate, and every high-authority act reassembles the whole key on one
  device. This design has no group key and never reconstructs one.
- Guardians can recombine the owner's key without consent. Quorum here
  produces signatures and leaves evidence. It never yields a secret.
- "Topology blocks" restate full state and link to the previous one.
  Taken as the `state` digest in every entry.
- Shards travel as detached blocks with only a hash on the chain. Taken
  for grants. To be taken for wrap sets when keys land.
- Critics of its chain asked for digests, not relationships, on the
  log. Taken for grants. The roster is still public in v1.
- Forks are avoided by allowing one writer. A one-owner group still
  needs the witness here, because one owner can have two devices and an
  outside verifier needs freshness either way.

**NAOMS** (hives; the TypeScript original and the Rust rewrite, read
2026-11-26 from the design docs, the roadmap, `spec/crates/chain.md`,
`spec/modules/mod-hives.md`, and `crates/chain/src/trust.rs`).

NAOMS built groups on threshold group keys first and wrote down what
that cost. It is the closest prior art for the governance half.

- Governance in the rewrite is a closed rule set counted over distinct
  persons: `AnySteward`, `StewardThreshold(n)`, `Majority`,
  `Consensus`, `Consent`. That is `quorum(k, role)`. The rewrite still
  uses threshold keys for branch signers and group key generation. It
  does not use them to decide who approved.
- In the original, a hive that declared "consensus" was keyed at
  threshold 1, so one member could change its rules and only
  application code objected. The fix was a threshold formula recomputed
  on every member add, because a fixed number "saturates". Taken as the
  `"majority"` and `"all"` forms of `k`.
- Recorded costs of signing with a threshold key: the dealer sees the
  whole key, every member add is a reshare, a new member could not sign
  until a later fix, and one dropped co-signer aborts the round.
  Confirms delegate-first.
- A removed founder kept write access because a reducer returned early
  on the creator's identity. The rewrite's rule: nothing keys on who
  created the hive. Here there is no founder key at all.
- The hive's identity is its chain, not a key, so that a rotation does
  not orphan what the hive issued. Same reasoning as the founding-entry
  XID.
- Nobody enters without invite and accept, and a recovered key carries
  its own proof of possession. Taken as "Acceptance".
- Lost-key recovery is attested by a quorum of stewards, the lost key
  takes no part, and the steward who writes the record cannot name its
  own key as the replacement. Taken as the role and key guard and
  "Lost keys".
  An unreachable threshold is shown and never clamped. Taken.
- A proposal lapses after a fixed lifetime, and "silence is never a
  yes". Taken as `exp`.
- The rule class belongs to the entry's kind and never to the author's
  choice. Already so here.
- Forks came from two entitled writers each choosing the next sequence
  number, and from in-process callers that skipped the authorization
  gate. One witness, one predecessor per entry, and one verifier
  function cover both.
- A decision is judged only after the node has an up-to-date view of
  the chain. That is the head freshness rule.
- Members sign under a per-hive pseudonym, never the root identity.
  Retrofitting that produced field defects. Not taken in v1. The roster
  note above keeps the bytes compatible.
- Not taken: consent by silence, proposals and votes as separate
  entries, a percentage threshold. For later, with keys: removal and
  key rotation as one all-or-none step, and a removal preview that
  lists what else ends.

## Open decisions

1. FROST, the anchor and Registry settlement, private logs with
   group-scoped member identifiers, and groups as members stay for
   later changes.
2. Whether `"majority"` should be the default that tooling proposes for
   `policy` and `roster`. Recommended: yes. It is 1 of 1 for a sole
   owner and grows with the roster.

Settled on 2026-11-26 by the user: the XID derivation; the Forgejo
profile; grants as bounded-staleness delegation, with the ordered
consume left to the Forgejo reissue; the `policy` rule as the root;
every key signing the entry that adds it; a trusted witness in v1, with
the anchor reserved as the optional stronger level.

## Unverified hypotheses

- **H1.** Claim: a group verifier can be built on `identikey-log`
  without changing the crate. `counter_sign` attaches signatures by
  keys other than `Op.actor` over the same `sign_digest`, `signatures_of`
  returns them in wire order, each verifies strictly under its own key,
  and the generic `verify` rejects the co-signed op. Confidence: high
  (source read, behavior not run). Verification: a test in
  `crates/identikey-log` that co-signs with two non-actor keys, checks
  each against `sign_digest`, confirms that `entry_hash` is a different
  value, and confirms that an elided entry is detectable. Synthesis:
  record the result here.
- **H2.** Claim: a `bc-xid` `XIDDocument` can be built for an XID that
  has no inception key in the document, so a group XID can be served by
  existing resolvers as a projection. Confidence: medium. Verification:
  construct one in identikey-core against the pinned `bc-xid`.
  Synthesis: record here and in the core change that adds the projection.
