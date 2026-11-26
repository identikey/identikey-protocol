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

### Why this departs from ADR-013 decision 1

ADR-013 gives the guild a dedicated inception key. The XID is the hash
of that key, and a binding proof signed by that key ties the XID to a
keyspace genesis.

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

Entries are `identikey-log` ops. Signatures use the log's existing
attached, plural signatures over a stable content hash.

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
never merged. An unknown kind stops replay at its predecessor.

```
Member  := { "xid": bstr,          ; 32 bytes
             "keys": [+ bstr],     ; 32-byte Ed25519, the member's approval keys
             "roles": [+ tstr] }

Rule    := { "k": uint / "majority" / "all", "role": tstr }

Policy  := { "mech": { "auth": "quorum-v1",
                       "settle": "witness-v1",
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

Bodies are canonical dCBOR. Unknown keys fail. `roster` is sorted by
`xid`, `grants` and `keys` bytewise. `set` replaces a member whose `xid`
is already present and adds one that is not. `drop` names member XIDs.

`state` is `SHA-256` of the canonical dCBOR of `State` after the entry
is applied. A verifier whose replay gives a different digest rejects the
entry. Two implementations in different languages cannot drift without
noticing, and a later light client can start from a settled entry and
its state. `State` does not contain the XID, so the founding entry can
carry it.

Limits are fixed in v1: 256 members, 64 signatures on one entry
(approvals and acceptances together), 65,536 bytes for one signed entry. Larger evidence is rejected, not truncated.

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

`Op.actor` is the proposer and must be a member key. Its signature
counts like any other. Signatures by keys outside the roster do not
count and do not invalidate.

| Entry | Rule |
|---|---|
| `group.found` | its own `policy` rule, against its own roster |
| `group.roster` | `roster`, plus the role and key guard below |
| `group.policy` | `policy` |
| `group.delegate` | `delegate` |
| `group.revoke` | `revoke` |

An absent `delegate` or `revoke` rule makes that action unavailable.

The founding entry is signed by every key of every member who holds a
governing role (see "Acceptance"). That meets its own `policy` rule, and
it is the incoming-control evidence ADR-013 asks for. A founder cannot
name an owner who has not agreed.

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

To gain the power to pass a rule, the group must already pass that
rule. An admin under `roster: 1 of admin` cannot mint owners when
`policy` is `2 of owner`. The same admin cannot put its own key on an
owner's seat. Dropping a member changes who holds that member's roles.

### Lockout guard

An entry is rejected when, in the resulting state, any rule's role has
no holder, or a numeric `k` is zero or greater than the number of
distinct members holding the role. FOKS offers this as an opt-in. Here
it always applies.

### Acceptance

A governing role is a role that a rule names in the policy in force
after the entry.

- Every key that a `group.found` or `group.roster` entry adds under a
  member who holds a governing role signs that entry.
- A member who gains a governing role in the entry signs it with at
  least one of its keys.

Nobody is given a governing role without agreeing to it, and no key
counts toward a rule before it has been shown to work. An acceptance
signature is not an approval. It counts toward a rule only when its
member already held the rule's role before the entry.

A `group.policy` entry does not ask for acceptance from holders of a
role it newly names. An earlier quorum admitted those members.

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

A receipt's time is not later than the entry's `exp` and not earlier
than the receipt time of the entry's parent. The time dates the entry
for a reader. It is the witness's statement and is not part of the
state digest.

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

A hostile witness can block an exit only by settling a competing valid
entry at the same sequence, and it can only get one from the owners.

## Head and freshness

```
head = Ed25519(
  "identikey/group/head/v1" 0x00
  || xid || seq:u64 || entry_hash || time:u64 || nonce )
```

`nonce` is 32 bytes. All zero means the head answers no challenge. A
head's time is not earlier than the receipt time of the entry it names.

- A verifier keeps the highest head it has accepted per XID. It refuses
  a log that does not extend that head.
- A relying party that installs a durable binding sends its own nonce
  and requires it back. It spends that nonce when it installs.
- A relying party that checks a grant in use requires a head no older
  than the grant's `head_age`.

Reading of ADR-013 decision 4, to be checked by advise: the consume
record for a governed action is that action's settled log entry. It is
ordered by the witness against every later handoff. Use of a grant is
delegated action under the freshness the grant declares, which ADR-013
leaves to policy.

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

A grant is live at a head when all hold:

- a settled `group.delegate` entry carries its digest
- no later settled `group.revoke` names it
- every later settled `group.policy` entry lists it in `keep`
- `nbf <= now <= exp`
- the head is no older than `head_age` seconds

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

## Transport

```
LogBundle := { "v": 1,
               "entries": [ { "op": bstr,          ; signed envelope
                              "by": "witness" / "exit",
                              "time": uint,
                              "receipt": bstr } ],
               ? "head": { "seq": uint, "entry": bstr, "time": uint,
                           "nonce": bstr, "sig": bstr } }
```

A bundle is self-verifying. Any copy is as good as another: the OP, a
mesh hub, a git repository, a file. Where a bundle is served is a
deployment matter and is not authority.

## Verifier

Input: the group XID, a bundle, the verifier's stored head for that XID
if any, the current time, and optionally a nonce and a grant body.
Output: accept with state and head, pending, conflict, or reject with
the failing evidence. Collection, discovery, and storage sit outside.

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

1. FROST, Registry settlement, private logs with group-scoped member
   identifiers, and groups as members stay for later changes.
2. Whether `"majority"` should be the default that tooling proposes for
   `policy` and `roster`. Recommended: yes. It is 1 of 1 for a sole
   owner and grows with the roster.

Settled: the XID derivation and the Forgejo profile (2026-11-26, user).
Proof of possession for incoming holders is now required (see
"Acceptance").

## Unverified hypotheses

- **H1.** Claim: `identikey-log` `counter_sign` and `signatures_of`
  let a verifier check several signatures by keys other than
  `Op.actor` over one stable `content_hash`. Confidence: high (API
  names read, behavior not run). Verification: a test in
  `crates/identikey-log` that co-signs with two non-actor keys and
  verifies each. Synthesis: record the result here.
- **H2.** Claim: a `bc-xid` `XIDDocument` can be built for an XID that
  has no inception key in the document, so a group XID can be served by
  existing resolvers as a projection. Confidence: medium. Verification:
  construct one in identikey-core against the pinned `bc-xid`.
  Synthesis: record here and in the core change that adds the projection.
