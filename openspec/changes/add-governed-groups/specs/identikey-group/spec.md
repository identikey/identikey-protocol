## ADDED Requirements

### Requirement: Group identifier commits to the founding entry
A group XID SHALL be the SHA-256 digest of the domain label
`identikey/group/xid/v1`, one zero byte, and the canonical unsigned
bytes of the group's `group.found` entry. The founding body SHALL carry
a 16-byte salt and SHALL NOT carry the XID. A verifier that holds only
the XID SHALL be able to authenticate the founding entry. Roster, rule,
key, and witness changes SHALL NOT change the XID. No private key SHALL
confer control of a group by virtue of the group's inception.

#### Scenario: Verifier holds only the XID
- GIVEN a verifier configured with a group XID and nothing else about the group
- WHEN it is given a bundle whose founding entry hashes to that XID
- THEN it accepts that founding entry as the start of the log
- AND it derives the roster, rules, and witness by replay

#### Scenario: A rival founding entry
- GIVEN a founder of a group that has since replaced its owners
- WHEN the founder signs a second founding entry with a different roster and witness
- THEN that entry hashes to a different XID
- AND a verifier configured with the first XID rejects it

#### Scenario: Identity survives a handoff
- GIVEN a group whose owners, rules, and witness have all been replaced by settled entries
- WHEN a verifier replays the log
- THEN the group XID is unchanged

### Requirement: The group log is a linear chain
Entries SHALL be `identikey-log` operations of kind `group.found`,
`group.roster`, `group.policy`, `group.delegate`, or `group.revoke`.
The founding entry SHALL have sequence 0 and no parent. Every other
entry SHALL name exactly one parent, the previous settled entry, SHALL
carry the group XID, and SHALL carry a sequence one greater than its
parent's. Two entries with the same parent SHALL NOT be merged. A
verifier SHALL stop at the predecessor of an entry whose kind it does
not implement. Bodies SHALL be canonical dCBOR, and an unknown body key
SHALL fail.

#### Scenario: Sequence gap
- GIVEN a log settled through sequence 4
- WHEN an entry with sequence 6 names the sequence 4 entry as its parent
- THEN verification rejects it

#### Scenario: Two children of one parent
- GIVEN two approved entries that name the same parent
- WHEN a verifier holds both and neither has a receipt
- THEN it applies neither and reports the state at the parent

#### Scenario: Unknown kind
- GIVEN a log whose sequence 3 entry has a kind the verifier does not implement
- WHEN the verifier replays the log
- THEN it reports the state at sequence 2 and does not skip ahead

### Requirement: Roster principals are member XIDs
A roster entry SHALL name a member XID, one or more 32-byte Ed25519
approval keys, and one or more roles. A key SHALL appear under at most
one member. A member key SHALL NOT equal the witness key or the exit
key. Approvals SHALL be counted per member XID, not per key. The log
SHALL be verifiable without resolving any member's own XID document.

#### Scenario: Two devices of one member
- GIVEN a rule that needs two members and a member with two listed keys
- WHEN both of that member's keys sign an entry and no other member signs
- THEN the entry is not approved

#### Scenario: One key under two members
- GIVEN an entry whose resulting roster lists one key under two member XIDs
- WHEN a verifier applies it
- THEN verification rejects it

#### Scenario: Offline replay
- GIVEN a bundle and no network access to any member's XID document
- WHEN a verifier replays the log
- THEN it reaches the same verdict it would reach online

### Requirement: Quorum authorization per action
The policy SHALL name a rule of the form `k` of `role` for `roster` and
for `policy`, and MAY name one for `delegate` and for `revoke`. `k`
SHALL be a number, `majority`, or `all`. With `n` distinct members
holding `role` in the state before the entry, the number needed SHALL
be `k` itself, `floor(n/2) + 1`, or `n` respectively. An entry SHALL be
approved only when valid signatures over that entry come from keys of
at least that many distinct members holding `role` in the state before
the entry. The proposer SHALL be a member. A signature by a key outside
the roster SHALL NOT count. An action with no rule SHALL be
unavailable. The founding entry SHALL meet its own `policy` rule against
its own roster.

#### Scenario: Two of three owners
- GIVEN a `policy` rule of 2 of `owner` and three owners
- WHEN two different owners sign a `group.policy` entry
- THEN the entry is approved

#### Scenario: One authoritative key
- GIVEN a group founded with one owner and every rule set to 1 of `owner`
- WHEN that owner signs an entry
- THEN the entry is approved

#### Scenario: Outsider signature
- GIVEN a rule of 2 of `owner`
- WHEN one owner and one key that is not in the roster sign an entry
- THEN the entry is not approved

#### Scenario: Majority follows the roster
- GIVEN a `policy` rule of `majority` of `owner` and five owners
- WHEN two owners sign a `group.policy` entry
- THEN the entry is not approved
- AND it is approved once a third owner signs

#### Scenario: All means every holder
- GIVEN a `policy` rule of `all` of `owner` and four owners
- WHEN three owners sign a `group.policy` entry
- THEN the entry is not approved

#### Scenario: Founding without its quorum
- GIVEN a founding entry whose `policy` rule is 2 of `owner`
- WHEN only one of its listed owners has signed it
- THEN verification rejects the founding entry

#### Scenario: No delegate rule
- GIVEN a policy with no `delegate` rule
- WHEN a `group.delegate` entry is signed by every member
- THEN verification rejects it

### Requirement: Role and key changes need the rules they affect
A `group.roster` entry that changes which members hold a role, or that
changes the keys of a member who holds a role, SHALL satisfy, in
addition to the `roster` rule, every rule that names that role. An
entry SHALL be rejected when, in the resulting state, the role of any
rule has no holder, or a numeric `k` is zero or greater than the number
of distinct members holding its role. A rule that too few holders
remain to meet SHALL stay unmet. No entry and no mechanism SHALL lower
it for them.

#### Scenario: Admin mints an owner
- GIVEN rules `roster` 1 of `admin` and `policy` 2 of `owner`
- WHEN one admin alone signs an entry that gives a member the `owner` role
- THEN verification rejects it

#### Scenario: Owners add an owner
- GIVEN the same rules and a signer who holds both `admin` and `owner`
- WHEN that signer, a second owner, and a key of the member sign an entry that gives the member the `owner` role
- THEN the entry is approved

#### Scenario: Admin re-keys an owner
- GIVEN rules `roster` 1 of `admin` and `policy` 2 of `owner`
- WHEN one admin alone signs an entry that replaces an owner's keys with a key the admin holds
- THEN verification rejects it

#### Scenario: Owners re-key an owner who lost a key
- GIVEN a `policy` rule of 2 of `owner`, a `roster` rule of 2 of `owner`, and three owners, one of whom lost every key
- WHEN the other two owners and the replacement key sign an entry that sets that owner's keys to the replacement
- THEN the entry is approved

#### Scenario: Too few holders remain
- GIVEN a `policy` rule of 2 of `owner` and two owners, one of whom lost every key
- WHEN the remaining owner signs a `group.policy` entry that lowers the rule to 1
- THEN the entry is not approved and the group keeps its last state

#### Scenario: Removal would strand a rule
- GIVEN a `policy` rule of 2 of `owner` and exactly two owners
- WHEN an approved entry would drop one of them
- THEN verification rejects it

### Requirement: Incoming control signs
A governing role SHALL be a role that a rule names in the policy in
force after the entry. Every key that a `group.found` or `group.roster`
entry adds under a member who holds a governing role SHALL sign that
entry. A member who gains a governing role in an entry SHALL sign it
with at least one of that member's keys. Such a signature SHALL count
toward a rule only when its member held the rule's role before the
entry.

#### Scenario: Owner named without consent
- GIVEN a founding entry that lists three owners
- WHEN keys of only two of them have signed it
- THEN verification rejects the founding entry

#### Scenario: New owner has not signed
- GIVEN a `group.roster` entry that adds a member with the `owner` role and enough owner approvals
- WHEN no key of the new member has signed it
- THEN verification rejects it

#### Scenario: A key that was never shown to work
- GIVEN a `group.roster` entry that adds a second key to an existing owner
- WHEN that second key has not signed the entry
- THEN verification rejects it

#### Scenario: Acceptance is not approval
- GIVEN a `roster` rule of 2 of `owner` and an entry that adds a new owner
- WHEN one existing owner and the new member sign it
- THEN the entry is not approved

#### Scenario: Member with no governing role
- GIVEN a role that no rule names
- WHEN an approved `group.roster` entry adds a member with only that role and the member has not signed
- THEN the entry is approved

### Requirement: An entry expires
Every entry after the founding entry SHALL carry an expiry time in Unix
seconds. A receipt whose time is later than the entry's expiry SHALL
NOT be a settlement record. An approval SHALL NOT be reusable on any
other entry.

#### Scenario: Stale proposal completed late
- GIVEN an entry one owner signed, whose expiry has passed
- WHEN a second owner signs it and the witness receipt carries a time after the expiry
- THEN the entry is not effective

#### Scenario: Settled in time
- GIVEN an approved entry and a witness receipt whose time is before the entry's expiry
- WHEN a verifier replays the log long after the expiry
- THEN the entry is effective

### Requirement: A witness receipt settles an entry
Approval SHALL NOT make an entry effective. An entry SHALL be effective
only when it is valid, approved, and carries a receipt by the witness
key of the policy in force before it. The receipt SHALL be a strict
Ed25519 signature over the label `identikey/group/settle/v1`, one zero
byte, the group XID, the sequence as an unsigned 64-bit big-endian
integer, the entry's content hash, and the settlement time in Unix
seconds as an unsigned 64-bit big-endian integer. A receipt's time
SHALL NOT be earlier than the receipt time of the entry's parent. The
time SHALL NOT enter the state digest. The founding entry SHALL be
settled by the witness it names. An approved entry with no receipt
SHALL be pending. Two settlement records for different entries at one
sequence SHALL freeze the group at the predecessor, in either arrival
order. A receipt on an
entry that fails validation SHALL NOT be a settlement record. The
witness SHALL NOT be able to author an entry.

#### Scenario: Approved and not settled
- GIVEN an entry with enough owner signatures and no receipt
- WHEN a verifier replays the log
- THEN it reports the entry pending and the state at the predecessor

#### Scenario: One receipt chooses
- GIVEN two approved entries with the same parent and one receipt
- WHEN two verifiers see the entries in opposite orders
- THEN both treat the entry with the receipt as effective and reject the other

#### Scenario: Witness equivocates
- GIVEN two valid approved entries at one sequence, each with a witness receipt
- WHEN a verifier holds both
- THEN it reports a conflict and the state at the predecessor

#### Scenario: Receipt on an invalid entry
- GIVEN an entry that lacks its quorum and carries a witness receipt
- WHEN a verifier replays the log
- THEN the entry is rejected and the receipt does not block a valid entry at that sequence

#### Scenario: Receipt dated before its parent
- GIVEN a settled entry whose receipt time is T
- WHEN the next entry's receipt carries a time earlier than T
- THEN that receipt is not a settlement record

#### Scenario: Witness signs as a member
- GIVEN a policy whose witness key also appears as a member key
- WHEN a verifier applies the entry that would install it
- THEN verification rejects it

### Requirement: An exit witness can only replace the witness
A policy MAY name an exit key, distinct from the witness key and from
every member key. An exit receipt SHALL use the label
`identikey/group/exit/v1` over the same fields as a settlement receipt.
It SHALL be admissible only on a `group.policy` entry whose policy
differs from the prior policy in the witness and in nothing else, and
only when that entry meets the `policy` rule.

#### Scenario: Leaving a witness that refuses
- GIVEN a group whose witness will not settle anything
- WHEN the owners approve a `group.policy` entry that changes only the witness and the exit key signs its receipt
- THEN the entry is effective and later entries are settled by the new witness

#### Scenario: Exit key orders a roster change
- GIVEN an approved `group.roster` entry with an exit receipt and no witness receipt
- WHEN a verifier replays the log
- THEN the entry is pending

#### Scenario: Exit key changes a rule
- GIVEN an approved `group.policy` entry that changes the witness and also lowers a rule's `k`
- WHEN its only receipt is an exit receipt
- THEN the entry is pending

### Requirement: Head freshness and no rollback
A head SHALL be a strict Ed25519 signature by the current witness over
the label `identikey/group/head/v1`, one zero byte, the group XID, the
sequence, the entry's content hash, a time in Unix seconds, and a
32-byte nonce. A head's time SHALL NOT be earlier than the receipt time
of the entry it names. A verifier SHALL retain the highest head it has accepted
for a group and SHALL refuse a log that does not extend it. A relying
party that installs a durable binding SHALL require its own nonce in
the head and SHALL spend that nonce on install. A log that verifies
without a head that meets the caller's freshness rule SHALL NOT
authorize a new action.

#### Scenario: Rollback
- GIVEN a verifier that has accepted a head at sequence 9
- WHEN it is given a valid log and head that end at sequence 7
- THEN it refuses that log

#### Scenario: Wrong nonce
- GIVEN a relying party that issued a nonce for an install
- WHEN the head it receives carries a different nonce
- THEN it does not install

#### Scenario: Old bundle still verifies
- GIVEN a bundle from before a policy change, complete with its receipts and an old head
- WHEN it is presented as authority for a new action after the change
- THEN the action is refused

### Requirement: Grants are detached and delegation comes first
A `group.delegate` entry SHALL carry the digest of a grant and SHALL NOT
carry the grant body. The digest SHALL be SHA-256 of the label
`identikey/group/grant/v1`, one zero byte, and the grant's canonical
dCBOR. A grant SHALL name the group, a holder, a scope with a kind, a
validity window, a maximum head age, and a salt. A grant SHALL be live
only when its delegate entry is settled, no later settled entry revokes
it, every later settled `group.policy` entry lists it as kept, the
current time is inside its window, and the head is no older than its
maximum head age. Group v1 SHALL NOT define a group signing key. A
member's signature SHALL NOT be a signature of the group.

#### Scenario: Live grant
- GIVEN a settled `group.delegate` entry and the grant body whose digest it carries
- WHEN a relying party checks the body, a fresh head, and the window
- THEN the grant is live

#### Scenario: Body does not match
- GIVEN a grant body whose scope was altered after issue
- WHEN a relying party computes its digest
- THEN no settled entry carries that digest and the grant is refused

#### Scenario: Revoked
- GIVEN a grant and a later settled `group.revoke` entry that names its digest
- WHEN a relying party checks the grant against the current head
- THEN the grant is refused

#### Scenario: Policy change without keep
- GIVEN a live grant and a later settled `group.policy` entry that does not list it as kept
- WHEN a relying party checks the grant
- THEN the grant is refused

#### Scenario: Policy change with keep
- GIVEN a live grant and a later settled `group.policy` entry that lists it as kept
- WHEN a relying party checks the grant
- THEN the grant is still live

#### Scenario: Member signs as the group
- GIVEN an owner of a group and a message signed with that owner's key
- WHEN a relying party is asked to accept it as the group's signature
- THEN it refuses

### Requirement: Every entry commits to its resulting state
Every entry SHALL carry the SHA-256 digest of the canonical dCBOR of
the state after the entry is applied: sequence, roster, policy, and
live grant digests. A verifier SHALL reject an entry when its own
replay gives a different digest.

#### Scenario: Replay disagrees
- GIVEN an entry whose state digest does not match the verifier's replay
- WHEN the verifier applies it
- THEN verification rejects it even if its signatures and receipt are valid

### Requirement: Mechanisms and limits fail closed
A policy SHALL declare its authorization, settlement, and secret-release
mechanisms. Group v1 SHALL accept `quorum-v1`, `witness-v1`, and `none`
respectively, and `visibility` `public`. Any other value SHALL be
rejected. A roster SHALL hold at most 256 members. An entry SHALL carry
at most 64 signatures and SHALL be at most 65,536 bytes signed. Evidence
over a limit SHALL be rejected and SHALL NOT be truncated. No failure
SHALL fall back to a single administrator.

#### Scenario: Unknown settlement mechanism
- GIVEN a founding entry whose policy names a settlement mechanism other than `witness-v1`
- WHEN a v1 verifier reads it
- THEN it rejects the group

#### Scenario: Unknown threshold form
- GIVEN a policy whose rule carries a `k` that is not a number, `majority`, or `all`
- WHEN a v1 verifier reads it
- THEN it rejects the entry

#### Scenario: Too many signatures
- GIVEN an entry that carries 65 signatures
- WHEN a verifier reads it
- THEN it rejects the entry and does not count the first 64

#### Scenario: Stripped evidence
- GIVEN an entry that needs two owners and a receipt
- WHEN it is presented with one valid owner signature and nothing else
- THEN it is not effective

### Requirement: A group is not a keyspace
Group v1 SHALL NOT wrap, release, or rotate a secret. A grant SHALL NOT
be a wrap, and group membership SHALL NOT be keyspace membership.
`identikey-keyspace-v1` operations and bytes SHALL be unchanged by this
standard.

#### Scenario: Grant presented as a key
- GIVEN a live grant
- WHEN its holder asks a keyspace replica for a wrapped key on the strength of the grant
- THEN the replica refuses

#### Scenario: Existing keyspace log
- GIVEN a keyspace v1 log written before this standard
- WHEN a keyspace v1 consumer replays it
- THEN the result is the same as before this standard
