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
verifier SHALL stop at the predecessor of an entry whose kind, or whose
policy mechanism value, it does not implement, and SHALL NOT authorize
a new action for that group on the earlier state. Bodies SHALL be canonical dCBOR, and an unknown key at
any depth SHALL fail. An entry SHALL have a body, SHALL have no
dependencies, negative acknowledgements, target fingerprint, or
timestamp, and SHALL carry no elided, salted, or undefined assertion.

#### Scenario: Sequence gap
- GIVEN a log settled through sequence 4
- WHEN an entry with sequence 6 names the sequence 4 entry as its parent
- THEN verification rejects it

#### Scenario: Two children of one parent
- GIVEN two approved entries that name the same parent
- WHEN a verifier holds both and neither has a receipt
- THEN it applies neither and reports the state at the parent

#### Scenario: Second parent
- GIVEN an entry that names two parents
- WHEN a verifier reads it
- THEN verification rejects it

#### Scenario: Unknown body key
- GIVEN a `group.roster` body with a key this standard does not define, inside a member map
- WHEN a verifier reads it
- THEN verification rejects it

#### Scenario: Elided entry
- GIVEN an entry in which one assertion has been replaced by its digest
- WHEN a verifier reads it
- THEN verification rejects it even though its signatures still verify

#### Scenario: Unknown kind
- GIVEN a log whose sequence 3 entry has a kind the verifier does not implement
- WHEN the verifier replays the log
- THEN it reports the state at sequence 2 and does not skip ahead
- AND it authorizes no new action for that group

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

### Requirement: Member signatures are exact
A member signature SHALL be a strict Ed25519 signature over the 32-byte
SHA-256 Gordian digest of the entry's wrapped unsigned envelope. It
SHALL NOT be a signature over the entry's content hash. Every signing
key SHALL be a valid, non-weak Ed25519 verification key. An entry SHALL
be presented with one key per attached signature, in wire order. Each
signature SHALL verify under its key, each key SHALL be a key of the
roster before the entry or a key the entry adds, and no key SHALL
appear twice. An entry that fails any of these SHALL be rejected as
presented. The proposer named by the entry SHALL be among its signers.
No signature algorithm other than Ed25519 SHALL be accepted in v1.

#### Scenario: Signature over the content hash
- GIVEN an entry whose only signature was made over its BLAKE3 content hash
- WHEN a verifier checks it
- THEN verification rejects it

#### Scenario: Co-signers who are not the proposer
- GIVEN an entry proposed by one owner and co-signed by two other owners
- WHEN a group verifier checks each signature under its own key
- THEN all three count as approvals

#### Scenario: Unattributable signature
- GIVEN an entry with enough owner signatures and one more signature by a key that is in no roster and is not added by the entry
- WHEN a verifier checks it
- THEN the entry as presented is rejected

#### Scenario: Same key twice
- GIVEN an entry that carries two signatures by one key
- WHEN a verifier checks it
- THEN the entry as presented is rejected

#### Scenario: Proposer did not sign
- GIVEN an entry that names an owner as proposer and carries signatures by two other owners only
- WHEN a verifier checks it
- THEN verification rejects it

#### Scenario: Weak key
- GIVEN an entry that adds a member key that is a small-order Ed25519 point
- WHEN a verifier checks it
- THEN verification rejects it

#### Scenario: Post-quantum signature
- GIVEN an entry that carries an ML-DSA signature
- WHEN a v1 verifier checks it
- THEN verification rejects it

### Requirement: Quorum authorization per action
The policy SHALL name a rule of the form `k` of `role` for `roster` and
for `policy`, and MAY name one for `delegate` and for `revoke`. `k`
SHALL be a number, `majority`, or `all`. With `n` distinct members
holding `role` in the state before the entry, the number needed SHALL
be `k` itself, `floor(n/2) + 1`, or `n` respectively. An entry SHALL be
approved only when valid signatures over that entry come from keys of
at least that many distinct members holding `role` in the state before
the entry. The proposer SHALL be a member. An action with no rule SHALL
be unavailable. The founding entry SHALL meet its own `policy` rule against
its own roster.

#### Scenario: Two of three owners
- GIVEN a `policy` rule of 2 of `owner` and three owners
- WHEN two different owners sign a `group.policy` entry
- THEN the entry is approved

#### Scenario: One authoritative key
- GIVEN a group founded with one owner and every rule set to 1 of `owner`
- WHEN that owner signs an entry
- THEN the entry is approved

#### Scenario: Member without the role
- GIVEN a rule of 2 of `owner`
- WHEN one owner and one member who does not hold `owner` sign an entry
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

### Requirement: The policy rule is the root
A `group.policy` entry that meets the `policy` rule SHALL be able to
replace every other rule, the witness, and the exit key. A threshold on
another action SHALL NOT bind the members who can pass the `policy`
rule. An entry that changes the `policy` rule, the members who hold its
role, or the keys of those members SHALL meet the `policy` rule as it
stood before that entry. Such an entry MAY leave the rule passable by
members who could not pass it before.

#### Scenario: Policy rewrites a stricter rule
- GIVEN rules `policy` 1 of `admin`, `roster` 1 of `admin`, and `delegate` 2 of `owner`
- WHEN one admin signs a `group.policy` entry that sets `delegate` to 1 of `admin`, and then signs a `group.delegate` entry alone
- THEN both entries are approved

#### Scenario: Rule removed and restored around a roster change
- GIVEN the same rules
- WHEN one admin removes the `delegate` rule by a `group.policy` entry, gives itself the `owner` role by a `group.roster` entry, and restores the rule by a second `group.policy` entry
- THEN all three entries are approved

#### Scenario: Owners lower their own threshold
- GIVEN owners A and B and a `policy` rule of 2 of `owner`
- WHEN A and B sign a `group.policy` entry that sets the rule to 1 of `owner`
- THEN the entry is approved, and A alone can pass the `policy` rule afterward

#### Scenario: A majority drops the rest
- GIVEN owners A, B, and C, with `policy` and `roster` both `majority` of `owner`
- WHEN A and B sign a `group.roster` entry that drops B and C
- THEN the entry is approved, and A alone can pass both rules afterward

#### Scenario: The root cannot be reached from below
- GIVEN rules `roster` 1 of `admin` and `policy` 2 of `owner`, and an admin who is not an owner
- WHEN that admin alone signs any `group.roster` entry that adds an owner, drops an owner, or changes an owner's keys
- THEN verification rejects it

### Requirement: Role and key changes need the rules they affect
A `group.roster` entry that changes which members hold a role, or that
changes the keys of a member who holds a role, SHALL satisfy, in
addition to the `roster` rule, every rule that names that role. An
entry SHALL be rejected when, in the resulting state, the role of any
rule has no holder, or a numeric `k` is zero or greater than the number
of distinct members holding its role, or the rule needs more than 48
members. A rule that too few holders
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

#### Scenario: All of forty-nine
- GIVEN 49 members who hold a role
- WHEN a `group.policy` entry that is otherwise approved sets a rule to `all` of that role
- THEN verification rejects it

#### Scenario: Majority crosses the limit
- GIVEN a rule of `majority` of a role held by 95 members
- WHEN an otherwise approved `group.roster` entry gives a 96th member that role
- THEN verification rejects it

#### Scenario: Too few holders remain
- GIVEN a `policy` rule of 2 of `owner` and two owners, one of whom lost every key
- WHEN the remaining owner signs a `group.policy` entry that lowers the rule to 1
- THEN the entry is not approved and the group keeps its last state

#### Scenario: Removal would strand a rule
- GIVEN a `policy` rule of 2 of `owner` and exactly two owners
- WHEN an approved entry would drop one of them
- THEN verification rejects it

### Requirement: Every key signs the entry that adds it
For an entry after the founding entry, the old keys SHALL be the keys
of the roster before the entry and the added keys SHALL be the keys of
the roster after the entry that are not old keys. For the founding
entry every key SHALL be an added key. Every added key SHALL sign its
entry, whatever roles its member holds. A member who gains a role in a `group.roster` entry
SHALL sign that entry with at least one of that member's keys. Such a
signature SHALL count toward a rule only when its member held the
rule's role before the entry. A `group.policy` entry SHALL NOT require
a signature from members whose role it gives a new power.

#### Scenario: Member named without consent
- GIVEN a founding entry that lists three members
- WHEN keys of only two of them have signed it
- THEN verification rejects the founding entry

#### Scenario: New member has not signed
- GIVEN a `group.roster` entry that adds a member and has enough approvals
- WHEN no key of the new member has signed it
- THEN verification rejects it

#### Scenario: New member with a role no rule names
- GIVEN a role that no rule names
- WHEN an approved `group.roster` entry adds a member with only that role and the member's key has not signed
- THEN verification rejects it

#### Scenario: A key that was never shown to work
- GIVEN a `group.roster` entry that adds a second key to an existing member
- WHEN that second key has not signed the entry
- THEN verification rejects it

#### Scenario: Promotion without consent
- GIVEN a `group.roster` entry that gives an existing member the `owner` role, with enough approvals
- WHEN no key of that member has signed it
- THEN verification rejects it

#### Scenario: Acceptance is not approval
- GIVEN a `roster` rule of 2 of `owner` and an entry that adds a new owner
- WHEN one existing owner and the new member sign it
- THEN the entry is not approved

#### Scenario: A policy change makes a role governing
- GIVEN members who hold a role that no rule names, each of whose keys signed the entry that added it
- WHEN a `group.policy` entry that meets the `policy` rule names that role in a rule
- THEN the entry is approved without signatures from those members
- AND every key that can now count toward that rule has signed an earlier entry

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
seconds as an unsigned 64-bit big-endian integer. Several receipts for
one entry SHALL be one settlement record, whatever their times. Receipt
times SHALL NOT be compared with one another, with a parent's receipt,
or with a head. The time SHALL NOT enter the state digest. The founding
entry SHALL be
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

#### Scenario: Two receipts for one entry
- GIVEN an entry with valid witness receipts at times 10 and 20, both before its expiry, and a child entry with a receipt at time 15
- WHEN one verifier is given the first receipt and another is given the second
- THEN both report the same chain and the same state

#### Scenario: Receipt by the wrong key
- GIVEN an approved entry and a receipt signed by a key that is not the witness of the policy in force before it
- WHEN a verifier replays the log
- THEN the entry is pending

#### Scenario: Receipt for another group
- GIVEN an approved entry and a witness receipt whose transcript names a different group XID
- WHEN a verifier replays the log
- THEN the entry is pending

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
only when that entry meets the `policy` rule. Heads over that entry and
later entries SHALL be signed by the new witness.

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
A head SHALL be a strict Ed25519 signature, by the witness named in the
state at the head's sequence, over the label `identikey/group/head/v1`, one zero byte, the group XID, the
sequence, the entry's content hash, a time in Unix seconds, and a
32-byte nonce. A verifier SHALL reject a head whose time is more than
60 seconds ahead of its own clock, and SHALL take a head's age as its
own clock minus the head's time, or zero when the head's time is ahead. A verifier SHALL retain the highest
head it has accepted for a group and SHALL refuse a log that does not
extend it. Given two valid chains for one group where one extends the
other, a verifier SHALL use the longer. A verifier that sent a nonce
SHALL require it in the head, SHALL use that head once, and SHALL
discard the nonce after 300 seconds. A log that verifies without a head
that meets the caller's freshness rule SHALL NOT authorize a new
action.

#### Scenario: Rollback
- GIVEN a verifier that has accepted a head at sequence 9
- WHEN it is given a valid log and head that end at sequence 7
- THEN it refuses that log

#### Scenario: Head from the future
- GIVEN a head whose time is one hour ahead of the verifier's clock
- WHEN the verifier checks it
- THEN it rejects the head

#### Scenario: Wrong nonce
- GIVEN a verifier that sent a nonce with its request
- WHEN the head it receives carries a different nonce
- THEN it refuses that head

#### Scenario: Retired witness answers a verifier that knows better
- GIVEN a verifier that has accepted a head at sequence 9, and a witness that the entry at sequence 7 replaced
- WHEN the retired witness signs a fresh head over sequence 6 with the verifier's nonce
- THEN the verifier refuses it

#### Scenario: First contact with two sources
- GIVEN a verifier meeting a group for the first time, a bundle that ends at sequence 6 with a fresh head by the witness named there, and a valid bundle that runs to sequence 9 and replaces that witness at sequence 7
- WHEN it is given both
- THEN it uses the longer chain and refuses the head over sequence 6

#### Scenario: Head signed by the outgoing witness after its replacement
- GIVEN a settled entry at sequence 7 that replaces the witness
- WHEN the outgoing witness signs a head over sequence 7
- THEN the verifier refuses that head

#### Scenario: Old bundle, verifier knows better
- GIVEN a bundle from before a policy change, complete with its receipts and its head, and a verifier that has accepted a head after the change
- WHEN the bundle is presented as authority for a new action
- THEN the action is refused

#### Scenario: Old bundle, head too old
- GIVEN the same bundle and a verifier that has not seen the change
- WHEN the bundle's head is older than the caller's freshness rule allows
- THEN the action is refused

#### Scenario: Head slightly ahead
- GIVEN a head dated 60 seconds ahead of the verifier's clock and a grant with a maximum head age of 60 seconds
- WHEN the verifier checks the grant now
- THEN the head's age is zero and the grant is live
- AND 121 seconds later the head's age is 61 seconds and the grant is refused

### Requirement: Grants are detached and delegation comes first
A `group.delegate` entry SHALL carry the digest of a grant and SHALL NOT
carry the grant body. The digest SHALL be SHA-256 of the label
`identikey/group/grant/v1`, one zero byte, and the grant's canonical
dCBOR. A grant SHALL name the group, a holder, a scope with a kind, a
validity window, a maximum head age of at least one second, and a
16-byte salt. A grant SHALL be live only when its digest is standing in
the state at the head, the presented body hashes to that digest and
names this group, the current time is inside its window, and the head
is no older than its maximum head age. Group v1 SHALL NOT define a group signing key. A
member's signature SHALL NOT be a signature of the group.

#### Scenario: Live grant
- GIVEN a settled `group.delegate` entry and the grant body whose digest it carries
- WHEN a relying party checks the body, a fresh head, and the window
- THEN the grant is live

#### Scenario: Body does not match
- GIVEN a grant body whose scope was altered after issue
- WHEN a relying party computes its digest
- THEN no settled entry carries that digest and the grant is refused

#### Scenario: Grant for another group
- GIVEN a grant body that names a different group and whose digest is standing in this group
- WHEN a relying party checks it
- THEN the grant is refused

#### Scenario: Outside the window
- GIVEN a standing grant whose window ended yesterday
- WHEN a relying party checks it against a fresh head
- THEN the grant is refused

#### Scenario: Head too old
- GIVEN a standing grant with a maximum head age of 60 seconds
- WHEN a relying party holds a head that is 120 seconds old
- THEN the grant is refused

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

### Requirement: A grant is delegation under bounded staleness
The holder of a grant SHALL act in its own name. A relying party that
honors a live grant SHALL treat a revocation or policy change settled
within the grant's maximum head age plus the 60-second clock tolerance
as possibly not yet visible. A live
grant and a head SHALL NOT by themselves authorize an action whose
effect outlasts the check, including a durable binding and a secret
release. Group v1 SHALL NOT define a consume record.

#### Scenario: Revoked inside the bound
- GIVEN a grant with a maximum head age of 60 seconds, and a relying party holding a head 30 seconds old
- WHEN a revocation of that grant settles and the relying party checks the grant against the head it holds
- THEN the grant is live for that check
- AND it is refused once the relying party holds a head that includes the revocation

#### Scenario: Policy change inside the bound
- GIVEN a grant with a maximum head age of 60 seconds, and a relying party holding a head 30 seconds old
- WHEN a `group.policy` entry that does not keep the grant settles and the relying party checks the grant against the head it holds
- THEN the grant is live for that check
- AND it is refused once the relying party holds a head that includes the policy change

#### Scenario: Durable binding on a head alone
- GIVEN a live grant and a fresh head that carries the relying party's nonce
- WHEN the relying party asks whether this standard authorizes it to install a binding that persists after the check
- THEN it does not

#### Scenario: Handoff races an install
- GIVEN a relying party that read a fresh head showing a live grant, and a policy change that voids the grant and settles before the party acts
- WHEN the party looks to this standard for an ordering between its action and the policy change
- THEN it finds none, and a profile that needs one defines an ordered consume record

### Requirement: The witness is trusted for currentness in v1
Settlement under `witness-v1` SHALL rely on a single operator for
ordering, for its clock, and for currentness. A witness SHALL NOT be
able to change a roster or a policy, to issue or restore a grant, or to
make effective an entry that lacks its approvals. The standard SHALL
state that a witness can refuse to settle, can date a receipt as it
chooses, can settle two approved entries at one sequence, and can sign
a head over an entry that is no longer the latest.

#### Scenario: Backdated receipt
- GIVEN an approved entry whose expiry passed yesterday and that was never settled
- WHEN the witness signs a receipt today that carries a time before the expiry
- THEN a verifier treats the entry as effective, and this standard does not detect the backdating

#### Scenario: First contact with one stale source
- GIVEN a verifier meeting a group for the first time and shown only a valid bundle that ends before a witness replacement, with a fresh head by the witness named there
- WHEN it verifies
- THEN it accepts, and this standard does not detect that the bundle is stale

#### Scenario: Witness tries to add a member
- GIVEN a `group.roster` entry that lacks its approvals and carries a valid witness receipt
- WHEN a verifier replays the log
- THEN the entry is rejected

### Requirement: A freeze is permanent and remembered
Two settlement records for different entries at one sequence SHALL
freeze the group at the predecessor, whichever keys signed the
receipts. No later entry, receipt, or witness replacement SHALL clear
a freeze in v1. A verifier that has verified both records SHALL store
the conflict durably, SHALL report conflict for that group afterward
whatever bundle it is given, and SHALL treat no grant of that group as
live.

#### Scenario: Exit races an earlier approved entry
- GIVEN an approved, unsettled `group.roster` entry at sequence 4 and a later approved witness replacement at sequence 4
- WHEN the witness settles the roster entry and the exit key settles the replacement
- THEN a verifier that holds both reports a conflict and the state at sequence 3

#### Scenario: Two exits
- GIVEN two different approved witness replacements at one sequence, each with an exit receipt
- WHEN a verifier holds both
- THEN it reports a conflict and the state at the predecessor

#### Scenario: Restart after a freeze
- GIVEN a verifier that recorded a conflict for a group and then restarted
- WHEN it is given a bundle that contains only one of the two entries
- THEN it still reports a conflict

#### Scenario: Grant under a freeze
- GIVEN a verifier that recorded a conflict for a group at sequence 4, and a grant standing in the state at sequence 3
- WHEN a relying party checks the grant with that verifier
- THEN the grant is refused

#### Scenario: Replacement after a freeze
- GIVEN a frozen group
- WHEN its owners approve a new witness replacement at the frozen sequence and the exit key settles it
- THEN verifiers that know of the conflict still report a conflict

### Requirement: Replay is a total function of the entries
Replay SHALL depend on the entries alone and SHALL NOT read a clock or
a grant body. The state SHALL be the sequence, the roster, the policy,
and the standing grant digests. Every array in a body and in the state
SHALL be sorted ascending without duplicates. The optional arrays of a
body SHALL be omitted when empty, and a present empty one SHALL fail.
The standing grant digests of the state SHALL be present and MAY be
empty. A
`group.roster` entry SHALL remove the members it drops and SHALL
replace or add the members it sets. A `group.policy` entry SHALL
replace the policy and SHALL leave standing exactly the digests it
keeps, each of which SHALL have been standing before it. A
`group.delegate` entry SHALL add a digest that is not standing. A
`group.revoke` entry SHALL remove a digest that is standing. An entry
after the founding entry that leaves the state unchanged apart from the
sequence SHALL fail. A member in `set` that equals the member already
present SHALL fail the entry. A key SHALL NOT pass from one member to
another in one entry. A bundle SHALL carry the whole chain from
sequence 0 with no gap.

#### Scenario: Same log, different clocks
- GIVEN one bundle with a standing grant whose body is not available
- WHEN two verifiers replay it a year apart
- THEN both compute the same state digests at every sequence

#### Scenario: Founding with no grants
- GIVEN a founding entry
- WHEN a verifier computes its state
- THEN the standing grant digests are an empty array, and the entry is accepted

#### Scenario: Last grant revoked
- GIVEN a group with one standing grant
- WHEN a `group.revoke` entry that meets the `revoke` rule names it
- THEN the entry is approved and the standing grant digests are an empty array

#### Scenario: Policy restated with every grant kept
- GIVEN a group with two standing grants
- WHEN a `group.policy` entry carries the same policy and keeps both
- THEN verification rejects it

#### Scenario: Policy restated with fewer grants kept
- GIVEN a group with two standing grants
- WHEN a `group.policy` entry that meets the `policy` rule carries the same policy and keeps one
- THEN the entry is approved and one grant is standing

#### Scenario: Unchanged member beside a changed one
- GIVEN a `group.roster` entry whose `set` lists one member with a new role and one member exactly as already present
- WHEN a verifier applies it
- THEN verification rejects it

#### Scenario: Key moved between members
- GIVEN a key listed under member A
- WHEN a `group.roster` entry removes it from A and lists it under member B
- THEN verification rejects it

#### Scenario: Member in both set and drop
- GIVEN a `group.roster` entry that names one XID in `set` and in `drop`
- WHEN a verifier applies it
- THEN verification rejects it

#### Scenario: Drop of an unknown member
- GIVEN a `group.roster` entry whose `drop` names an XID that is not in the roster
- WHEN a verifier applies it
- THEN verification rejects it

#### Scenario: Unsorted roster
- GIVEN an entry whose `set` lists two members out of XID order
- WHEN a verifier applies it
- THEN verification rejects it

#### Scenario: Keep cannot restore a grant
- GIVEN a grant that an earlier `group.policy` entry voided
- WHEN a later `group.policy` entry lists its digest in `keep`
- THEN verification rejects that entry

#### Scenario: Revoke of a grant that is not standing
- GIVEN a digest that was never delegated
- WHEN a `group.revoke` entry names it
- THEN verification rejects it

#### Scenario: Delegated twice
- GIVEN a standing grant
- WHEN a `group.delegate` entry carries the same digest
- THEN verification rejects it

#### Scenario: Issued again after revocation
- GIVEN a grant that was delegated and then revoked
- WHEN a new `group.delegate` entry that meets the `delegate` rule carries the same digest
- THEN the grant is standing again

#### Scenario: Bundle with a gap
- GIVEN a bundle whose entries run 0, 1, 3
- WHEN a verifier reads it
- THEN it rejects the bundle

### Requirement: Every entry commits to its resulting state
Every entry SHALL carry the SHA-256 digest of the canonical dCBOR of
the state after the entry is applied. A verifier SHALL reject an entry
when its own replay gives a different digest.

#### Scenario: Replay disagrees
- GIVEN an entry whose state digest does not match the verifier's replay
- WHEN the verifier applies it
- THEN verification rejects it even if its signatures and receipt are valid

### Requirement: Mechanisms and limits fail closed
A policy SHALL declare its authorization, settlement, anchor, and
secret-release mechanisms. Group v1 SHALL accept `quorum-v1`,
`witness-v1`, `none`, and `none` respectively, and `visibility`
`public`. Any other value SHALL be rejected. A roster SHALL hold at
most 256 members, and a member SHALL hold at most 8 keys. An entry
after the founding entry SHALL carry at most 64 signatures by old keys
and SHALL add at most 16 keys. The founding entry SHALL be exempt from
the limit of 16, its roster SHALL hold at most 64 keys, and it SHALL
carry no signature other than those of its roster's keys. Each
signature SHALL be counted once. An entry SHALL be at most 65,536 bytes
signed. Evidence over a limit SHALL be rejected and SHALL NOT be
truncated. No failure SHALL fall back to a
single administrator.

#### Scenario: Unknown settlement mechanism
- GIVEN a founding entry whose policy names a settlement mechanism other than `witness-v1`
- WHEN a v1 verifier reads it
- THEN it rejects the group

#### Scenario: Unknown threshold form
- GIVEN a policy whose rule carries a `k` that is not a number, `majority`, or `all`
- WHEN a v1 verifier reads it
- THEN it rejects the entry

#### Scenario: Group adopts an anchor
- GIVEN a group whose sequence 5 entry is a `group.policy` entry that names an anchor mechanism other than `none`
- WHEN a v1 verifier replays the log
- THEN it stops at sequence 4 and authorizes no new action for that group

#### Scenario: First contact before an anchor adoption
- GIVEN a group that adopted an anchor at sequence 5, and a v1 verifier meeting it for the first time
- WHEN the verifier is shown only the entries through sequence 4 and a fresh head by the witness named there
- THEN it accepts, and this standard does not detect that the group has since adopted an anchor

#### Scenario: Too many signatures
- GIVEN an entry that carries 65 signatures by keys already on the roster
- WHEN a verifier reads it
- THEN it rejects the entry and does not count the first 64

#### Scenario: Founding with seventeen keys
- GIVEN a founding entry whose roster holds 17 keys, all of which signed it
- WHEN a verifier reads it
- THEN the limit of 16 added keys does not apply and the entry is accepted

#### Scenario: Founding with sixty-four keys
- GIVEN a founding entry whose roster holds 64 keys, all of which signed it
- WHEN a verifier reads it
- THEN the entry is accepted

#### Scenario: Founding with sixty-five keys
- GIVEN a founding entry whose roster holds 65 keys
- WHEN a verifier reads it
- THEN it rejects the entry

#### Scenario: Removed key still approves
- GIVEN an owner whose key an approved `group.roster` entry removes
- WHEN that key signs the entry
- THEN the signature counts as that owner's approval and as one signature by an old key

#### Scenario: Too many keys added
- GIVEN a `group.roster` entry that adds 17 keys
- WHEN a verifier reads it
- THEN it rejects the entry

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
