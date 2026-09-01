# identikey-keyspace (ADDED)

Protocol-tier shared keyspace. Living file after fold/act:
`docs/standards/identikey-keyspace-v1.md`.

## ADDED Requirements

### Requirement: Distributed keyspace object
The system SHALL treat a keyspace as the composition of the keys that
comprise it, kept alive by holders of admin keys, and SHALL NOT house
it as a document at a single server, node, or database.

#### Scenario: Admin keys keep it alive
- GIVEN at least one holder of an admin key
- WHEN that holder replicates and signs keyspace ops
- THEN the keyspace remains available to other holders

#### Scenario: No home at identikey-core
- GIVEN identikey-core Postgres
- WHEN a keyspace roster is queried there
- THEN that row is a cache of identikey-log ops, not the source of truth

### Requirement: Keyspace identifier
The system SHALL identify a keyspace by the identikey-log content hash
of its genesis op (`blake3` of the canonical unsigned envelope), SHALL
treat the first `keyspace.join` that installs an admin roster entry and
a PTK wrap-list as outer genesis, SHALL treat `keyspace.nest` as inner
genesis, and SHALL NOT introduce a second identifier or an eighth kind.

#### Scenario: Cite the genesis hash
- GIVEN a signed genesis op with content hash H
- WHEN a later op names that keyspace
- THEN the id in the op body is H

#### Scenario: Outer genesis is the first join
- GIVEN no prior keyspace ops
- WHEN the first `keyspace.join` installs at least one admin entry and
  a PTK wrap-list
- THEN that join's content hash is the keyspace id

#### Scenario: Nested keyspace is its own genesis
- GIVEN an outer keyspace H and a `keyspace.nest` op
- WHEN holders refer to the inner keyspace
- THEN they use the nest op's content hash, not a field on H

### Requirement: Op kinds
The system SHALL use these identikey-log kind strings and no `guild.*`
kinds: `keyspace.join`, `keyspace.change`, `keyspace.leave`,
`keyspace.assign-node`, `keyspace.nest`, `keyspace.epoch-begin`,
`keyspace.epoch-commit`.

#### Scenario: Leave is its own kind
- GIVEN a member on the roster
- WHEN that member is removed
- THEN holders append `keyspace.leave`, not a wrap-kind or kick-kind

#### Scenario: Kick is not a kind
- GIVEN an operator removes a member and optionally starts an epoch
- WHEN ops are appended
- THEN blacklist/roster lives on `leave` / `change` and cryptographic
  eviction lives on `epoch-begin` / `epoch-commit`

### Requirement: Log actor vs wrap target
The system SHALL use identikey-log Ed25519 `actor` keys as the only
authors of `keyspace.*` ops, and SHALL treat P-256 public keys as
wrap-targets only. This change SHALL NOT modify identikey-log.

#### Scenario: P-256 cannot administer
- GIVEN a member whose classical identity is P-256 only
- WHEN a PTK wrap to that P-256 key is on the wrap-list
- THEN that member can unwrap and SHALL NOT be a valid `actor` on a
  `keyspace.*` op

#### Scenario: Ed25519 admin companion
- GIVEN a holder who also has an Ed25519 key with `admin: true`
- WHEN that holder appends `keyspace.change`
- THEN verifiers accept the op if the actor matches that roster entry

### Requirement: Admin field on roster
The system SHALL carry an `admin` boolean on each roster entry in
`keyspace.join` and `keyspace.change` bodies, SHALL remove the entry
on `keyspace.leave`, and SHALL reject `join` / `change` / `leave` /
`assign-node` / `nest` / `epoch-begin` / `epoch-commit` whose actor is
not currently `admin: true`.

#### Scenario: Member cannot kick
- GIVEN a roster entry with `admin: false`
- WHEN that member's Ed25519 key authors `keyspace.leave`
- THEN holders reject the op

#### Scenario: Last admin fade
- GIVEN the last `admin: true` entry leaves or is removed
- WHEN no remaining holder has an admin key
- THEN the keyspace fades; no further administering ops verify

### Requirement: Self-describing CBOR wrap
The system SHALL encode each PTK wrap as a CBOR map that carries an
algorithm tag and raw ciphertext bytes, and SHALL accept these v1 tags:
`x25519-xchacha20poly1305` (Ed25519 PUK, X25519 via RFC 7748) and
`p256-xchacha20poly1305`.

#### Scenario: Wrap is CBOR, not a side box
- GIVEN a PTK wrapped to a member's latest PUK
- WHEN the wrap is placed in an op body
- THEN the wrap is a CBOR map with an algorithm tag and raw byte
  strings, not a base64 or NaCl-only binary blob beside the op

#### Scenario: Unknown wrap tag
- GIVEN a wrap whose algorithm tag is not a v1 tag
- WHEN a v1 holder applies the wrap-list
- THEN that wrap is not treated as a successful unwrap

### Requirement: Device cascade without device objects
The system SHALL name the cascade device-revoke → PUK rotate → rewrap
to latest PUK, and SHALL NOT specify device-key objects or device-revoke
ops on the keyspace log.

#### Scenario: Device revoke is outside this log
- GIVEN a member device is revoked
- WHEN the keyspace wrap-list is updated
- THEN the update is a rewrap to that member's latest PUK via
  `change` / epoch ops, not a device-key kind

### Requirement: Two profiles
The system SHALL name two profiles on one spec: house/buyer (configurable
epoch, kick can rekey) and access-node (high churn, long epoch, lower
assurance, nested after assign-node).

#### Scenario: Access-node is nested
- GIVEN a node assigned to an outer house keyspace
- WHEN the access-node keyspace is created
- THEN it is a `keyspace.nest` inner genesis, not a rename of the outer

### Requirement: Three layers uncollapsed
The system SHALL treat keyspace membership as identity/key-management,
and SHALL NOT treat a Biscuit as membership or a Recrypt group as a
keyspace.

#### Scenario: Mixing layers is a protocol error
- GIVEN a Recrypt recryption group or a Biscuit attenuation
- WHEN specifying who holds a keyspace PTK
- THEN that group or token is not the keyspace roster

### Requirement: Test-vector hooks
The spec SHALL name test-vector slots for genesis id, each op kind, and
each v1 wrap tag. Filled byte fixtures are not owed by this change.

#### Scenario: Hooks present without fixtures
- GIVEN `docs/standards/identikey-keyspace-v1.md`
- WHEN an implementer looks for vectors
- THEN named slots exist for genesis hash, seven kinds, and two wrap
  tags, even if fixture files are empty or absent
