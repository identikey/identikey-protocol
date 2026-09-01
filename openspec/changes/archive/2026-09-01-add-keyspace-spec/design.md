# Design — identikey keyspace v1

Steer 2026-08-31 / 2026-09-01 on `ikp-cvu` is the source. This file
does not re-open those decisions. Independent read is the advise pass
(reader Grok 4.6).

## What a keyspace is

A keyspace is a **distributed object**: the keys that comprise it. It
does not live in a place. It is not a document housed at identikey-core,
on one mesh node, or in Postgres. Anyone holding an admin key keeps it
alive. If every admin key is gone or stops participating, the object
fades. Holders replicate a signed artifact (roster, wrap-list, nested
ids). That artifact is evidence of the object, not its home.

XID stays who-I-am. Join/leave is not an Elect rewrite of the member
XID.

## Methods (FOKS, not FOKS-the-product)

| Layer | Name | Role | This spec |
|---|---|---|---|
| Device | device key | per-device; revoke cascades | cascade rule only; not a protocol object |
| User | PUK | per-identikey user key; latest PUK is the wrap target | identity keys already specified |
| Keyspace | PTK | per-keyspace team key; encrypted to each member's latest PUK | wrap records |

Device revoke → user rotates PUK → keyspace rewraps to latest PUK.

## Wire

**Id.** `identikey-log` `content_hash` of the genesis op
(`blake3` of the canonical unsigned envelope; no domain separation).
No second identifier.

**Genesis kind (advise 2026-09-01 amend).** No eighth kind. Outer
genesis is the first `keyspace.join` that installs at least one admin
roster entry and a PTK wrap-list; that join's `content_hash` is the
keyspace id. Inner genesis is `keyspace.nest`; that nest's
`content_hash` is the nested keyspace id. An empty keyspace with no
members is impossible by construction.

**Kinds.** `keyspace.join` · `keyspace.change` · `keyspace.leave` ·
`keyspace.assign-node` · `keyspace.nest` · `keyspace.epoch-begin` ·
`keyspace.epoch-commit`. Not `guild.*`. Kick, blacklist, admin-grant,
and wrap-list are fields or consequences, not kinds. Kind strings are
`<namespace>.<verb>` (two-segment); identikey-log's documented
convention is three-segment and is not enforced.

**Actor vs wrap-target (advise 2026-09-01 amend).** identikey-log
`Op.actor` stays the raw 32-byte Ed25519 public key. This landing does
not amend the log. P-256 is a wrap-target only (`p256-xchacha20poly1305`).
A P-256-only enclave identity cannot author keyspace ops; an admin
companion is Ed25519.

**Admin-ness (advise 2026-09-01 amend).** Roster entries in `join` /
`change` bodies carry an `admin` boolean. `leave` removes the entry.
Only an actor whose current roster entry has `admin: true` may append
`join`, `change`, `leave`, `assign-node`, `nest`, `epoch-begin`, or
`epoch-commit`. Member-only keys receive wraps; they do not administer.

**Wrap.** Self-describing. Wrap records are CBOR maps (encoding
conventions: raw bytes in CBOR). Each wrap carries an algorithm tag.
v1 tags: `x25519-xchacha20poly1305` (Ed25519 PUK via RFC 7748) and
`p256-xchacha20poly1305`. No HPKE. No PQ wrap this landing.

**Log.** Ops ride `identikey-log` among holders. The log surfaces
concurrency and does not merge. Epoch commit is all-or-none on the log.
Postgres is an optional cache.

## Two profiles

**House / buyer.** Configurable epoch. Kick can rekey. Secrets live
here.

**Access-node.** Inner keyspace, created after a node is assigned to an
outer keyspace (`keyspace.assign-node` then `keyspace.nest`). High
churn, long epoch, lower assurance. Identikey login wraps the caller's
latest PUK to that node's PTK. Local service-mesh broadcast/comms, not
house secrets.

## Three layers stay uncollapsed

| Layer | Question | This work |
|---|---|---|
| Identity | Who is this? | XID + keyspace membership (this spec) |
| Agency | What may they do? | Biscuit. Not membership. |
| Data access | Who can read this ciphertext? | Recrypt. Not a keyspace. |

Mixing any two is a protocol error.
