# IdentiKey Keyspace v1

**Status:** Draft spec. Test-vector hooks named; fixtures not filled (`ikp-6yz.2`).
**Date:** 2026-09-01
**Does not implement:** a crate in this workspace. Ops ride
[`identikey-log`](../../crates/identikey-log). First product consumer:
identikey-core `guild-keyspaces` / Lightning Mesh (product word **guild**).
**Does not specify:** FOKS servers, `user@host`, encrypted git, or FOKS KV.

This is the protocol-tier answer to “how do several identikeys hold keys
in one space.” It does not replace identity possession proof, and it
does not replace Recrypt or Biscuit.

---

## 1. Three layers. Do not collapse them.

Restated from [`identikey-capability-v1.md`](identikey-capability-v1.md) §1
so this file stands alone. That table is not patched here.

| Layer | Question | Spec |
|---|---|---|
| **Identity** | Who is this? | [`identikey-auth-challenge-v1.md`](identikey-auth-challenge-v1.md) (possession proof). **This spec** is shared key-management among those identities. |
| **Agency** | What may this holder *do*? | Biscuit ([`identikey-capability-v1.md`](identikey-capability-v1.md)). Not membership. |
| **Data access** | Who can read this ciphertext? | Recrypt. Not a keyspace. |

A keyspace roster is not a grant. A Biscuit is not a wrap-list. A
recryption group is not a keyspace. Mixing any two is a protocol error.

Lightning Mesh UI and Admin say **guild** for this object. Op kinds and
this document say **keyspace**. One object, two words. No OIDC claim
named `guilds`. Do not title this standard `guild-v1`.

---

## 2. Object

A keyspace is a **distributed object**: the keys that comprise it. It
does not live in a place. It is not a document housed at identikey-core,
on one mesh node, or in Postgres.

Anyone holding an admin key keeps it alive: they replicate and sign.
If every admin key is gone or stops participating, the object fades.
Holders replicate a signed artifact (roster, wrap-list, nested ids).
That artifact is evidence of the object, not its home.

XID stays who-I-am. Join/leave is not an Elect rewrite of the member
XID. Postgres, if present, is a cache of ops on this log.

### 2.1 Methods (FOKS, not FOKS-the-product)

| Layer | Name | Role | This spec |
|---|---|---|---|
| Device | device key | per-device; revoke cascades | cascade rule only; not a protocol object |
| User | PUK | per-identikey user key; latest PUK is the wrap target | identity keys already specified |
| Keyspace | PTK | 32-byte per-keyspace secret; wrapped to each member's latest PUK | wrap records |

Device revoke → user rotates PUK → keyspace rewraps to latest PUK.
Device-key objects and device-revoke ops are not `keyspace.*` kinds.

---

## 3. Identifier

The keyspace id is the identikey-log `content_hash` of its **genesis
op**: `blake3` of the canonical unsigned envelope bytes, with no
domain-separation prefix (see `identikey-log` `codec::content_hash`).

No second identifier. Nested keyspace id = that inner genesis hash.

**Outer genesis.** The first `keyspace.join` that installs at least one
admin roster entry and a PTK wrap-list. That join's `content_hash` is
the keyspace id. The genesis body does **not** carry the id (it cannot:
the id is the hash of the op).

**Inner genesis.** `keyspace.nest`. That nest's `content_hash` is the
nested keyspace id.

An empty keyspace with no members is impossible by construction. There
is no eighth kind.

---

## 4. Log

Ops ride [`identikey-log`](../../crates/identikey-log): signed,
actor-attributed, content-addressed, causally ordered. The body is
opaque canonical CBOR (CBOR-in-CBOR). This spec types that body.

The log surfaces concurrency and does not merge. The keyspace consumer
defines the commit rule in §8.

`Op.actor` is the raw 32-byte Ed25519 public key. This spec does not
amend identikey-log.

Non-genesis ops SHOULD set the log assertion `target-fp` to the
keyspace id.

### 4.1 Kind strings

Kinds are two-segment `<namespace>.<verb>`. identikey-log documents
`<namespace>.<noun>.<verb>` as convention and does not enforce it.

| Kind | Role |
|---|---|
| `keyspace.join` | Genesis (first) or add members |
| `keyspace.change` | Roster / profile / blacklist fields |
| `keyspace.leave` | Remove a roster entry |
| `keyspace.assign-node` | Bind an opaque node id to this keyspace |
| `keyspace.nest` | Inner genesis |
| `keyspace.epoch-begin` | Start PTK rotation |
| `keyspace.epoch-commit` | Commit that rotation, all-or-none |

Not `guild.*`. Kick, wrap, rewrap, blacklist, and admin-grant are
**fields or consequences**, not kinds. There is no `rename` kind.

---

## 5. Actor vs wrap-target

**Authors** of `keyspace.*` ops are identikey-log Ed25519 actors.

**Wrap-targets** are PUKs: Ed25519 (via X25519, §7.2) or P-256.

A P-256-only enclave identity can receive a wrap and cannot author a
`keyspace.*` op. An admin companion is Ed25519.

`admin: true` on a roster entry requires an Ed25519 `actor`.

---

## 6. Roster and admin

dCBOR maps. Keys are short text. Byte strings are raw
([`encoding-conventions.md`](encoding-conventions.md) §1).

```
PublicKey := { "alg": tstr, "key": bstr }

; alg "ed25519" → key 32 bytes (RFC 8032)
; alg "p256"    → key 33 bytes compressed SEC1 (same as auth-challenge v1)

RosterEntry := {
  "admin": bool,
  "puks":  [PublicKey],       ; wrap targets; at least one
  "actor": bstr,              ; 32-byte Ed25519; REQUIRED if admin is true
}

; "actor" MAY be omitted when admin is false (wrap-target-only member)
```

`keyspace.leave` removes the entry. Kick is `leave` and/or `change`
(roster + optional blacklist field) plus cryptographic eviction on
epoch (§8).

### 6.1 Who may append

After genesis, holders accept `join` / `change` / `leave` /
`assign-node` / `nest` / `epoch-begin` / `epoch-commit` only when
`Op.actor` matches a roster entry whose **applied** `admin` is true.

**Genesis exception.** Outer genesis is a `keyspace.join` with no
prior roster. It is valid iff `Op.actor` appears as `admin: true` on
a `RosterEntry` **in that same body**. Inner genesis (`keyspace.nest`)
is signed by an **outer** admin; the nest body lists the inner roster,
and `Op.actor` must be `admin: true` on the applied **outer** roster.

If the last `admin: true` entry leaves, the keyspace fades. Further
administering ops do not verify.

---

## 7. Wrap

Each wrap is a CBOR map, not a side binary box.

```
Wrap := {
  "alg":        tstr,   ; v1 tags below
  "recipient":  bstr,   ; raw PUK bytes matching alg
  "ephemeral":  bstr,   ; ephemeral public key, same curve as alg
  "nonce":      bstr,   ; 24-byte XChaCha20 nonce
  "ciphertext": bstr,   ; XChaCha20-Poly1305(PTK); 16-byte tag appended
  "epoch":      uint    ; keyspace epoch this wrap belongs to
}
```

v1 `alg` values:

| Tag | Recipient / ephemeral | DH |
|---|---|---|
| `x25519-xchacha20poly1305` | 32-byte X25519 u-coordinate | X25519 |
| `p256-xchacha20poly1305` | 33-byte compressed SEC1 P-256 | ECDH P-256 |

No HPKE. No PQ wrap in v1. An unknown `alg` is not a successful unwrap.

**PTK** is 32 random bytes. Do not reuse a PTK across epochs.

### 7.1 Key derivation

```
dh = ECDH(ephemeral_sk, recipient_pk)
k  = blake3(
       "identikey-keyspace-v1-wrap" || dh || ephemeral || recipient
     )[0:32]
```

Encrypt the PTK with XChaCha20-Poly1305, key `k`, nonce 24 bytes.
Ciphertext is ciphertext ‖ 16-byte tag.

### 7.2 Ed25519 PUK → X25519

For `x25519-xchacha20poly1305` when the PUK is an Ed25519 identity
key, convert the 32-byte Ed25519 public key to an X25519 public key
per RFC 7748 §4.1 (birational map; equivalent to libsodium
`crypto_sign_ed25519_pk_to_curve25519`).

Implementations MUST reject the all-zero X25519 public key and the
small-order Montgomery u-coordinates (torsion). A rejected conversion
is not a successful wrap or unwrap.

Private-key conversion, when the holder wraps to themselves, uses the
matching RFC 7748 / libsodium secret-key map with clamping as
specified there.

### 7.3 P-256

`p256-xchacha20poly1305` uses ECDH on NIST P-256. Recipient and
ephemeral are compressed SEC1 (33 bytes), matching auth-challenge v1.
Reject the point at infinity and low-order points.

---

## 8. Epoch

Hybrid eviction:

1. **Instant.** Roster deny / optional blacklist field on `leave` or
   `change`. Guardians stop serving bytes.
2. **Cryptographic.** PTK rotation on a configurable epoch. Envelope
   rewrap (KMS-style): do not rewrite every blob keyed to the PTK.

When rotation fires it is a directed graph: member-key rotation and
every PTK whose wrap-list changed. Commit is all-or-none.

`keyspace.epoch-begin` carries the new `epoch` uint and wrap-list for
remaining members. `keyspace.epoch-commit` carries the same `epoch`
and MUST have the matching begin in its parent hashes.

**Concurrency.** Two `epoch-begin` ops that are concurrent (neither
is an ancestor of the other in the log DAG) are a conflict. Holders
MUST NOT merge them and MUST NOT apply either until an admin `nacks`
one (identikey-log `nacks` assertion) or a later admin `epoch-begin`
parents exactly one of them. identikey-log does not pick a winner.

House/buyer profile: epoch is configurable; kick MAY start an epoch.
Access-node profile: long epoch; join/leave MUST NOT rotate the PTK
on each event.

---

## 9. Op bodies

Every body is a dCBOR map. Non-genesis ops carry `"keyspace": bstr`
(32-byte genesis hash).

```
JoinBody := {
  "roster":  [RosterEntry],   ; genesis: the initial roster
  "wraps":   [Wrap],          ; PTK wraps for this epoch
  "epoch":   uint,            ; genesis: 0
  "profile": tstr,            ; "house" | "access-node"
  "keyspace": bstr,           ; omitted on outer genesis
}

ChangeBody := {
  "keyspace":   bstr,
  "roster":     [RosterEntry], ; optional replacement/additions
  "blacklist":  [bstr],        ; optional actor or recipient keys
  "profile":    tstr,          ; optional
  "epoch":      uint           ; optional; does not rotate PTK
}

LeaveBody := {
  "keyspace":  bstr,
  "actor":     bstr,           ; optional — Ed25519 being removed
  "recipient": bstr,           ; optional — wrap-target being removed
  "blacklist": bool            ; default false
}

AssignNodeBody := {
  "keyspace": bstr,
  "node":     bstr             ; opaque 32-byte node id (product-defined)
}

NestBody := {
  "outer":   bstr,             ; outer keyspace id
  "roster":  [RosterEntry],    ; inner initial roster
  "wraps":   [Wrap],
  "epoch":   uint,             ; 0
  "profile": tstr              ; typically "access-node"
}

EpochBeginBody := {
  "keyspace": bstr,
  "epoch":    uint,            ; previous + 1
  "wraps":    [Wrap]
}

EpochCommitBody := {
  "keyspace": bstr,
  "epoch":    uint             ; same as the begin this commits
}
```

`LeaveBody` MUST include at least one of `"actor"` or `"recipient"`.

---

## 10. Profiles

One spec, two named profiles.

**House / buyer.** Configurable epoch. Kick MAY rekey. Secrets live
here. Profile tag `"house"`.

**Access-node.** Inner keyspace, created after `keyspace.assign-node`
on an outer house keyspace, then `keyspace.nest`. High churn, long
epoch, lower assurance. Identikey login wraps the caller's latest PUK
to that node's PTK. Used for local service-mesh broadcast/comms, not
house secrets, not Recrypt data-groups. Roster/blacklist update
immediately; PTK does not rotate on each join. Profile tag
`"access-node"`.

---

## 11. Test-vector hooks

Named slots. Filled byte fixtures are not owed by `ikp-cvu` /
`add-keyspace-spec`. Tracked with the rest of the identity-tier
vectors in `ikp-6yz.2`.

| Slot | Covers |
|---|---|
| `genesis-join` | Outer genesis `keyspace.join`; id = `content_hash` |
| `join` | Subsequent join citing `keyspace` |
| `change` | Roster / blacklist |
| `leave` | Removal |
| `assign-node` | Opaque node id |
| `nest` | Inner genesis; id = nest `content_hash` |
| `epoch-begin` | New wraps, new epoch |
| `epoch-commit` | Commit matching begin |
| `wrap-x25519` | `x25519-xchacha20poly1305` including RFC 7748 conversion |
| `wrap-p256` | `p256-xchacha20poly1305` |
| `wrap-unknown-alg` | Unknown tag is not a successful unwrap |
| `genesis-self-admin` | Genesis actor listed `admin: true` in the same body |
| `member-cannot-leave` | `admin: false` actor rejected on `leave` |
| `concurrent-epoch-begin` | Two concurrent begins; neither applied |

Suggested path when filled: `docs/standards/vectors/keyspace-v1/`.

---

## 12. Out of scope

- FOKS servers, `user@host`, encrypted git, FOKS KV
- Recrypt as keyspace identity
- Biscuit as membership
- Wallet `"keyspace-membership"` assertion (later, non-authoritative)
- HPKE; PQ wrap
- Device-key objects on this log
- Runtime wrap/rotate crate
- Lightning Admin UI
