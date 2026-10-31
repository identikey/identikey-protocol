# IdentiKey Secret v1

**Status:** Draft, implemented by [`identikey-secret`](../../crates/identikey-secret)
and stored by [`identikey-wallet`](../../crates/identikey-wallet).
**Date:** 2026-10-29

A foreign secret kept with an identikey on disk. This is local custody. It
is not a Biscuit, not a guild holder, and not the Mjolnir redeem vault.

identikey-core does not store these records. Its database holds a C2
encapsulation scalar, a managed-key blob, OIDC session material, and a
cache of keyspace wraps. The keyspace cache is not the source of truth.
None of those columns is this object.

## 1. Record

```text
id           path-safe, 1..=64 bytes, [A-Za-z0-9._-], not "." or ".."
label        1..=128 bytes, no NUL, no slash
created      unix seconds, CBOR tag 1
salt         32 bytes
value        1..=65536 bytes
```

The Gordian object type is `identikey.sealed-secret`, format version 1.
The wallet container carries it as a `sealed-secret` assertion. A wallet
with no secrets omits the assertion. Unknown assertions inside the object
are preserved. Unknown wallet-level assertions stay on the wallet.

## 2. Commitment

```text
Blake3("identikey-secret-v1\n" || salt || value)
```

The salt may be shown with the commitment. The value must not. An unsalted
hash of the value is not a commitment. Mjolnir's
`mjolnir/secret-commit/v1` names a different vault.

## 3. Disk

The first store is the IKEYW v2 file. The Argon2id shell that encrypts the
identikey encrypts these records too. One unlock reveals both. Removing a
secret from memory does not remove it from disk until the wallet is saved.

## 4. Out of scope

- Redeem, copy-out, and the proxy use grant.
- Wrapping the value to other holders. That is keyspace or `identikey-share`.
- A second file format. A later store may implement the same record.
