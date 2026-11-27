# Key derivation

Status: convention for new work. Decided 2026-11-27 (Duke). It does not
change any existing wire.

## The rule

A new IdentiKey construction that derives a key from secret key
material uses BLAKE3 in key-derivation mode:

```
key = blake3::derive_key(context, key_material)
```

Do not hash a label and a secret together by hand. Do not reach for
HKDF in a new construction unless one of the exceptions below applies.

## Context strings

The context is what separates one derived key from another.

- Hardcoded in the source. Never built from input at run time.
- Globally unique and specific to one purpose.
- Form: `identikey <standard>-<version> <purpose>`, for example
  `identikey group-v2 epoch wrap key`.
- Versioned through the standard it belongs to. A changed meaning gets
  a new string.

Anything that varies per use (a recipient key, an epoch number, a
sector) goes in `key_material`, after the secret, in a fixed-length or
length-prefixed encoding. It does not go in the context.

## What this mode is for

`key_material` is already a strong secret: a random key, a seed, or a
Diffie-Hellman output. The mode is deliberately fast.

It is not for passwords or anything a person chose. Those use Argon2id,
as the wallet file and the OP's password store already do.

## Exceptions

Use HKDF-SHA-256 instead when the derivation must run in one of these:

- a FIPS-validated module,
- an HSM, secure enclave, or TPM that offers no BLAKE3,
- a browser with WebCrypto alone and no WASM.

Say which exception applies in the standard that makes the choice.

## Hierarchical keys

IdentiKey has no hierarchical (HD) key generation today. If it is
added, note one limit before choosing this mode for it: BLAKE3
derivation is one-way from a secret. It gives the equivalent of BIP32
hardened children only. Deriving a child public key from a parent
public key, without the secret, needs a different construction.

## Existing derivations, as of 2026-11-27

These are not changed by this note. Each is fixed by a wire or by
values already issued.

| Where | Construction | Why it stays |
|---|---|---|
| Keyspace v1 and share v1 wrap key (`identikey-share`, and the copy in identikey-core `identikey-keys`) | `blake3("identikey-keyspace-v1-wrap" \|\| dh \|\| ephemeral \|\| recipient)`, a plain hash | Frozen keyspace v1 wire. A successor wrap should use `derive_key`. |
| Pairwise OIDC `sub` (identikey-core `identikey-oidc`) | HKDF-SHA-256 over the pairwise salt, the sector, and the XID | Changing it changes every relying party's `sub` for every user. |
| Wallet file key (`identikey-wallet`) | Argon2id from a password | Password input. Correct as it is. |
| OP password store (identikey-core) | Argon2id | Password hashing. Correct as it is. |

Fingerprints, content hashes, commitments, and the digests in
`identikey-group` are hashes of public data. They are not key
derivation and this note does not cover them.
