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

No IdentiKey code generates hierarchical (HD) keys today. One proposal
exists and was never built: `ik:v1`, in the `tools` repo at
`docs/architecture/hd-key-hierarchy-ik-v1.md` (2025), which derives
hardened Ed25519 and X25519 branches from one seed with HKDF-SHA512.
If HD keys are built, that proposal is revisited under this convention.
Note one limit before choosing this mode for it: BLAKE3
derivation is one-way from a secret. It gives the equivalent of BIP32
hardened children only. Deriving a child public key from a parent
public key, without the secret, needs a different construction.

## Existing derivations, as of 2026-11-27

IdentiKey is pre-alpha. A wire can still change, and this is the time
to change it. The wrap key was moved to this convention on 2026-11-27.
The rest stay, each for the reason given.

| Where | Construction | Status |
|---|---|---|
| Keyspace v1 and share v1 wrap key (`identikey-share`, and the copy in identikey-core `identikey-keys`) | `derive_key`, one context per wrap algorithm (keyspace v1 §7.1) | Follows this convention. Was a plain BLAKE3 hash of a label and the inputs. |
| Pairwise OIDC `sub` (identikey-core `identikey-oidc`) | HKDF-SHA-256 over the pairwise salt, the sector, and the XID | Changing it changes every relying party's `sub` for every user. |
| Wallet file key (`identikey-wallet`) | Argon2id from a password | Password input. Correct as it is. |
| OP password store (identikey-core) | Argon2id | Password hashing. Correct as it is. |

Fingerprints, content hashes, commitments, and the digests in
`identikey-group` are hashes of public data. They are not key
derivation and this note does not cover them.
