# IdentiKey Share v1

**Status:** Draft, implemented by [`identikey-share`](../../crates/identikey-share).
**Date:** 2026-10-28

How several holders read one ciphertext. This is data access. It is not a
keyspace roster, not a Biscuit, and not a guild holder class. Capability v1
§7.5 still binds a holder to one public key. A share grant does not change that.

The wrap bytes inside a share are keyspace v1 §7. This document does not
redefine them.

---

## 1. What is shared

One 32-byte DEK. The payload is XChaCha20-Poly1305 under that DEK, with
associated data `identikey-share-v1-payload`. Each recipient gets a KEK wrap
of the same DEK:

- **Direct.** Keyspace §7 to an X25519 u-coordinate, to the RFC 7748 Montgomery
  image of an Ed25519 verifying key, or to a compressed P-256 point. The KEK
  is the Blake3 of the ECDH shared secret, the ephemeral public key, and the
  recipient, under the label `identikey-keyspace-v1-wrap`.
- **Recrypt.** An opaque `recrypt-pre` capsule of that same DEK. A backend
  such as Recrypt encapsulates, decapsulates, and transforms it. This spec
  does not define the PRE ciphertext.

Rewrap and rotate open one wrap and seal new ones. The payload ciphertext
does not change. The DEK is not an output of rewrap.

Every listed direct recipient can open. Threshold reconstruction (SSKR,
guardian quorum) is key recovery and is not this object.

## 2. Post-quantum signatures

A grant is signed by Ed25519. ML-DSA-44, ML-DSA-65, or ML-DSA-87 may be
attached over the same bytes. Absence is valid. A verifier with policy
`required` rejects a classical-only grant. A present ML-DSA signature is
always checked. There is no ML-DSA-only grant, and there is no post-quantum
KEM in the v1 wrap.

ML-DSA-87 is the large choice: public key about 2.5KB, signature about 4.6KB.
Signers that do not have a PQ key omit it.

## 3. Grant

The signed body is the dCBOR map of version, content id, access commitment,
epoch, mode (`direct`, `recrypt`, or `either`), the Ed25519 signer, and the
PQ algorithm and public key when present. The signature message is
`identikey-share-v1-grant\n` concatenated with that map's canonical bytes.
Ed25519 and ML-DSA signatures sit beside the body. They are not inside it.

`direct` requires wraps and no capsules. `recrypt` requires capsules and no
wraps. `either` requires both. Adding or transforming a recipient changes the
access commitment, so the old grant no longer matches.

## 4. Out of scope

- Guild or keyspace id as a holder class.
- Authoring `keyspace.*` log ops, or deciding an epoch winner.
- PQ KEM wraps, HPKE, and threshold shares.
- A Recrypt implementation. The capsule slot is the seam.
