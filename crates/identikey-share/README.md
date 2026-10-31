# identikey-share

Permissive protocol crate for sharing a ciphertext with more than one holder.

The payload is encrypted under one 32-byte DEK. Each recipient gets a keyspace
v1 wrap of that DEK to their encapsulation public key (X25519, an Ed25519 key
converted with RFC 7748, or P-256). That wrap is the KEK step. Rewrap opens
one wrap and seals another. The DEK is wiped inside that call.

A grant is an Ed25519 signature over the payload id and the recipient set.
ML-DSA-44, ML-DSA-65, or ML-DSA-87 may be attached. Verifiers accept a
classical grant unless they ask for the post-quantum signature. The public
key for ML-DSA-87 is about 2.5KB and the signature about 4.6KB, so leaving it
off is a real choice.

A `recrypt-pre` capsule holds an opaque PRE ciphertext of the same DEK.
Recrypt, or any other backend, implements `RecryptKem`. This crate does not
link OpenFHE.

This is data access. A roster, a keyspace id, or this grant is not a Biscuit
holder class.

The wire contract is `docs/standards/identikey-share-v1.md`.
