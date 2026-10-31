//! Opaque secrets kept with an identikey.
//!
//! A record is an id, a label, a creation time, a 32-byte salt, and the
//! secret bytes. The public name of the secret is
//! `Blake3("identikey-secret-v1\n" || salt || value)`. The salt may travel.
//! The value must not. This is not Mjolnir's `mjolnir/secret-commit/v1`
//! commitment and it is not a Biscuit.
//!
//! [`MemorySecretStore`] is the in-memory store. The first on-disk store is
//! the IKEYW wallet: `identikey-wallet` seals these envelopes inside the
//! same Argon2id file as the identity. identikey-core's custody columns and
//! keyspace cache are not this store.

#![warn(rust_2018_idioms)]

mod record;
mod store;

pub use record::{
    MAX_VALUE_LEN, SealedSecret, SecretCommitment, SecretError, SecretId, SecretMeta, commitment,
};
pub use store::{MemorySecretStore, SecretStore};
