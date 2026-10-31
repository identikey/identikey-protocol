//! Share a ciphertext by wrapping one symmetric key to each recipient.
//!
//! The payload is XChaCha20-Poly1305 under a fresh 32-byte DEK. Each
//! recipient's encapsulation public key is a KEK: the DEK is sealed with the
//! keyspace v1 wrap (`x25519-xchacha20poly1305` or `p256-xchacha20poly1305`).
//! Rewrap opens one wrap and seals a new one. The DEK does not leave the
//! function that performs that step.
//!
//! An Ed25519 identity is a wrap target only after the RFC 7748 map to X25519.
//! ML-DSA signs the grant when the signer has a PQ key. It is not required,
//! and it is not a KEM. A Recrypt capsule may carry a PRE ciphertext of the
//! same DEK. This crate does not implement PRE.
//!
//! A grant authorizes the current access set of one share. It is data access.
//! It is not a Biscuit, and it is not a guild holder class.
//!
//! ```
//! use identikey_share::{Share, WrapSecret};
//!
//! let alice = WrapSecret::generate_x25519();
//! let public = alice.public().expect("x25519 public");
//! let share = Share::seal(b"guild note", &[public], 0).expect("seal");
//! let opened = share.open(&alice).expect("open");
//! assert_eq!(&opened[..], b"guild note");
//! ```

#![warn(rust_2018_idioms)]

mod error;
mod grant;
mod recrypt;
mod share;
mod wrap;

pub use error::ShareError;
pub use grant::{AccessGrant, AccessMode, GrantKeys, PqAlg, PqPolicy, grant_access, verify_grant};
pub use recrypt::{RecryptCapsule, RecryptKem, RecryptPublic};
pub use share::Share;
pub use wrap::{WrapPublic, WrapSecret, rewrap_key, unwrap_key, wrap_key};
