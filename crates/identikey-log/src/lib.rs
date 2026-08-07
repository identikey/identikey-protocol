//! # identikey-log
//!
//! A **signed op log**: an append-only, content-addressed, causally ordered DAG
//! of operations, each attributed to an actor and each carrying an opaque typed
//! body.
//!
//! Every property in that sentence is a *verifiability* property — who said it,
//! that they said exactly this, what it came after, and that nobody rewrote it
//! since. None of them is specific to any application domain, which is why this
//! lives beside `identikey-auth` (who you are) and `identikey-wallet` (custody
//! of that identity) rather than inside a consumer.
//!
//! The wire format originated as Dreamball's `ball.action` v4; the bytes are
//! frozen against cross-runtime golden vectors, so the name of the `type`
//! field (`"ball.action"`) is a historical artefact, not a dependency.
//!
//! ## What an op is
//!
//! ```text
//! kind           worldtree.kanban-card.move     open UTF-8 dispatch key
//! body           <opaque canonical CBOR>        the consumer's payload
//! hlc            [l, c]                         causal position
//! actor          <32-byte Ed25519 public key>   who
//! parent-hashes  [<32 bytes>, ...]              what this came after
//! content_hash   blake3(canonical bytes)        the op's identity
//! signed         [alg, signature]               attached, detached, plural
//! ```
//!
//! ## Quick start
//!
//! ```
//! use identikey_log::{Author, Hlc, Op, codec, sign};
//!
//! // A deterministic test identity. Use real entropy in production.
//! let author = Author::from_seed(&[0u8; 32]);
//!
//! let op = Op::new("worldtree.kanban-card.move", author.actor(), Hlc::new(1_700_000_000_000, 7))
//!     .with_body(vec![0x82, 0x01, 0x02])   // canonical CBOR: [1, 2]
//!     .with_parents([[0x10u8; 32]]);
//!
//! // The op's identity is the hash of its *unsigned* bytes, so it does not
//! // change when signatures are attached.
//! let id = codec::content_hash(&op).unwrap();
//!
//! let signed = author.sign(op).unwrap();
//! let bytes = codec::encode_signed(&signed).unwrap();
//!
//! let (round_tripped, id2) = sign::decode_and_verify(&bytes).unwrap();
//! assert_eq!(round_tripped, signed);
//! assert_eq!(id, id2);
//! ```
//!
//! ## Guarantees, and their edges
//!
//! * **Deterministic bytes.** Encoding is dCBOR; the same logical op always
//!   produces the same bytes in any conformant implementation. The golden
//!   vectors in `tests/goldens.rs` are the gate.
//! * **Signatures cover the unsigned bytes**, not the signed envelope, so
//!   co-signing is additive and `content_hash` is stable.
//! * **The body is opaque.** This crate checks that it is canonical CBOR and
//!   otherwise does not look inside. Typing the body is the consumer's job.
//! * **Concurrency is surfaced, not resolved.** Two ops with identical `hlc`
//!   are concurrent; the protocol deliberately imposes no merge rule.

#![warn(rust_2018_idioms)]

pub mod codec;
pub mod error;
pub mod hlc;
pub mod op;
pub mod sign;

pub use codec::{content_hash, decode, encode, encode_signed};
pub use error::{LogError, Result};
pub use hlc::Hlc;
pub use op::{Hash32, Op, SigAlg, Signature, SignedOp, FORMAT_VERSION, OP_TYPE};
pub use sign::{
    decode_and_verify, verify, verify_ed25519, verify_ml_dsa_87, verify_with_pq_key, Author,
};
