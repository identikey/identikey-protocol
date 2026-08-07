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
//! 'signed'       Signature                      attached, plural, elision-safe
//! ```
//!
//! ## It is a Gordian Envelope
//!
//! Not envelope-*shaped* — an actual `bc_envelope::Envelope`. The core map is
//! the subject, the optional metadata are real assertions, and a signature
//! covers the wrapped subject's SHA-256 digest tree rather than a literal byte
//! string. That last point is the whole reason (Dreamball-y4t.16): a signature
//! over a digest tree **survives elision**, so a partially redacted op is
//! still verifiable by anyone holding the author's key. An op log that cannot
//! hand out a redacted-but-verifiable slice of itself is missing the feature
//! it most wants.
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
//! * **Deterministic bytes.** Encoding is dCBOR and Gordian orders assertions
//!   by digest; the same logical op always produces the same bytes in any
//!   conformant implementation. The golden vectors in `tests/goldens.rs` are
//!   the gate.
//! * **Signatures cover the wrapped unsigned envelope**, not the signed one,
//!   so co-signing is additive and `content_hash` is stable.
//! * **Elision preserves signatures; substitution does not.** Proven, not
//!   asserted — see `tests/elision.rs`.
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

// The browser host seam: the `env.getRandomBytes` import both getrandom majors
// are routed to, plus the minimal exports that make the wasm CI gate check a
// linked module rather than an empty one.
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use bc_components::Signature;
pub use bc_envelope::Envelope;
pub use codec::{
    content_hash, decode, encode, encode_signed, from_envelope, to_envelope,
    to_signed_envelope,
};
pub use error::{LogError, Result};
pub use hlc::Hlc;
pub use op::{Hash32, Op, SignedOp, FORMAT_VERSION, OP_TYPE};
pub use sign::{
    actor_key, decode_and_verify, signatures_of, verify, verify_envelope,
    verify_envelope_with_pq_key, verify_ml_dsa_87, verify_with_pq_key, Author,
};
