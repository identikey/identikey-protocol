//! Characterisation test: this format vs. Gordian Envelope proper.
//!
//! `identikey-log` uses Blockchain Commons' deterministic CBOR codec (`dcbor`)
//! but *not* `bc_envelope::Envelope`, even though it borrows the `#6.200` /
//! `#6.201` tags. That is a deliberate, load-bearing choice, and it is easy for
//! a future reader to assume it was an oversight and "simplify" it into
//! `Envelope`. This test pins the actual bytes each produces so the difference
//! is a fact in the test output rather than a claim in a comment.
//!
//! If a future version of this crate migrates to real Gordian Envelope, this
//! test is the one that must be deleted deliberately — and every golden vector
//! in `goldens.rs` will change at the same time.

use bc_envelope::prelude::*;
use identikey_log::{codec, Author, Hlc, Op};

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// A stand-in "core map" — the exact same logical CBOR value both sides wrap.
fn core_value() -> dcbor::CBOR {
    let mut m = dcbor::Map::new();
    m.insert("type", "ball.action");
    m.into()
}

#[test]
fn difference_1_subject_only_envelope_is_an_array_here_and_bare_there() {
    // Gordian Envelope: a subject-only envelope is `200(201(value))`.
    let gordian = Envelope::new(core_value()).to_cbor_data();
    assert!(hex(&gordian).starts_with("d8c8d8c9"), "got {}", hex(&gordian));

    // This format: `200([201(core)])` — always an array, even with zero
    // attributes. Note the `81` (array of 1) that Gordian does not emit.
    let ours = codec::encode(&Op::new("k", [0u8; 32], Hlc::new(1, 0))).unwrap();
    assert!(hex(&ours).starts_with("d8c881d8c9"), "got {}", hex(&ours));

    // And the difference is not merely cosmetic: Gordian's decoder rejects a
    // one-element array outright ("node must have at least two elements").
    assert!(Envelope::try_from(dcbor::CBOR::try_from_data(&ours).unwrap()).is_err());
}

#[test]
fn difference_2_attributes_are_arrays_here_and_maps_there() {
    // Gordian assertion: a single-entry MAP `{predicate: object}`, each side
    // itself an envelope.
    let gordian = Envelope::new(core_value()).add_assertion("signed", "x").to_cbor_data();
    let g = hex(&gordian);
    // `82` node array, then `a1` — the assertion map.
    assert!(g.contains("a1"), "expected an assertion map in {g}");

    // Ours: a 2-element ARRAY `[label, value]`, both bare dCBOR (no leaf tag).
    // In the signed golden that is `82 66 "signed" 82 67 "ed25519" 5840 <sig>`.
    let author = Author::from_seed(&[0u8; 32]);
    let signed = author
        .sign(Op::new("k", author.actor(), Hlc::new(1, 0)))
        .unwrap();
    let ours = hex(&codec::encode_signed(&signed).unwrap());
    assert!(ours.contains("82667369676e6564"), "expected [\"signed\", ...] in {ours}");
}

#[test]
fn difference_3_signatures_cover_bytes_here_and_the_digest_tree_there() {
    // Ours: raw Ed25519 over the canonical unsigned bytes. Verifiable with
    // nothing but the actor key and the bytes.
    let author = Author::from_seed(&[0u8; 32]);
    let op = Op::new("k", author.actor(), Hlc::new(1, 0));
    let unsigned_bytes = codec::encode(&op).unwrap();
    let signed = author.sign(op).unwrap();
    identikey_log::verify_ed25519(
        &author.actor(),
        &unsigned_bytes,
        &signed.signatures[0].value,
    )
    .expect("our signature is over the literal canonical bytes");

    // Gordian: the signature is computed over the subject's SHA-256 digest
    // tree, and is carried as a tagged `Signature` object under the `'signed'
    // known value. Consequence: a Gordian signature survives elision of an
    // assertion; ours does not, because eliding changes the bytes.
    //
    // We assert the structural fact rather than re-deriving BC's signing:
    // a Gordian envelope's digest is defined and stable, and it is NOT the
    // canonical byte string we sign.
    let gordian = Envelope::new(core_value());
    let digest = gordian.digest().to_owned();
    assert_ne!(digest.data(), &unsigned_bytes[..]);
}
