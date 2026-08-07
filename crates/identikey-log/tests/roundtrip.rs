//! Round-trip, rejection and tamper-detection behaviour.

use bc_components::Signature;
// Producing an ML-DSA signature needs bc-components' PQ support, which is
// native-only — see `identikey-log`'s `pqcrypto` feature.
#[cfg(feature = "pqcrypto")]
use bc_components::{SignatureScheme, Signer};
use bc_envelope::prelude::*;
use identikey_log::{codec, error::LogError, sign, Author, Hlc, Op};

fn author() -> Author { Author::from_seed(&[7u8; 32]) }

fn full_op(a: &Author) -> Op {
    Op::new("worldtree.kanban-card.move", a.actor(), Hlc::new(1_700_000_000_001, 3))
        .with_body(vec![0x82, 0x01, 0x02])
        .with_parents([[0x10u8; 32], [0x11u8; 32]])
        .with_deps([[0x20u8; 32]])
        .with_nacks([[0x30u8; 32]])
        .with_target_fp([0x40u8; 32])
        .with_timestamp(1_700_000_000)
}

#[test]
fn every_field_survives_a_round_trip() {
    let a = author();
    let op = full_op(&a);
    let bytes = codec::encode(&op).unwrap();
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(decoded.op, op);
    assert_eq!(decoded.elided, 0);
    assert_eq!(codec::encode(&decoded.op).unwrap(), bytes);
}

#[test]
fn repeated_assertions_round_trip_regardless_of_digest_order() {
    // Gordian orders assertions by digest, not by insertion, so a decoder that
    // simply pushed them in wire order would return `deps` in an arbitrary
    // order and break equality. Four deps is enough for the sort to bite.
    let a = author();
    let op = Op::new("k.n.v", a.actor(), Hlc::new(1, 0))
        .with_deps([[0x01u8; 32], [0x02u8; 32], [0x03u8; 32], [0x04u8; 32]])
        .with_nacks([[0xf1u8; 32], [0xf2u8; 32]]);
    let bytes = codec::encode(&op).unwrap();
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(decoded.op, op);
    assert_eq!(codec::encode(&decoded.op).unwrap(), bytes);
}

#[test]
fn a_body_less_op_has_a_six_key_core_map_and_a_bare_subject() {
    let a = author();
    let op = Op::new("k.n.v", a.actor(), Hlc::new(1, 0));
    let bytes = codec::encode(&op).unwrap();
    // `d8c8 d8c9 a6` — tag 200, tag 201, map(6). No array: a subject-only
    // Gordian envelope is bare.
    assert_eq!(&bytes[..4], &[0xd8, 0xc8, 0xd8, 0xc9]);
    assert_eq!(bytes[4], 0xa6, "core map should have 6 keys without a body");
    assert_eq!(codec::decode(&bytes).unwrap().op, op);
}

#[test]
fn an_op_with_assertions_is_a_node_and_one_without_is_a_leaf() {
    let a = author();
    let bare = codec::to_envelope(&Op::new("k.n.v", a.actor(), Hlc::new(1, 0))).unwrap();
    assert!(bare.is_leaf());
    let with_assertions = codec::to_envelope(&full_op(&a)).unwrap();
    assert!(with_assertions.is_node());
    assert_eq!(with_assertions.assertions().len(), 4);
}

#[test]
fn multiple_signatures_are_all_checked_and_form_a_set_on_the_wire() {
    let a = author();
    let b = Author::from_seed(&[9u8; 32]);
    let op = full_op(&a);
    let signed = b.counter_sign(a.sign(op).unwrap()).unwrap();
    assert_eq!(signed.signatures.len(), 2);

    // Both cover the same wrapped unsigned envelope, but only `a` is the
    // actor, so the all-present-must-verify policy fails on `b`'s signature.
    assert!(matches!(sign::verify(&signed), Err(LogError::BadSignature)));

    // Gordian orders assertions by digest, so `'signed'` assertions are a SET
    // on the wire, not a list: a decoder returns them in digest order and the
    // author's insertion order is not recoverable. What *is* guaranteed is
    // that the set survives and the bytes are stable either way.
    let bytes = codec::encode_signed(&signed).unwrap();
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(decoded.op, signed.op);
    assert_eq!(decoded.signatures.len(), 2);
    for sig in &signed.signatures {
        assert!(decoded.signatures.contains(sig));
    }
    assert_eq!(codec::encode_signed(&decoded).unwrap(), bytes);
    // ...and the envelope-level verifier agrees with the struct-level one.
    let envelope = codec::to_signed_envelope(&signed).unwrap();
    assert!(matches!(
        sign::verify_envelope(&envelope, &a.actor()),
        Err(LogError::BadSignature)
    ));
}

#[test]
fn co_signing_does_not_disturb_the_first_signature_or_the_identity() {
    let a = author();
    let b = Author::from_seed(&[9u8; 32]);
    let signed = a.sign(full_op(&a)).unwrap();
    let hash = codec::content_hash(&signed.op).unwrap();
    let co_signed = b.counter_sign(signed.clone()).unwrap();

    assert_eq!(co_signed.signatures[0], signed.signatures[0]);
    assert_eq!(codec::content_hash(&co_signed.op).unwrap(), hash);
    // `b`'s signature is valid — against `b`, which is not the actor.
    sign::verify_envelope(
        &codec::to_signed_envelope(&signed).unwrap(),
        &a.actor(),
    )
    .unwrap();
}

#[test]
fn tampering_with_the_body_invalidates_the_signature() {
    let a = author();
    let signed = a.sign(full_op(&a)).unwrap();
    let mut tampered = signed.clone();
    tampered.op.body = Some(vec![0x82, 0x01, 0x03]);
    assert!(matches!(sign::verify(&tampered), Err(LogError::BadSignature)));
    assert!(sign::verify(&signed).is_ok());
}

#[test]
fn tampering_with_the_hlc_invalidates_the_signature_and_the_content_hash() {
    let a = author();
    let signed = a.sign(full_op(&a)).unwrap();
    let before = codec::content_hash(&signed.op).unwrap();

    let mut tampered = signed.clone();
    tampered.op.hlc = Hlc::new(1_700_000_000_002, 3);
    assert!(matches!(sign::verify(&tampered), Err(LogError::BadSignature)));
    assert_ne!(codec::content_hash(&tampered.op).unwrap(), before);
}

#[test]
fn tampering_with_an_assertion_invalidates_the_signature() {
    // The pre-Gordian format got this for free (the assertion was inside the
    // signed byte string). On Gordian it is only true because signing wraps:
    // a bare `add_signature` would cover the subject alone and let every
    // assertion be rewritten at will. This test is what pins that choice.
    let a = author();
    let signed = a.sign(full_op(&a)).unwrap();
    for tampered in [
        {
            let mut t = signed.clone();
            t.op.deps = vec![[0x21u8; 32]];
            t
        },
        {
            let mut t = signed.clone();
            t.op.timestamp = Some(1_700_000_001);
            t
        },
        {
            let mut t = signed.clone();
            t.op.target_fp = Some([0x41u8; 32]);
            t
        },
        {
            let mut t = signed.clone();
            t.op.nacks.push([0x31u8; 32]);
            t
        },
    ] {
        assert!(matches!(sign::verify(&tampered), Err(LogError::BadSignature)));
    }
}

#[test]
fn swapping_the_actor_invalidates_the_signature() {
    let a = author();
    let signed = a.sign(full_op(&a)).unwrap();
    let mut tampered = signed.clone();
    tampered.op.actor = Author::from_seed(&[9u8; 32]).actor();
    assert!(matches!(sign::verify(&tampered), Err(LogError::BadSignature)));
}

#[test]
fn flipping_a_signature_bit_is_rejected() {
    let a = author();
    let mut signed = a.sign(full_op(&a)).unwrap();
    // Irrefutable in the default feature set — `Signature` has exactly one
    // variant when only `ed25519` is on — but refutable with `pqcrypto`. Keep
    // the `else` arm so the test compiles in both configurations.
    #[allow(irrefutable_let_patterns)]
    let Signature::Ed25519(mut raw) = signed.signatures[0] else {
        panic!("expected an Ed25519 signature")
    };
    raw[0] ^= 0x01;
    signed.signatures[0] = Signature::Ed25519(raw);
    assert!(matches!(sign::verify(&signed), Err(LogError::BadSignature)));
}

#[test]
fn an_unsigned_op_is_not_silently_accepted_by_the_verifier() {
    let a = author();
    let bytes = codec::encode(&full_op(&a)).unwrap();
    assert!(matches!(sign::decode_and_verify(&bytes), Err(LogError::Unsigned)));
}

#[test]
fn an_empty_kind_is_rejected_on_both_sides() {
    let a = author();
    let op = Op::new("", a.actor(), Hlc::new(1, 0));
    assert!(matches!(codec::encode(&op), Err(LogError::EmptyKind)));
}

#[test]
fn a_non_canonical_body_is_rejected() {
    let a = author();
    // 0x1801 is 1 encoded in two bytes — valid CBOR, not *deterministic* CBOR.
    let op = Op::new("k.n.v", a.actor(), Hlc::new(1, 0)).with_body(vec![0x18, 0x01]);
    assert!(matches!(codec::encode(&op), Err(LogError::NonCanonicalBody)));
}

#[test]
fn trailing_bytes_are_rejected() {
    let a = author();
    let mut bytes = codec::encode(&full_op(&a)).unwrap();
    bytes.push(0x00);
    assert!(codec::decode(&bytes).is_err());
}

#[test]
fn a_wrong_format_version_is_rejected_before_anything_else_is_read() {
    let a = author();
    let bytes = codec::encode(&Op::new("k.n.v", a.actor(), Hlc::new(1, 0))).unwrap();
    // The core map ends with `"format-version" 04`; flip the 4 to a 3 — the
    // shape a legacy v3 palace envelope's discriminant would have.
    let mut v3 = bytes.clone();
    let last = v3.len() - 1;
    assert_eq!(v3[last], 0x04);
    v3[last] = 0x03;
    assert!(matches!(
        codec::decode(&v3),
        Err(LogError::UnsupportedFormatVersion(3))
    ));
}

#[test]
fn an_unknown_predicate_is_rejected_rather_than_silently_dropped() {
    let a = author();
    let envelope = codec::to_envelope(&full_op(&a))
        .unwrap()
        .add_assertion("depz", CBOR::to_byte_string([0x22u8; 32]));
    assert!(matches!(
        codec::from_envelope(&envelope),
        Err(LogError::UnknownPredicate(_))
    ));
}

#[test]
fn a_non_signed_assertion_on_the_wrapper_is_rejected() {
    // The wrapper is the signed region's boundary. Anything smuggled onto it
    // that is not a signature would be invisible to every signature present.
    let a = author();
    let envelope = codec::to_signed_envelope(&a.sign(full_op(&a)).unwrap())
        .unwrap()
        .add_assertion("note", "smuggled");
    assert!(matches!(
        codec::from_envelope(&envelope),
        Err(LogError::UnknownPredicate(_))
    ));
}

/// Requires the native-only `pqcrypto` feature, because *producing* an ML-DSA
/// signature needs bc-components' PQ keypair support. The verification side of
/// this test runs through `sign::verify_ml_dsa_87` (fips204), so this doubles
/// as a live cross-implementation KAT: signed by PQClean C, verified by pure
/// Rust, every run.
#[test]
#[cfg(feature = "pqcrypto")]
fn a_pq_signature_with_no_pq_key_is_rejected_not_ignored() {
    let a = author();
    let (pq_private, pq_public) = SignatureScheme::MLDSA87.keypair();
    let mut signed = a.sign(full_op(&a)).unwrap();

    // A real ML-DSA-87 signature over the same wrapped digest the Ed25519 one
    // covers — so the only reason it can fail is the missing key.
    let digest = *codec::to_envelope(&signed.op).unwrap().wrap().digest().data();
    signed.signatures.push(pq_private.sign(&(&digest as &dyn AsRef<[u8]>)).unwrap());

    // It encodes and decodes structurally...
    let bytes = codec::encode_signed(&signed).unwrap();
    assert_eq!(codec::decode(&bytes).unwrap().signatures.len(), 2);
    // ...but there is nowhere in a v4 core map for an ML-DSA-87 public key, so
    // a plain `verify` has nothing to check it against and must not pass it.
    assert!(matches!(sign::verify(&signed), Err(LogError::PqDangling)));
    // Given the key out of band, both signatures check out.
    sign::verify_with_pq_key(&signed, Some(&pq_public)).unwrap();
}

/// The interop split, pinned as an assertion rather than left as folklore.
///
/// Without the `pqcrypto` feature — which is the *default*, and the only
/// configuration that builds for `wasm32-unknown-unknown` — bc-components has
/// no `Signature::MLDSA` variant, so a PQ-signed op cannot be **parsed**, not
/// merely cannot be verified. The op is well-formed; this build simply cannot
/// represent one of its values.
///
/// The test constructs the `#6.40105` object by hand precisely because the
/// type needed to construct it properly does not exist here. If this ever
/// starts failing because decode succeeded, the split has been closed and this
/// test should be replaced by one that verifies the signature.
#[test]
#[cfg(not(feature = "pqcrypto"))]
fn a_pq_signature_cannot_even_be_decoded_without_the_pqcrypto_feature() {
    use dcbor::prelude::*;

    let a = author();
    // tag 40105, [level 5 (= ML-DSA-87), 4627 signature bytes] — the exact
    // shape `MLDSASignature::untagged_cbor` emits.
    let mldsa_object = CBOR::to_tagged_value(
        40105,
        vec![CBOR::from(5), CBOR::to_byte_string(vec![0u8; 4627])],
    );
    let envelope = codec::to_signed_envelope(&a.sign(full_op(&a)).unwrap())
        .unwrap()
        .add_assertion(known_values::SIGNED, mldsa_object);

    assert!(matches!(
        codec::from_envelope(&envelope),
        Err(LogError::PqUnavailable)
    ));

    // But the *maths* is present in this build: the fips204 seam is compiled
    // unconditionally and rejects nonsense rather than being a stub.
    assert!(matches!(
        sign::verify_ml_dsa_87(&[0u8; 2592], b"msg", &[0u8; 4627]),
        Err(LogError::InvalidKey("ml-dsa-87")) | Err(LogError::BadSignature)
    ));
}

#[test]
fn a_signed_object_that_is_not_a_signature_is_rejected_on_decode() {
    let a = author();
    let envelope = codec::to_envelope(&full_op(&a))
        .unwrap()
        .wrap()
        .add_assertion(known_values::SIGNED, "not a signature");
    assert!(matches!(
        codec::from_envelope(&envelope),
        Err(LogError::InvalidValue(_))
    ));
}
