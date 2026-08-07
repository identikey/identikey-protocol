//! Round-trip, rejection and tamper-detection behaviour.

use identikey_log::{codec, error::LogError, sign, Author, Hlc, Op, SigAlg, Signature};

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
    assert_eq!(codec::encode(&decoded.op).unwrap(), bytes);
}

#[test]
fn a_body_less_op_has_a_six_key_core_map() {
    let a = author();
    let op = Op::new("k.n.v", a.actor(), Hlc::new(1, 0));
    let bytes = codec::encode(&op).unwrap();
    // `d8c8 81 d8c9 a6` — tag 200, array(1), tag 201, map(6).
    assert_eq!(&bytes[..5], &[0xd8, 0xc8, 0x81, 0xd8, 0xc9]);
    assert_eq!(bytes[5], 0xa6, "core map should have 6 keys without a body");
    assert_eq!(codec::decode(&bytes).unwrap().op, op);
}

#[test]
fn multiple_signatures_are_all_checked_and_are_order_stable() {
    let a = author();
    let b = Author::from_seed(&[9u8; 32]);
    let op = full_op(&a);
    let signed = b.counter_sign(a.sign(op).unwrap()).unwrap();
    assert_eq!(signed.signatures.len(), 2);

    // Both cover the same unsigned bytes, but only `a` is the actor, so the
    // all-present-must-verify policy fails on `b`'s signature.
    assert!(matches!(sign::verify(&signed), Err(LogError::BadSignature)));

    let bytes = codec::encode_signed(&signed).unwrap();
    assert_eq!(codec::decode(&bytes).unwrap(), signed);
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
    signed.signatures[0].value[0] ^= 0x01;
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
fn an_unknown_attribute_label_is_rejected_rather_than_silently_dropped() {
    let a = author();
    let signed = a.sign(full_op(&a)).unwrap();
    let bytes = codec::encode_signed(&signed).unwrap();
    // Rename the `deps` attribute label to `depz` — same length, so the rest
    // of the encoding is untouched.
    let pos = bytes.windows(4).position(|w| w == b"deps").unwrap();
    let mut mutated = bytes.clone();
    mutated[pos + 3] = b'z';
    assert!(codec::decode(&mutated).is_err());
}

#[test]
fn a_pq_signature_with_no_pq_key_is_rejected_not_ignored() {
    let a = author();
    let mut signed = a.sign(full_op(&a)).unwrap();
    signed.signatures.push(Signature { alg: SigAlg::MlDsa87, value: vec![0u8; 4627] });
    let bytes = codec::encode_signed(&signed).unwrap();
    // It encodes and decodes structurally...
    assert_eq!(codec::decode(&bytes).unwrap().signatures.len(), 2);
    // ...but there is nowhere in a v4 core map for an ML-DSA-87 public key, so
    // a plain `verify` has nothing to check it against and must not pass it.
    assert!(matches!(sign::verify(&signed), Err(LogError::PqDangling)));
}

#[test]
fn an_unknown_signature_algorithm_tag_is_rejected_on_decode() {
    let a = author();
    let signed = a.sign(full_op(&a)).unwrap();
    let bytes = codec::encode_signed(&signed).unwrap();
    // `ed25519` → `ed25519x` would change the length prefix, so swap a letter
    // instead: `ed25519` → `ed2551A`.
    let pos = bytes.windows(7).position(|w| w == b"ed25519").unwrap();
    let mut mutated = bytes.clone();
    mutated[pos + 6] = b'A';
    assert!(matches!(codec::decode(&mutated), Err(LogError::UnknownAlg(_))));
}
