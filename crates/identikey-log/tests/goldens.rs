//! Cross-runtime golden vectors — the regression gate for the wire format.
//!
//! These bytes were produced by an independent (Zig) implementation. The
//! signing seed is all-zeros and RFC 8032 Ed25519 is deterministic, so the
//! vectors are fully self-contained: any conformant implementation must
//! reproduce them byte for byte, including the signature.
//!
//! The vendored copy of the manifest lives in `tests/fixtures/` for provenance;
//! the constants below are asserted against it so the two cannot drift.

use identikey_log::{codec, sign, Author, Hlc, Op, SigAlg};

const MANIFEST: &str = include_str!("fixtures/action_v4_goldens.json");

/// `action_v4_unsigned`
const UNSIGNED_HEX: &str = "d8c881d8c9a763686c63821b0000018bcfe568000764626f647943820102646b696e64781a776f726c64747265652e6b616e62616e2d636172642e6d6f766564747970656b62616c6c2e616374696f6e656163746f7258203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da296d706172656e742d68617368657381582010101010101010101010101010101010101010101010101010101010101010106e666f726d61742d76657273696f6e04";
const UNSIGNED_BLAKE3: &str =
    "5b97ee37cd5fc24ee7e88c96d6613dadf9fafe4ebea5429ac328af133e2fd27b";

/// `action_v4_signed`
const SIGNED_HEX: &str = "d8c882d8c9a763686c63821b0000018bcfe568000764626f647943820102646b696e64781a776f726c64747265652e6b616e62616e2d636172642e6d6f766564747970656b62616c6c2e616374696f6e656163746f7258203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da296d706172656e742d68617368657381582010101010101010101010101010101010101010101010101010101010101010106e666f726d61742d76657273696f6e0482667369676e656482676564323535313958409c6046ab78bebcb744ed214fa0e44f362e0853a15360c8c781458230058f1aaa771da72aaeb20e95a35cf42c0a0188e7bcc257710220306d30b9202d72bbde03";
const SIGNED_BLAKE3: &str =
    "3c7a55d8f4b8012d054a572057e042fe764c314aead95b28d972cfdcb12a8c7f";

/// The Ed25519 public key derived from the all-zeros seed. Public test vector.
const ACTOR_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The logical value both vectors encode.
fn golden_op(actor: [u8; 32]) -> Op {
    Op::new("worldtree.kanban-card.move", actor, Hlc::new(1_700_000_000_000, 7))
        .with_body(vec![0x82, 0x01, 0x02])
        .with_parents([[0x10u8; 32]])
}

#[test]
fn constants_match_the_vendored_manifest() {
    for needle in [UNSIGNED_HEX, UNSIGNED_BLAKE3, SIGNED_HEX, SIGNED_BLAKE3, ACTOR_HEX] {
        assert!(MANIFEST.contains(needle), "constant drifted from the manifest: {needle}");
    }
}

#[test]
fn actor_is_derived_from_the_all_zeros_seed() {
    let author = Author::from_seed(&[0u8; 32]);
    assert_eq!(hex(&author.actor()), ACTOR_HEX);
}

#[test]
fn unsigned_golden_bytes_reproduce_exactly() {
    let author = Author::from_seed(&[0u8; 32]);
    let bytes = codec::encode(&golden_op(author.actor())).unwrap();
    assert_eq!(hex(&bytes), UNSIGNED_HEX);
    assert_eq!(bytes, unhex(UNSIGNED_HEX));
}

#[test]
fn unsigned_golden_blake3_matches() {
    // content_hash is blake3 over precisely these bytes, so the digest of the
    // unsigned vector *is* the op's content_hash.
    let author = Author::from_seed(&[0u8; 32]);
    let op = golden_op(author.actor());
    assert_eq!(hex(&codec::content_hash(&op).unwrap()), UNSIGNED_BLAKE3);
    assert_eq!(hex(blake3::hash(&unhex(UNSIGNED_HEX)).as_bytes()), UNSIGNED_BLAKE3);
}

#[test]
fn signed_golden_bytes_reproduce_exactly() {
    let author = Author::from_seed(&[0u8; 32]);
    let signed = author.sign(golden_op(author.actor())).unwrap();
    let bytes = codec::encode_signed(&signed).unwrap();
    assert_eq!(hex(&bytes), SIGNED_HEX);
}

#[test]
fn signed_golden_blake3_matches() {
    assert_eq!(hex(blake3::hash(&unhex(SIGNED_HEX)).as_bytes()), SIGNED_BLAKE3);
}

#[test]
fn content_hash_is_unchanged_by_attaching_signatures() {
    let author = Author::from_seed(&[0u8; 32]);
    let op = golden_op(author.actor());
    let before = codec::content_hash(&op).unwrap();
    let signed = author.sign(op).unwrap();
    assert_eq!(codec::content_hash(&signed.op).unwrap(), before);
}

#[test]
fn goldens_decode_and_verify() {
    let unsigned = codec::decode(&unhex(UNSIGNED_HEX)).unwrap();
    assert!(!unsigned.is_signed());
    let author = Author::from_seed(&[0u8; 32]);
    assert_eq!(unsigned.op, golden_op(author.actor()));

    let (signed, hash) = sign::decode_and_verify(&unhex(SIGNED_HEX)).unwrap();
    assert_eq!(signed.signatures.len(), 1);
    assert_eq!(signed.signatures[0].alg, SigAlg::Ed25519);
    assert_eq!(signed.op, golden_op(author.actor()));
    // The identity of a signed op is still the hash of its unsigned form.
    assert_eq!(hex(&hash), UNSIGNED_BLAKE3);
}

#[test]
fn round_trip_is_byte_stable() {
    for h in [UNSIGNED_HEX, SIGNED_HEX] {
        let bytes = unhex(h);
        let decoded = codec::decode(&bytes).unwrap();
        assert_eq!(codec::encode_signed(&decoded).unwrap(), bytes);
    }
}
