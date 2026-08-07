//! Cross-runtime golden vectors — the regression gate for the wire format.
//!
//! # Re-baselined 2026-08-07 (Dreamball-y4t.16 / y4t.18)
//!
//! These vectors used to come from an independent Zig implementation of a
//! format that borrowed Gordian Envelope's tags but not its structure. That
//! format is gone: the decision recorded in Dreamball-y4t.16 moved this crate
//! onto real `bc_envelope::Envelope`, and every byte changed at once. The
//! superseded values are pinned below next to the live ones — not as a second
//! gate, but so the change reads as a decision with a diff rather than a
//! silent overwrite. The Zig encoder can no longer produce these bytes and is
//! not expected to; the whole Zig substrate is what this port replaces.
//!
//! What did *not* change: the signing seed is still all-zeros, Ed25519 (RFC
//! 8032) is still deterministic, and the assertion order is fixed by Gordian's
//! digest sort. So these vectors remain fully self-contained — any conformant
//! Gordian Envelope implementation must reproduce them byte for byte,
//! signature included.
//!
//! The vendored copy of the manifest lives in `tests/fixtures/` for provenance;
//! the constants below are asserted against it so the two cannot drift.

use identikey_log::{codec, sign, Author, Hlc, Op, Signature};

const MANIFEST: &str = include_str!("fixtures/action_v4_goldens.json");

/// `action_v4_unsigned` — `200(201(core))`, a bare Gordian subject.
const UNSIGNED_HEX: &str = "d8c8d8c9a763686c63821b0000018bcfe568000764626f647943820102646b696e64781a776f726c64747265652e6b616e62616e2d636172642e6d6f766564747970656b62616c6c2e616374696f6e656163746f7258203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da296d706172656e742d68617368657381582010101010101010101010101010101010101010101010101010101010101010106e666f726d61742d76657273696f6e04";
const UNSIGNED_BLAKE3: &str =
    "cd1afaeec8d6af64b5e1b2e907acbf42ed68316d80e5e430ef3a92e9cbae78c3";

/// `action_v4_signed` — `200([200(201(core)), {3: 201(40020([2, sig]))}])`:
/// the unsigned envelope wrapped, with one `'signed'` assertion.
const SIGNED_HEX: &str = "d8c882d8c8d8c9a763686c63821b0000018bcfe568000764626f647943820102646b696e64781a776f726c64747265652e6b616e62616e2d636172642e6d6f766564747970656b62616c6c2e616374696f6e656163746f7258203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da296d706172656e742d68617368657381582010101010101010101010101010101010101010101010101010101010101010106e666f726d61742d76657273696f6e04a103d8c9d99c54820258406ce51ce17e05c5db30980200443eade191f3ea4aacf16741c5fba2e3af0349f7dba77a80e74bc3c9a09d9c1dfa23de193366116a8028bc1f737a11caaa460d06";
const SIGNED_BLAKE3: &str =
    "28d0cfa146da697b031bf8d414e0eeb0cb0b083a0d86471b1d6b78349753230a";

/// The Ed25519 public key derived from the all-zeros seed. Public test vector.
/// **Unchanged** by the re-baselining — the identity is the one thing that did
/// not move.
const ACTOR_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

/// The superseded pre-Gordian vectors, for the record. See the module comment.
mod pre_gordian {
    /// Was `200([201(core)])` — note the `81`, the one-element array Gordian
    /// does not emit and its decoder rejects outright.
    pub const UNSIGNED_HEX: &str = "d8c881d8c9a763686c63821b0000018bcfe568000764626f647943820102646b696e64781a776f726c64747265652e6b616e62616e2d636172642e6d6f766564747970656b62616c6c2e616374696f6e656163746f7258203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da296d706172656e742d68617368657381582010101010101010101010101010101010101010101010101010101010101010106e666f726d61742d76657273696f6e04";
    pub const UNSIGNED_BLAKE3: &str =
        "5b97ee37cd5fc24ee7e88c96d6613dadf9fafe4ebea5429ac328af133e2fd27b";
    /// Was a 2-element array attribute `["signed", ["ed25519", <64 bytes>]]`
    /// appended to the same array, over a raw Ed25519 signature of the literal
    /// unsigned bytes.
    pub const SIGNED_HEX: &str = "d8c882d8c9a763686c63821b0000018bcfe568000764626f647943820102646b696e64781a776f726c64747265652e6b616e62616e2d636172642e6d6f766564747970656b62616c6c2e616374696f6e656163746f7258203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da296d706172656e742d68617368657381582010101010101010101010101010101010101010101010101010101010101010106e666f726d61742d76657273696f6e0482667369676e656482676564323535313958409c6046ab78bebcb744ed214fa0e44f362e0853a15360c8c781458230058f1aaa771da72aaeb20e95a35cf42c0a0188e7bcc257710220306d30b9202d72bbde03";
    pub const SIGNED_BLAKE3: &str =
        "3c7a55d8f4b8012d054a572057e042fe764c314aead95b28d972cfdcb12a8c7f";
}

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
    // The manifest must also carry the superseded values, so the re-baselining
    // is auditable from the fixture alone.
    for needle in [
        pre_gordian::UNSIGNED_HEX,
        pre_gordian::UNSIGNED_BLAKE3,
        pre_gordian::SIGNED_HEX,
        pre_gordian::SIGNED_BLAKE3,
    ] {
        assert!(MANIFEST.contains(needle), "manifest lost a superseded value: {needle}");
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
fn the_subject_only_envelope_is_bare_not_wrapped_in_an_array() {
    // `d8c8 d8c9` — tag 200, tag 201. The pre-Gordian `81` between them is
    // gone; this is the single most load-bearing byte of the re-baselining.
    let bytes = unhex(UNSIGNED_HEX);
    assert_eq!(&bytes[..4], &[0xd8, 0xc8, 0xd8, 0xc9]);
    assert_eq!(&unhex(pre_gordian::UNSIGNED_HEX)[..5], &[0xd8, 0xc8, 0x81, 0xd8, 0xc9]);
    // And the core map itself is byte-identical across the change: only the
    // envelope structure moved.
    assert_eq!(bytes[4..], unhex(pre_gordian::UNSIGNED_HEX)[5..]);
}

#[test]
fn unsigned_golden_blake3_matches() {
    // content_hash is blake3 over precisely these bytes, so the digest of the
    // unsigned vector *is* the op's content_hash.
    let author = Author::from_seed(&[0u8; 32]);
    let op = golden_op(author.actor());
    assert_eq!(hex(&codec::content_hash(&op).unwrap()), UNSIGNED_BLAKE3);
    assert_eq!(hex(blake3::hash(&unhex(UNSIGNED_HEX)).as_bytes()), UNSIGNED_BLAKE3);
    // The re-baselining moved it. Recorded, not implied.
    assert_ne!(UNSIGNED_BLAKE3, pre_gordian::UNSIGNED_BLAKE3);
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
fn the_signature_is_a_tagged_gordian_signature_under_a_known_value() {
    // `a1 03` — a single-entry assertion map whose predicate is the KNOWN
    // VALUE 3 ('signed'), not the six text bytes "signed". The object is
    // `d8c9 d99c54 8202 5840…`: a leaf holding tag 40020 (Signature),
    // scheme 2 (Ed25519), 64 bytes.
    assert!(SIGNED_HEX.contains("a103d8c9d99c548202584"), "got {SIGNED_HEX}");
    // The superseded form spelled the label out: `82 66 "signed"`.
    assert!(pre_gordian::SIGNED_HEX.contains("82667369676e6564"));
    assert!(!SIGNED_HEX.contains("7369676e6564"));
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
    assert!(matches!(signed.signatures[0], Signature::Ed25519(_)));
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

#[test]
fn the_superseded_vectors_are_no_longer_decodable() {
    // Not a regression — the point. `bc-envelope` rejects the one-element
    // array outright ("node must have at least two elements"), which is why
    // the format could never have been migrated in place.
    assert!(codec::decode(&unhex(pre_gordian::UNSIGNED_HEX)).is_err());
    assert!(codec::decode(&unhex(pre_gordian::SIGNED_HEX)).is_err());
}
