//! Co-signature by keys other than `Op.actor`.
//!
//! `docs/standards/identikey-group-v1.md` builds a group entry on this crate
//! without changing it: one op, several Ed25519 signatures by different
//! members over the same digest, each attributed to its own key by a verifier
//! that does not call [`sign::verify`]. These tests are what that standard
//! relies on. They started as spike H1 of the `add-governed-groups` change
//! (`docs/spikes/add-governed-groups-h1/finding.md`).
//!
//! The group verifier's own path is spelled out in `attribute` below: read the
//! raw 64-byte signature out of `Signature::Ed25519`, parse the key with
//! `ed25519-dalek`, refuse a weak key, and call `verify_strict`. It does not
//! hand an unchecked key to `bc-components`.

use std::collections::HashSet;

use bc_components::Digest;
use bc_envelope::prelude::*;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use identikey_log::{codec, sign, Author, Hash32, Hlc, LogError, Op, Signature, SignedOp};

fn proposer() -> Author { Author::from_seed(&[1u8; 32]) }
fn member_a() -> Author { Author::from_seed(&[2u8; 32]) }
fn member_b() -> Author { Author::from_seed(&[3u8; 32]) }
fn stranger() -> Author { Author::from_seed(&[9u8; 32]) }

/// An op in the shape a group entry uses: a kind, a canonical body, one
/// parent, and no assertion of any kind. The body is `{"seq": 1}`.
fn entry(actor: Hash32) -> Op {
    Op::new("group.roster", actor, Hlc::new(1_700_000_000_001, 0))
        .with_body(vec![0xa1, 0x63, b's', b'e', b'q', 0x01])
        .with_parents([[0x10u8; 32]])
}

/// What members sign.
fn sign_digest(op: &Op) -> [u8; 32] {
    *codec::to_envelope(op).unwrap().wrap().digest().data()
}

fn raw(sig: &Signature) -> [u8; 64] {
    match sig {
        Signature::Ed25519(bytes) => *bytes,
        #[allow(unreachable_patterns)]
        _ => panic!("a group entry carries Ed25519 signatures only"),
    }
}

/// A key the group standard accepts: the canonical encoding of a curve point
/// that is not of small order. `from_bytes` alone decodes a `y` at or above
/// the field prime, so the decoded point is re-encoded and compared.
fn valid_key(bytes: &Hash32) -> Option<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes).ok()?;
    if key.is_weak() || key.to_edwards().compress().to_bytes() != *bytes {
        return None;
    }
    Some(key)
}

/// Strict Ed25519 under one key, the way a group verifier checks it.
fn verifies_under(key: &Hash32, digest: &[u8; 32], sig: &Signature) -> bool {
    let Some(key) = valid_key(key) else { return false };
    key.verify_strict(digest, &DalekSignature::from_bytes(&raw(sig))).is_ok()
}

/// The candidate keys a signature verifies under.
fn attribute(candidates: &[Hash32], digest: &[u8; 32], sig: &Signature) -> Vec<Hash32> {
    candidates.iter().copied().filter(|k| verifies_under(k, digest, sig)).collect()
}

/// Proposer signs, two other members co-sign.
fn co_signed() -> (Op, SignedOp) {
    let p = proposer();
    let op = entry(p.actor());
    let signed = p.sign(op.clone()).unwrap();
    let signed = member_a().counter_sign(signed).unwrap();
    let signed = member_b().counter_sign(signed).unwrap();
    (op, signed)
}

#[test]
fn each_co_signature_verifies_under_its_own_key_and_no_other() {
    let (op, signed) = co_signed();
    let digest = sign_digest(&op);
    let roster = [proposer().actor(), member_a().actor(), member_b().actor()];

    let bytes = codec::encode_signed(&signed).unwrap();
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(decoded.op, op);
    assert_eq!(decoded.elided, 0);
    assert_eq!(decoded.signatures.len(), 3);

    let mut signers = HashSet::new();
    for sig in &decoded.signatures {
        let keys = attribute(&roster, &digest, sig);
        assert_eq!(keys.len(), 1, "one signature, exactly one candidate key");
        signers.insert(keys[0]);
    }
    assert_eq!(signers, roster.into_iter().collect::<HashSet<_>>());
}

#[test]
fn two_non_actor_keys_alone_can_sign_an_op() {
    // The proposer does not sign here. The log crate does not require the
    // actor's signature to be among those attached. A group verifier does.
    let op = entry(proposer().actor());
    let signed = member_a().sign(op.clone()).unwrap();
    let signed = member_b().counter_sign(signed).unwrap();
    let digest = sign_digest(&op);

    let decoded = codec::decode(&codec::encode_signed(&signed).unwrap()).unwrap();
    assert_eq!(decoded.signatures.len(), 2);
    for sig in &decoded.signatures {
        assert!(!verifies_under(&proposer().actor(), &digest, sig));
        let keys = attribute(&[member_a().actor(), member_b().actor()], &digest, sig);
        assert_eq!(keys.len(), 1);
    }
}

#[test]
fn the_generic_verifier_rejects_a_co_signed_op() {
    // `sign::verify` checks every signature against `Op.actor`. A co-signed
    // group entry therefore never passes it, and a group verifier does not
    // call it.
    let (_, signed) = co_signed();
    assert!(matches!(sign::verify(&signed), Err(LogError::BadSignature)));

    let bytes = codec::encode_signed(&signed).unwrap();
    assert!(matches!(sign::decode_and_verify(&bytes), Err(LogError::BadSignature)));

    // Control: with the proposer's signature alone it passes.
    let alone = proposer().sign(signed.op.clone()).unwrap();
    sign::verify(&alone).unwrap();
}

#[test]
fn the_sign_digest_is_not_the_entry_hash() {
    let (op, signed) = co_signed();
    let entry_bytes = codec::encode(&op).unwrap();
    let entry_hash = codec::content_hash(&op).unwrap();

    assert_eq!(entry_hash, *blake3::hash(&entry_bytes).as_bytes());
    assert_ne!(entry_hash, sign_digest(&op));

    // Signatures are not part of the entry bytes, so co-signing moves neither
    // value.
    let decoded = codec::decode(&codec::encode_signed(&signed).unwrap()).unwrap();
    assert_eq!(codec::content_hash(&decoded.op).unwrap(), entry_hash);
    assert_eq!(sign_digest(&decoded.op), sign_digest(&op));

    // A signature over the entry hash is not a signature over the entry.
    let p = proposer();
    let over_hash = Signature::Ed25519(
        ed25519_dalek::Signer::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            &entry_hash,
        )
        .to_bytes(),
    );
    assert!(verifies_under(&p.actor(), &entry_hash, &over_hash));
    assert!(!verifies_under(&p.actor(), &sign_digest(&op), &over_hash));
}

#[test]
fn the_digests_can_be_computed_without_this_crate() {
    // The portable construction the standard writes down, checked against
    // what `bc-envelope` computes.
    let (op, signed) = co_signed();
    let sha256 = |bytes: &[u8]| *Digest::from_image(bytes).data();

    // A group entry has no assertion, so its unsigned envelope is a bare
    // leaf: tag 200 (envelope), tag 201 (leaf), then the core map.
    let unsigned = codec::to_envelope(&op).unwrap();
    assert!(unsigned.assertions().is_empty());
    let core = unsigned.subject().try_leaf().unwrap().to_cbor_data();
    assert_eq!(core[0], 0xa7, "a map of seven pairs");
    let entry_bytes = codec::encode(&op).unwrap();
    assert_eq!(entry_bytes, [&[0xd8, 0xc8, 0xd8, 0xc9][..], &core].concat());

    // leaf digest = SHA-256(core map bytes); wrapper digest = SHA-256(leaf
    // digest). The wrapper digest is what is signed.
    let leaf = sha256(&core);
    assert_eq!(leaf, *unsigned.digest().data());
    assert_eq!(sha256(&leaf), sign_digest(&op));

    // A signature assertion: {3: 201(40020([2, sig]))}. Its digest is
    // SHA-256(digest(predicate) || digest(object)), each a SHA-256 of the
    // untagged-leaf CBOR.
    let predicate = sha256(&[0xd9, 0x9c, 0x40, 0x03]); // 40000(3), 'signed'
    let assertion_digest = |sig: &Signature| {
        let mut object = vec![0xd9, 0x9c, 0x54, 0x82, 0x02, 0x58, 0x40]; // 40020([2, h'..'])
        object.extend_from_slice(&raw(sig));
        sha256(&[predicate, sha256(&object)].concat())
    };

    // The signed envelope: tag 200, an array of the wrapped subject and the
    // assertions, sorted by assertion digest.
    let mut sigs = signed.signatures.clone();
    sigs.sort_by_key(assertion_digest);
    let mut expected = vec![0xd8, 0xc8, 0x84];
    expected.extend_from_slice(&entry_bytes);
    for sig in &sigs {
        expected.extend_from_slice(&[0xa1, 0x03, 0xd8, 0xc9]);
        expected.extend_from_slice(&[0xd9, 0x9c, 0x54, 0x82, 0x02, 0x58, 0x40]);
        expected.extend_from_slice(&raw(sig));
    }
    assert_eq!(codec::encode_signed(&signed).unwrap(), expected);
}

#[test]
fn wire_order_is_assertion_digest_order_not_signing_order() {
    let p = proposer();
    let op = entry(p.actor());
    let digest = sign_digest(&op);

    let forward = member_b()
        .counter_sign(member_a().counter_sign(p.sign(op.clone()).unwrap()).unwrap())
        .unwrap();
    let backward = p
        .counter_sign(member_a().counter_sign(member_b().sign(op.clone()).unwrap()).unwrap())
        .unwrap();

    // Ed25519 is deterministic, so both orders carry the same three
    // signatures and encode to the same bytes.
    let bytes = codec::encode_signed(&forward).unwrap();
    assert_eq!(bytes, codec::encode_signed(&backward).unwrap());

    // Decoding returns them in the order they sit on the wire, which is
    // ascending assertion digest.
    let decoded = codec::decode(&bytes).unwrap();
    let envelope = Envelope::try_from_cbor_data(bytes.clone()).unwrap();
    assert_eq!(sign::signatures_of(&envelope).unwrap(), decoded.signatures);
    let digests: Vec<_> = decoded
        .signatures
        .iter()
        .map(|s| Envelope::new_assertion(known_values::SIGNED, s.clone()).digest())
        .collect();
    assert!(digests.windows(2).all(|w| w[0] < w[1]));

    // So a transport that lists one key per signature lists them in this
    // order, and it need not be the order the members signed in.
    let wire_keys: Vec<Hash32> = decoded
        .signatures
        .iter()
        .map(|s| attribute(&[p.actor(), member_a().actor(), member_b().actor()], &digest, s)[0])
        .collect();
    assert_eq!(wire_keys.iter().collect::<HashSet<_>>().len(), 3);

    // Re-encoding what was decoded gives the same bytes. A group verifier
    // uses this to refuse any other encoding of the entry.
    assert_eq!(codec::encode_signed(&decoded).unwrap(), bytes);
}

#[test]
fn a_signature_by_a_key_outside_the_candidates_is_unattributable() {
    let (op, signed) = co_signed();
    let signed = stranger().counter_sign(signed).unwrap();
    let digest = sign_digest(&op);
    let roster = [proposer().actor(), member_a().actor(), member_b().actor()];

    let decoded = codec::decode(&codec::encode_signed(&signed).unwrap()).unwrap();
    assert_eq!(decoded.signatures.len(), 4);
    let unattributed =
        decoded.signatures.iter().filter(|s| attribute(&roster, &digest, s).is_empty()).count();
    assert_eq!(unattributed, 1, "the log codec carries it, the group verifier must refuse it");
}

#[test]
fn a_repeated_signature_does_not_survive_encoding() {
    // The same key signing twice gives the same signature, and an envelope
    // holds one copy of an assertion. Plurality cannot be faked by repetition.
    let p = proposer();
    let op = entry(p.actor());
    let twice = p.counter_sign(p.sign(op).unwrap()).unwrap();
    assert_eq!(twice.signatures.len(), 2);
    let decoded = codec::decode(&codec::encode_signed(&twice).unwrap()).unwrap();
    assert_eq!(decoded.signatures.len(), 1);
}

#[test]
fn an_elided_signature_is_visible_to_the_decoder() {
    let (_, signed) = co_signed();
    let envelope = codec::to_signed_envelope(&signed).unwrap();
    let bytes = envelope.to_cbor_data();

    let target = envelope.assertions().remove(0);
    let redacted = envelope.elide_removing_target(&target);
    let redacted_bytes = redacted.to_cbor_data();
    assert_ne!(redacted_bytes, bytes);

    let decoded = codec::decode(&redacted_bytes).unwrap();
    assert_eq!(decoded.elided, 1);
    assert_eq!(decoded.signatures.len(), 2);
    // Re-encoding drops the elided element, so the byte-equality check also
    // catches it.
    assert_ne!(codec::encode_signed(&decoded).unwrap(), redacted_bytes);
}

#[test]
fn an_elided_inner_assertion_is_visible_and_moves_the_entry_hash() {
    // A group entry carries no inner assertion at all. This shows what the
    // verifier would see if one were present and elided.
    let p = proposer();
    let op = entry(p.actor()).with_timestamp(1_700_000_000);
    let signed = member_a().counter_sign(p.sign(op.clone()).unwrap()).unwrap();
    let envelope = codec::to_signed_envelope(&signed).unwrap();

    let target = Envelope::new_assertion(
        codec::PRED_TIMESTAMP,
        CBOR::to_tagged_value(codec::TAG_EPOCH_TIME, 1_700_000_000u64),
    );
    let redacted = envelope.elide_removing_target(&target);
    assert_eq!(redacted.digest(), envelope.digest(), "the signatures still cover it");

    let decoded = codec::decode(&redacted.to_cbor_data()).unwrap();
    assert_eq!(decoded.elided, 1);
    assert_eq!(decoded.op.timestamp, None);
    // The decoded op is a different op: other entry bytes, another entry
    // hash, another sign digest.
    assert_ne!(
        codec::content_hash(&decoded.op).unwrap(),
        codec::content_hash(&op).unwrap()
    );
    assert_ne!(sign_digest(&decoded.op), sign_digest(&op));
}

#[test]
fn a_key_that_is_not_a_point_is_weak_or_is_non_canonical_never_verifies() {
    let (op, signed) = co_signed();
    let digest = sign_digest(&op);

    // Some 32-byte strings are not Ed25519 points. Find one.
    let not_a_point = (0u8..=255)
        .map(|b| [b; 32])
        .find(|k| VerifyingKey::from_bytes(k).is_err())
        .expect("a byte string that does not decompress");
    // The identity point is a valid encoding and a weak key.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(VerifyingKey::from_bytes(&identity).unwrap().is_weak());

    // The field prime plus three, little-endian. The library decodes it to
    // the point with y = 3, which is not weak. It is not a canonical key.
    let mut non_canonical = [0xffu8; 32];
    non_canonical[0] = 0xf0;
    non_canonical[31] = 0x7f;
    let decoded = VerifyingKey::from_bytes(&non_canonical).expect("the library decodes it");
    assert!(!decoded.is_weak());
    assert_ne!(decoded.to_edwards().compress().to_bytes(), non_canonical);
    assert!(valid_key(&non_canonical).is_none());

    for key in [proposer().actor(), member_a().actor(), member_b().actor()] {
        assert!(valid_key(&key).is_some());
    }
    for sig in &signed.signatures {
        assert!(!verifies_under(&not_a_point, &digest, sig));
        assert!(!verifies_under(&identity, &digest, sig));
        assert!(!verifies_under(&non_canonical, &digest, sig));
    }
}
