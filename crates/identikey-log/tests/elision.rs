//! **The test that only passes on real Gordian Envelope.**
//!
//! Everything else in this crate's suite passed against the pre-Gordian
//! format too — the one that borrowed the `#6.200` / `#6.201` tags and the
//! word "envelope" but signed a literal byte string. That is the failure mode
//! this file exists to close: a lookalike format satisfies every test that
//! only checks round-tripping, rejection and tamper-detection, because those
//! are properties any self-consistent encoder has.
//!
//! Elision is not such a property. A signature over literal canonical bytes
//! *cannot* survive the removal of an assertion, because removing it changes
//! the bytes. A signature over a Merkle digest tree can, because the elided
//! assertion is replaced by its own digest and every enclosing digest is
//! unchanged. There is no way to fake that with the right tags and the wrong
//! structure.
//!
//! So this is the acceptance gate for Dreamball-y4t.18, and it is deliberately
//! written to be falsifiable: it asserts the *mechanism* (the digest is
//! unchanged), the *consequence* (the signature still verifies), and — because
//! a test where everything trivially verifies would be worse than no test —
//! two negatives showing the verifier is still discriminating.

use std::collections::HashSet;

use bc_envelope::prelude::*;
use identikey_log::{codec, sign, Author, Hlc, LogError, Op};

fn author() -> Author { Author::from_seed(&[3u8; 32]) }

/// An op with four elidable assertions, so there is something to redact.
fn op(a: &Author) -> Op {
    Op::new("worldtree.kanban-card.move", a.actor(), Hlc::new(1_700_000_000_001, 3))
        .with_body(vec![0x82, 0x01, 0x02])
        .with_parents([[0x10u8; 32]])
        .with_deps([[0x20u8; 32]])
        .with_nacks([[0x30u8; 32]])
        .with_target_fp([0x40u8; 32])
        .with_timestamp(1_700_000_000)
}

/// The `'timestamp'` assertion as a standalone envelope — the redaction
/// target. Digests are structural, so this reconstructs the exact element
/// inside the signed op.
fn timestamp_assertion(secs: u64) -> Envelope {
    Envelope::new_assertion(
        codec::PRED_TIMESTAMP,
        CBOR::to_tagged_value(codec::TAG_EPOCH_TIME, secs),
    )
}

fn deps_assertion(dep: [u8; 32]) -> Envelope {
    Envelope::new_assertion(codec::PRED_DEPS, CBOR::to_byte_string(dep))
}

/// The single elided element among an envelope's (unwrapped) assertions.
fn the_elided_assertion(envelope: &Envelope) -> Envelope {
    let inner = envelope.try_unwrap().unwrap_or_else(|_| envelope.clone());
    let mut elided: Vec<_> =
        inner.assertions().into_iter().filter(|x| x.is_elided()).collect();
    assert_eq!(elided.len(), 1, "expected exactly one elided assertion");
    elided.remove(0)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn a_signature_survives_elision_of_an_assertion() {
    let a = author();
    let op = op(&a);

    let unsigned = codec::to_envelope(&op).unwrap();
    let signed = a.sign_envelope(&unsigned);

    // Baseline: the op as authored verifies, and carries the timestamp.
    sign::verify_envelope(&signed, &a.actor()).unwrap();
    assert_eq!(
        codec::from_envelope(&signed).unwrap().op.timestamp,
        Some(1_700_000_000)
    );

    // Redact the timestamp. The holder does this; the author is not involved
    // and is not asked to re-sign.
    let redacted = signed.elide_removing_target(&timestamp_assertion(1_700_000_000));

    // 1. The content really is gone.
    let decoded = codec::from_envelope(&redacted).unwrap();
    assert_eq!(decoded.op.timestamp, None, "the timestamp must not survive");
    assert_eq!(decoded.elided, 1, "and its absence must be visible, not silent");
    assert_ne!(redacted.to_cbor_data(), signed.to_cbor_data());
    // The timestamp value is not merely unreachable through the decoder — it
    // is not in the bytes at all.
    let timestamp_cbor =
        CBOR::to_tagged_value(codec::TAG_EPOCH_TIME, 1_700_000_000u64).to_cbor_data();
    assert!(contains(&signed.to_cbor_data(), &timestamp_cbor));
    assert!(!contains(&redacted.to_cbor_data(), &timestamp_cbor));
    // What replaced it is exactly its own digest.
    assert_eq!(
        the_elided_assertion(&redacted).digest(),
        timestamp_assertion(1_700_000_000).digest()
    );

    // 2. THE MECHANISM. The elided assertion is replaced by its own digest,
    //    so every enclosing digest — including the wrapped subject the
    //    signature covers — is bit-identical.
    assert_eq!(
        redacted.digest(),
        signed.digest(),
        "elision must not perturb the digest tree"
    );

    // 3. THE POINT. The author's signature still verifies over the redacted
    //    op. This is the property the whole migration was for, and the one
    //    the pre-Gordian format could not have at any price short of
    //    hand-rolling a Merkle tree.
    sign::verify_envelope(&redacted, &a.actor())
        .expect("a Gordian signature survives elision");

    // The other assertions are untouched and still readable.
    assert_eq!(decoded.op.deps, vec![[0x20u8; 32]]);
    assert_eq!(decoded.op.nacks, vec![[0x30u8; 32]]);
    assert_eq!(decoded.op.target_fp, Some([0x40u8; 32]));
    // ...and the subject, which is not elidable in this profile, is intact.
    assert_eq!(decoded.op.kind, "worldtree.kanban-card.move");
    assert_eq!(decoded.op.actor, a.actor());
}

#[test]
fn every_assertion_is_independently_elidable_and_all_of_them_at_once() {
    let a = author();
    let op = op(&a);
    let signed = a.sign_envelope(&codec::to_envelope(&op).unwrap());

    // Elide every assertion of the wrapped op, one target set.
    let inner = signed.try_unwrap().unwrap();
    let targets: HashSet<_> = inner.assertions().iter().map(|x| x.digest()).collect();
    let stripped = signed.elide_removing_set(&targets);

    let decoded = codec::from_envelope(&stripped).unwrap();
    assert_eq!(decoded.elided, 4, "deps, nacks, target-fp, timestamp");
    assert!(decoded.op.deps.is_empty());
    assert!(decoded.op.nacks.is_empty());
    assert_eq!(decoded.op.target_fp, None);
    assert_eq!(decoded.op.timestamp, None);

    assert_eq!(stripped.digest(), signed.digest());
    sign::verify_envelope(&stripped, &a.actor())
        .expect("a fully stripped op still verifies");
}

// ---------------------------------------------------------------------------
// The negatives — without these the test above proves nothing
// ---------------------------------------------------------------------------

#[test]
fn tampering_with_a_non_elided_assertion_still_breaks_the_signature() {
    let a = author();
    let op = op(&a);
    let signed = a.sign_envelope(&codec::to_envelope(&op).unwrap());
    let redacted = signed.elide_removing_target(&timestamp_assertion(1_700_000_000));
    let signature = sign::signatures_of(&signed).unwrap().remove(0);

    // Same op, same author's signature, one changed `deps` value. Elision is
    // permitted; substitution is not, and the digest tree tells them apart.
    let tampered_op = op.clone().with_deps([[0x21u8; 32]]);
    let tampered = codec::to_envelope(&tampered_op)
        .unwrap()
        .wrap()
        .add_assertion(known_values::SIGNED, signature);

    assert_ne!(tampered.digest(), signed.digest());
    assert!(matches!(
        sign::verify_envelope(&tampered, &a.actor()),
        Err(LogError::BadSignature)
    ));

    // Control: the honest and the redacted forms both still verify, so the
    // failure above is about the tampering and not about the harness.
    sign::verify_envelope(&signed, &a.actor()).unwrap();
    sign::verify_envelope(&redacted, &a.actor()).unwrap();
}

#[test]
fn a_redacted_op_does_not_verify_against_the_wrong_actor() {
    let a = author();
    let stranger = Author::from_seed(&[9u8; 32]);
    let signed = a.sign_envelope(&codec::to_envelope(&op(&a)).unwrap());
    let redacted = signed.elide_removing_target(&timestamp_assertion(1_700_000_000));

    assert!(matches!(
        sign::verify_envelope(&redacted, &stranger.actor()),
        Err(LogError::BadSignature)
    ));
}

#[test]
fn eliding_the_signature_itself_leaves_nothing_to_verify() {
    let a = author();
    let signed = a.sign_envelope(&codec::to_envelope(&op(&a)).unwrap());
    let targets: HashSet<_> = signed.assertions().iter().map(|x| x.digest()).collect();
    let no_sig = signed.elide_removing_set(&targets);

    // The digest still matches — elision is elision — but a verifier must not
    // read "no signatures present" as "nothing failed".
    assert_eq!(no_sig.digest(), signed.digest());
    assert!(matches!(
        sign::verify_envelope(&no_sig, &a.actor()),
        Err(LogError::Unsigned)
    ));
}

// ---------------------------------------------------------------------------
// The rest of what the digest tree buys — salting and inclusion proofs
// ---------------------------------------------------------------------------

#[test]
fn salting_defeats_the_guess_the_elided_digest_attack() {
    let a = author();
    let op = op(&a);

    // Unsalted, an elided assertion is only as private as it is unguessable.
    // A `timestamp` has maybe a few million plausible values, so an attacker
    // reconstructs the assertion and compares digests — and wins.
    let plain = codec::to_envelope(&op).unwrap();
    let plain_redacted =
        plain.elide_removing_target(&timestamp_assertion(1_700_000_000));
    let guess = timestamp_assertion(1_700_000_000);
    assert_eq!(
        the_elided_assertion(&plain_redacted).digest(),
        guess.digest(),
        "unsalted, the elided digest IS the digest of the guess — the attack works"
    );

    // Salted, the same guess produces a different digest, and the attacker has
    // to find the salt too.
    let salted = codec::salt_assertions(&plain).unwrap();
    let salted_signed = a.sign_envelope(&salted);
    let salted_target = salted
        .assertions()
        .into_iter()
        .find(|x| {
            x.as_predicate()
                .and_then(|p| p.extract_subject::<String>().ok())
                .as_deref()
                == Some(codec::PRED_TIMESTAMP)
        })
        .expect("a salted timestamp assertion");
    assert_ne!(salted_target.digest(), guess.digest());

    // Two independently salted copies of the same op do not correlate.
    let salted2 = codec::salt_assertions(&codec::to_envelope(&op).unwrap()).unwrap();
    assert_ne!(salted.digest(), salted2.digest());

    // And salting costs none of the properties above: still elidable, still
    // verifiable, still decodable.
    let salted_redacted = salted_signed.elide_removing_target(&salted_target);
    assert_eq!(salted_redacted.digest(), salted_signed.digest());
    sign::verify_envelope(&salted_redacted, &a.actor()).unwrap();
    let decoded = codec::from_envelope(&salted_redacted).unwrap();
    assert_eq!(decoded.op.timestamp, None);
    assert_eq!(decoded.elided, 1);
    assert_ne!(the_elided_assertion(&salted_redacted).digest(), guess.digest());
    // The salted, unredacted form still reads back as the original op.
    assert_eq!(codec::from_envelope(&salted_signed).unwrap().op, op);
}

#[test]
fn an_inclusion_proof_reveals_one_assertion_and_nothing_else() {
    let a = author();
    let op = op(&a);
    let signed = a.sign_envelope(&codec::to_envelope(&op).unwrap());

    // What a verifier is assumed to hold: the root digest alone.
    let root = signed.elide_revealing_set(&HashSet::new());
    assert_eq!(root.digest(), signed.digest());

    // What the holder sends: a proof that this op depends on 0x20…, with
    // everything else — body, kind, actor, the other assertions — elided.
    let target = deps_assertion([0x20u8; 32]);
    let proof = signed
        .proof_contains_target(&target)
        .expect("the assertion is present, so a proof exists");
    assert!(root.confirm_contains_target(&target, &proof));
    assert!(!proof.format().contains("worldtree.kanban-card.move"));

    // A proof for one element does not confirm another, and a proof for an
    // assertion the op does not carry cannot be produced at all.
    assert!(!root.confirm_contains_target(&deps_assertion([0x21u8; 32]), &proof));
    assert!(signed.proof_contains_target(&deps_assertion([0x21u8; 32])).is_none());
}
