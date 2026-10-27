//! pq-state-chain v1: record codec and caller-held trust verifier.

use identikey_auth::state::ML_DSA_65_PK_LEN;
use identikey_auth::{
    observe, state_signing_payload, xid_for_control_key, AuthError, ClassicalPublicKey,
    OperationalKey, PqAlg, PqPublicKey, Signer, SoftwareSigner, StateRecord, StateSignatures,
    Trust,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// An ML-DSA-65 key (the Ed25519 half doubles as an Elect key where needed).
fn keypair() -> SoftwareSigner {
    SoftwareSigner::generate_ed25519().with_ml_dsa_65().unwrap()
}

fn pq_pub(s: &SoftwareSigner) -> PqPublicKey {
    s.pq_public_key().unwrap()
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn record(xid: [u8; 32], seq: u64, prev: Option<[u8; 32]>, control: &PqPublicKey) -> StateRecord {
    StateRecord { xid, seq, prev, control: control.clone(), operational: vec![] }
}

fn new_identity(s: &SoftwareSigner) -> StateRecord {
    let pk = pq_pub(s);
    record(xid_for_control_key(&pk), 1, None, &pk)
}

fn successor(of: &StateRecord, control: &PqPublicKey) -> StateRecord {
    record(of.xid, of.seq + 1, Some(of.digest()), control)
}

/// Signatures by each listed PQ key, plus an optional classical (Elect) signature.
fn sign(rec: &StateRecord, pq: &[&SoftwareSigner], elect: Option<&SoftwareSigner>) -> StateSignatures {
    let payload = rec.signing_payload();
    StateSignatures {
        pq: pq.iter().map(|s| s.sign_pq(&payload).unwrap().unwrap()).collect(),
        classical: elect.map(|e| e.sign_classical(&payload).unwrap()),
    }
}

fn accept(trust: &Trust, rec: &StateRecord, sigs: &StateSignatures, elect: Option<&ClassicalPublicKey>, sound: bool) -> Trust {
    observe(trust, &rec.to_bytes(), sigs, elect, sound).unwrap()
}

fn head_digest(t: &Trust) -> [u8; 32] {
    t.authority().unwrap().digest
}

/// Minimal canonical CBOR builder for hand-made (possibly invalid) records.
#[derive(Clone)]
enum C {
    U(u64),
    B(Vec<u8>),
    T(&'static str),
    A(Vec<C>),
    M(Vec<(&'static str, C)>),
    Raw(Vec<u8>),
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    match n {
        0..=23 => out.push(mt | n as u8),
        24..=0xff => out.extend([mt | 24, n as u8]),
        0x100..=0xffff => {
            out.push(mt | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(mt | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}

fn enc(c: &C) -> Vec<u8> {
    let mut out = Vec::new();
    match c {
        C::U(n) => head(0, *n, &mut out),
        C::B(b) => {
            head(2, b.len() as u64, &mut out);
            out.extend(b);
        }
        C::T(s) => {
            head(3, s.len() as u64, &mut out);
            out.extend(s.as_bytes());
        }
        C::A(items) => {
            head(4, items.len() as u64, &mut out);
            items.iter().for_each(|i| out.extend(enc(i)));
        }
        C::M(entries) => {
            let mut kv: Vec<(Vec<u8>, Vec<u8>)> =
                entries.iter().map(|(k, v)| (enc(&C::T(k)), enc(v))).collect();
            kv.sort();
            head(5, kv.len() as u64, &mut out);
            for (k, v) in kv {
                out.extend(k);
                out.extend(v);
            }
        }
        C::Raw(b) => out.extend(b),
    }
    out
}

fn control_map(alg: &'static str, key_len: usize, threshold: u64) -> C {
    C::M(vec![
        ("alg", C::T(alg)),
        ("key", C::B(vec![7; key_len])),
        ("threshold", C::U(threshold)),
    ])
}

/// The fields of a valid seq-1 record, for mutation.
fn base_fields() -> Vec<(&'static str, C)> {
    vec![
        ("v", C::U(1)),
        ("xid", C::B(vec![1; 32])),
        ("seq", C::U(1)),
        ("control", control_map("ml-dsa-65", ML_DSA_65_PK_LEN, 1)),
        ("operational", C::A(vec![])),
    ]
}

fn with(mut fields: Vec<(&'static str, C)>, key: &'static str, value: Option<C>) -> Vec<u8> {
    fields.retain(|(k, _)| *k != key);
    if let Some(v) = value {
        fields.push((key, v));
    }
    enc(&C::M(fields))
}

fn decode_err(bytes: &[u8]) -> AuthError {
    StateRecord::from_bytes(bytes).unwrap_err()
}

// ---------------------------------------------------------------------------
// encoding pins
// ---------------------------------------------------------------------------

#[test]
fn xid_is_sha256_of_this_crates_pq_key_cbor() {
    let pk = PqPublicKey { alg: PqAlg::MlDsa65, bytes: vec![7; ML_DSA_65_PK_LEN] };
    let cbor = pk.to_value().to_bytes();
    // {"alg": "ml-dsa-65", "key": bstr(1952)} in canonical key order.
    let mut expected = vec![0xa2, 0x63];
    expected.extend(b"alg");
    expected.push(0x69);
    expected.extend(b"ml-dsa-65");
    expected.push(0x63);
    expected.extend(b"key");
    expected.extend([0x59, 0x07, 0xa0]);
    expected.extend(vec![7; ML_DSA_65_PK_LEN]);
    assert_eq!(cbor, expected);
    assert_eq!(
        hex(&xid_for_control_key(&pk)),
        "7efd3def7df7d857cb1157d2bedf4b9743d77ad0ec56c1518f23295ac86206c2"
    );
}

#[test]
fn record_bytes_and_digest_are_pinned() {
    let pk = PqPublicKey { alg: PqAlg::MlDsa65, bytes: vec![7; ML_DSA_65_PK_LEN] };
    let rec = record([1; 32], 1, None, &pk);
    let bytes = rec.to_bytes();
    assert_eq!(bytes, enc(&C::M(base_fields())));
    assert_eq!(bytes.len(), 2053);
    assert_eq!(hex(&bytes[..12]), "a56176016373657101637869");
    assert_eq!(
        hex(&rec.digest()),
        "6e0b9a762072614490707568345e56a5f4fd923c0e77b17a876f24cc32ef5d47"
    );
    assert_eq!(StateRecord::from_bytes(&bytes).unwrap(), rec);
}

#[test]
fn signing_payload_is_domain_then_unsigned_bytes() {
    let pk = PqPublicKey { alg: PqAlg::MlDsa65, bytes: vec![7; ML_DSA_65_PK_LEN] };
    let rec = record([1; 32], 1, None, &pk);
    let unsigned = rec.to_bytes();
    let expected = enc(&C::A(vec![C::T("identikey-pq-state/v1"), C::B(unsigned.clone())]));
    assert_eq!(state_signing_payload(&unsigned), expected);
    assert_eq!(rec.signing_payload(), expected);
    // The digest covers the unsigned map only, not the payload.
    assert_eq!(hex(&rec.digest()), "6e0b9a762072614490707568345e56a5f4fd923c0e77b17a876f24cc32ef5d47");
}

#[test]
fn successor_roundtrips_with_prev_and_operational_keys() {
    let pk = PqPublicKey { alg: PqAlg::MlDsa65, bytes: vec![9; ML_DSA_65_PK_LEN] };
    let rec = StateRecord {
        xid: [3; 32],
        seq: 2,
        prev: Some([4; 32]),
        control: pk,
        operational: vec![
            OperationalKey {
                alg: "ed25519".into(),
                key: vec![5; 32],
                privileges: vec!["auth".into(), "sign".into()],
                not_before: Some(10),
                not_after: Some(20),
            },
            OperationalKey {
                alg: "p256".into(),
                key: vec![6; 33],
                privileges: vec![],
                not_before: None,
                not_after: None,
            },
        ],
    };
    let bytes = rec.to_bytes();
    let back = StateRecord::from_bytes(&bytes).unwrap();
    assert_eq!(back, rec);
    assert_eq!(back.to_bytes(), bytes);
}

// ---------------------------------------------------------------------------
// codec rejections
// ---------------------------------------------------------------------------

#[test]
fn rejects_other_versions_before_reading_v1_fields() {
    assert!(matches!(decode_err(&with(base_fields(), "v", Some(C::U(2)))), AuthError::Version(2)));
    assert!(matches!(decode_err(&with(base_fields(), "v", Some(C::U(0)))), AuthError::Version(0)));
    // A v2 record with keys v1 does not know is still a version error.
    let mut v2 = base_fields();
    v2.retain(|(k, _)| *k != "v");
    v2.push(("v", C::U(2)));
    v2.push(("future", C::U(1)));
    assert!(matches!(decode_err(&enc(&C::M(v2))), AuthError::Version(2)));
    assert!(StateRecord::from_bytes(&with(base_fields(), "v", None)).is_err());
    assert!(StateRecord::from_bytes(&with(base_fields(), "v", Some(C::T("1")))).is_err());
}

#[test]
fn rejects_unknown_keys_at_every_level() {
    assert!(StateRecord::from_bytes(&with(base_fields(), "extra", Some(C::U(0)))).is_err());
    let control = C::M(vec![
        ("alg", C::T("ml-dsa-65")),
        ("key", C::B(vec![7; ML_DSA_65_PK_LEN])),
        ("threshold", C::U(1)),
        ("keys", C::U(1)),
    ]);
    assert!(StateRecord::from_bytes(&with(base_fields(), "control", Some(control))).is_err());
    let op = C::M(vec![
        ("alg", C::T("ed25519")),
        ("key", C::B(vec![1; 32])),
        ("privileges", C::A(vec![])),
        ("authority", C::U(1)),
    ]);
    assert!(StateRecord::from_bytes(&with(base_fields(), "operational", Some(C::A(vec![op])))).is_err());
}

#[test]
fn rejects_non_canonical_encoding() {
    let good = enc(&C::M(base_fields()));
    assert!(StateRecord::from_bytes(&good).is_ok());

    // v = 1 in the non-minimal one-byte form.
    let mut fields = base_fields();
    fields[0] = ("v", C::Raw(vec![0x18, 0x01]));
    assert!(StateRecord::from_bytes(&enc(&C::M(fields))).is_err());

    // Keys out of canonical order: swap "seq" ahead of "v".
    let mut swapped = vec![0xa5];
    swapped.extend(enc(&C::T("seq")));
    swapped.push(0x01);
    swapped.extend(enc(&C::T("v")));
    swapped.push(0x01);
    swapped.extend(&good[1 + 2 + 1 + 4 + 1..]);
    assert_eq!(swapped.len(), good.len());
    assert!(StateRecord::from_bytes(&swapped).is_err());

    // Trailing bytes.
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(StateRecord::from_bytes(&trailing).is_err());
}

#[test]
fn prev_is_absent_on_the_first_record_and_present_after() {
    // null is not absent.
    assert!(StateRecord::from_bytes(&with(base_fields(), "prev", Some(C::Raw(vec![0xf6])))).is_err());
    assert!(StateRecord::from_bytes(&with(base_fields(), "prev", Some(C::B(vec![0; 32])))).is_err());
    let mut later = base_fields();
    later.retain(|(k, _)| *k != "seq");
    later.push(("seq", C::U(2)));
    assert!(StateRecord::from_bytes(&enc(&C::M(later.clone()))).is_err());
    assert!(StateRecord::from_bytes(&with(later.clone(), "prev", Some(C::B(vec![0; 32])))).is_ok());
    assert!(StateRecord::from_bytes(&with(later, "prev", Some(C::B(vec![0; 31])))).is_err());
    assert!(StateRecord::from_bytes(&with(base_fields(), "seq", Some(C::U(0)))).is_err());
    assert!(StateRecord::from_bytes(&with(base_fields(), "xid", Some(C::B(vec![1; 31])))).is_err());
}

#[test]
fn control_profile_is_exactly_one_ml_dsa_65_key_threshold_1() {
    for (alg, len, threshold) in [
        ("ml-dsa-44", ML_DSA_65_PK_LEN, 1),
        ("ml-dsa-87", ML_DSA_65_PK_LEN, 1),
        ("ed25519", ML_DSA_65_PK_LEN, 1),
        ("ml-dsa-65", ML_DSA_65_PK_LEN - 1, 1),
        ("ml-dsa-65", ML_DSA_65_PK_LEN + 1, 1),
        ("ml-dsa-65", ML_DSA_65_PK_LEN, 0),
        ("ml-dsa-65", ML_DSA_65_PK_LEN, 2),
    ] {
        let bytes = with(base_fields(), "control", Some(control_map(alg, len, threshold)));
        assert!(StateRecord::from_bytes(&bytes).is_err(), "{alg} {len} {threshold}");
    }
    // Two control keys.
    let two = C::A(vec![
        control_map("ml-dsa-65", ML_DSA_65_PK_LEN, 1),
        control_map("ml-dsa-65", ML_DSA_65_PK_LEN, 1),
    ]);
    assert!(StateRecord::from_bytes(&with(base_fields(), "control", Some(two))).is_err());
    // Missing threshold.
    let no_t = C::M(vec![("alg", C::T("ml-dsa-65")), ("key", C::B(vec![7; ML_DSA_65_PK_LEN]))]);
    assert!(StateRecord::from_bytes(&with(base_fields(), "control", Some(no_t))).is_err());
    // An encoder-side wrong alg is caught on decode.
    let pk = PqPublicKey { alg: PqAlg::MlDsa44, bytes: vec![7; ML_DSA_65_PK_LEN] };
    assert!(StateRecord::from_bytes(&record([1; 32], 1, None, &pk).to_bytes()).is_err());
}

#[test]
fn operational_entries_are_typed() {
    assert!(StateRecord::from_bytes(&with(base_fields(), "operational", None)).is_err());
    assert!(StateRecord::from_bytes(&with(base_fields(), "operational", Some(C::M(vec![])))).is_err());
    let op = |privs: C, nb: Option<C>| {
        let mut m = vec![("alg", C::T("ed25519")), ("key", C::B(vec![1; 32])), ("privileges", privs)];
        if let Some(nb) = nb {
            m.push(("not_before", nb));
        }
        C::M(m)
    };
    let ok = op(C::A(vec![C::T("auth")]), Some(C::U(5)));
    assert!(StateRecord::from_bytes(&with(base_fields(), "operational", Some(C::A(vec![ok])))).is_ok());
    let bad_priv = op(C::A(vec![C::U(1)]), None);
    assert!(StateRecord::from_bytes(&with(base_fields(), "operational", Some(C::A(vec![bad_priv])))).is_err());
    let bad_nb = op(C::A(vec![]), Some(C::T("soon")));
    assert!(StateRecord::from_bytes(&with(base_fields(), "operational", Some(C::A(vec![bad_nb])))).is_err());
}

// ---------------------------------------------------------------------------
// new identity
// ---------------------------------------------------------------------------

#[test]
fn new_identity_inception_key_is_the_control_key() {
    let k = keypair();
    let rec = new_identity(&k);
    // No classical signature, and classical soundness does not matter.
    for sound in [false, true] {
        let t = accept(&Trust::new(), &rec, &sign(&rec, &[&k], None), None, sound);
        let h = t.authority().unwrap();
        assert_eq!(h.digest, rec.digest());
        assert_eq!(h.control_key(), &pq_pub(&k));
        assert_eq!(h.xid(), &xid_for_control_key(&pq_pub(&k)));
        assert_eq!(h.seq(), 1);
        assert!(t.anchor().is_none());
        assert_eq!(t.resolve(&rec.digest()).unwrap().control_key(), &pq_pub(&k));
    }
}

#[test]
fn new_identity_needs_the_control_signature() {
    let k = keypair();
    let other = keypair();
    let rec = new_identity(&k);
    let bytes = rec.to_bytes();
    assert!(observe(&Trust::new(), &bytes, &StateSignatures::default(), None, true).is_err());
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[&other], None), None, true).is_err());
    // A classical signature is no substitute.
    let elect = k.classical_public_key();
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[], Some(&k)), Some(&elect), true).is_err());
}

#[test]
fn second_seq1_record_after_a_head_is_rejected_not_a_fork() {
    let k = keypair();
    let rec = new_identity(&k);
    let t = accept(&Trust::new(), &rec, &sign(&rec, &[&k], None), None, true);
    let mut alt = rec.clone();
    alt.operational.push(OperationalKey {
        alg: "ed25519".into(),
        key: vec![1; 32],
        privileges: vec![],
        not_before: None,
        not_after: None,
    });
    assert!(observe(&t, &alt.to_bytes(), &sign(&alt, &[&k], None), None, true).is_err());
    assert_eq!(head_digest(&t), rec.digest());
    assert!(!t.is_forked());
}

// ---------------------------------------------------------------------------
// migration
// ---------------------------------------------------------------------------

const CLASSICAL_XID: [u8; 32] = [0xc1; 32];

fn migration(control: &SoftwareSigner) -> StateRecord {
    record(CLASSICAL_XID, 1, None, &pq_pub(control))
}

#[test]
fn sound_classical_accepts_the_pair_as_anchor_and_head() {
    let elect = SoftwareSigner::generate_ed25519();
    let k = keypair();
    let rec = migration(&k);
    let t = accept(&Trust::new(), &rec, &sign(&rec, &[&k], Some(&elect)), Some(&elect.classical_public_key()), true);
    assert_eq!(t.anchor(), Some(&rec.digest()));
    assert_eq!(head_digest(&t), rec.digest());
    assert_eq!(t.authority().unwrap().xid(), &CLASSICAL_XID);
}

#[test]
fn unsound_classical_without_anchor_rejects() {
    let elect = SoftwareSigner::generate_ed25519();
    let k = keypair();
    let rec = migration(&k);
    let trust = Trust::new();
    let r = observe(&trust, &rec.to_bytes(), &sign(&rec, &[&k], Some(&elect)), Some(&elect.classical_public_key()), false);
    assert!(r.is_err());
    assert_eq!(trust, Trust::new());
}

#[test]
fn unsound_classical_accepts_the_stored_anchor_and_sets_an_empty_head() {
    let elect = SoftwareSigner::generate_ed25519();
    let k = keypair();
    let rec = migration(&k);
    let sigs = sign(&rec, &[&k], Some(&elect));
    let ek = elect.classical_public_key();
    let t = accept(&Trust::with_anchor(rec.digest()), &rec, &sigs, Some(&ek), false);
    assert_eq!(head_digest(&t), rec.digest());
    assert_eq!(t.anchor(), Some(&rec.digest()));

    // A different first record is not the anchor, sound or not.
    let k2 = keypair();
    let other = migration(&k2);
    for sound in [false, true] {
        let r = observe(&Trust::with_anchor(rec.digest()), &other.to_bytes(), &sign(&other, &[&k2], Some(&elect)), Some(&ek), sound);
        assert!(r.is_err());
    }
}

#[test]
fn migration_needs_both_signatures() {
    let elect = SoftwareSigner::generate_ed25519();
    let k = keypair();
    let rec = migration(&k);
    let bytes = rec.to_bytes();
    let ek = elect.classical_public_key();
    // Classical alone never creates a head.
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[], Some(&elect)), Some(&ek), true).is_err());
    // Control alone is not a migration.
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[&k], None), Some(&ek), true).is_err());
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[&k], Some(&elect)), None, true).is_err());
    // Elect signature by a different key.
    let wrong = SoftwareSigner::generate_ed25519();
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[&k], Some(&wrong)), Some(&ek), true).is_err());
    // Control signature by a different key.
    let k2 = keypair();
    assert!(observe(&Trust::new(), &bytes, &sign(&rec, &[&k2], Some(&elect)), Some(&ek), true).is_err());
    // A signature over a different payload (the raw unsigned bytes) does not count.
    let raw = StateSignatures {
        pq: vec![k.sign_pq(&bytes).unwrap().unwrap()],
        classical: Some(elect.sign_classical(&bytes).unwrap()),
    };
    assert!(observe(&Trust::new(), &bytes, &raw, Some(&ek), true).is_err());
}

/// Anchor, then a rotation so the head is past the anchor.
fn migrated_and_rotated() -> (SoftwareSigner, SoftwareSigner, StateRecord, StateRecord, Trust) {
    let elect = SoftwareSigner::generate_ed25519();
    let k = keypair();
    let anchor = migration(&k);
    let t = accept(&Trust::new(), &anchor, &sign(&anchor, &[&k], Some(&elect)), Some(&elect.classical_public_key()), true);
    let next = successor(&anchor, &pq_pub(&k));
    let t = accept(&t, &next, &sign(&next, &[&k], None), None, true);
    (elect, k, anchor, next, t)
}

#[test]
fn a_second_genesis_does_not_replace_the_head() {
    let (elect, _k, anchor, next, t) = migrated_and_rotated();
    let k2 = keypair();
    let other = migration(&k2);
    let r = observe(&t, &other.to_bytes(), &sign(&other, &[&k2], Some(&elect)), Some(&elect.classical_public_key()), true);
    assert!(r.is_err());
    assert_eq!(head_digest(&t), next.digest());
    assert_eq!(t.anchor(), Some(&anchor.digest()));
    assert!(!t.is_forked());
}

#[test]
fn replaying_the_anchor_does_not_rewind_the_head() {
    let (elect, k, anchor, next, t) = migrated_and_rotated();
    for sound in [false, true] {
        let t2 = accept(&t, &anchor, &sign(&anchor, &[&k], Some(&elect)), Some(&elect.classical_public_key()), sound);
        assert_eq!(head_digest(&t2), next.digest());
        assert_eq!(t2.anchor(), Some(&anchor.digest()));
        // The anchor no longer resolves as authority; only the head does.
        assert!(t2.resolve(&anchor.digest()).is_none());
        assert!(t2.resolve(&next.digest()).is_some());
    }
}

// ---------------------------------------------------------------------------
// rotation
// ---------------------------------------------------------------------------

fn genesis() -> (SoftwareSigner, StateRecord, Trust) {
    let k = keypair();
    let rec = new_identity(&k);
    let t = accept(&Trust::new(), &rec, &sign(&rec, &[&k], None), None, true);
    (k, rec, t)
}

#[test]
fn previous_control_key_rotates_to_a_new_key() {
    let (k1, g, t) = genesis();
    let k2 = keypair();
    let next = successor(&g, &pq_pub(&k2));
    let t = accept(&t, &next, &sign(&next, &[&k1, &k2], None), None, false);
    let h = t.authority().unwrap();
    assert_eq!(h.digest, next.digest());
    assert_eq!(h.control_key(), &pq_pub(&k2));
    assert_eq!(h.seq(), 2);
    assert_eq!(h.xid(), &g.xid);

    // Signature order does not matter.
    let k3 = keypair();
    let third = successor(&next, &pq_pub(&k3));
    let t = accept(&t, &third, &sign(&third, &[&k3, &k2], None), None, false);
    assert_eq!(head_digest(&t), third.digest());
}

#[test]
fn rotation_keeps_the_anchor() {
    let (_elect, k, anchor, next, t) = migrated_and_rotated();
    let k2 = keypair();
    let third = successor(&next, &pq_pub(&k2));
    let t = accept(&t, &third, &sign(&third, &[&k, &k2], None), None, false);
    assert_eq!(t.anchor(), Some(&anchor.digest()));
    assert_eq!(head_digest(&t), third.digest());
}

#[test]
fn successor_cannot_declare_its_own_authority() {
    let (k1, g, t) = genesis();
    let k2 = keypair();
    let next = successor(&g, &pq_pub(&k2));
    let bytes = next.to_bytes();
    // Only the new key.
    assert!(observe(&t, &bytes, &sign(&next, &[&k2], None), None, true).is_err());
    // Only the previous key, but the control key changed.
    assert!(observe(&t, &bytes, &sign(&next, &[&k1], None), None, true).is_err());
    assert_eq!(head_digest(&t), g.digest());
}

#[test]
fn rotation_checks_prev_seq_and_xid() {
    let (k1, g, t) = genesis();
    let pk = pq_pub(&k1);
    let cases = [
        record(g.xid, 2, Some([0; 32]), &pk),
        record(g.xid, 3, Some(g.digest()), &pk),
        record([9; 32], 2, Some(g.digest()), &pk),
    ];
    for rec in cases {
        assert!(observe(&t, &rec.to_bytes(), &sign(&rec, &[&k1], None), None, true).is_err());
    }
    // Without a head, a later record has nothing to extend.
    let next = successor(&g, &pk);
    assert!(observe(&Trust::new(), &next.to_bytes(), &sign(&next, &[&k1], None), None, true).is_err());
    assert_eq!(head_digest(&t), g.digest());
}

#[test]
fn a_classical_signature_does_not_move_the_head() {
    let (elect, k, _anchor, next, t) = migrated_and_rotated();
    let ek = elect.classical_public_key();
    // Elect signs a replacement control key.
    let k2 = keypair();
    let replace = successor(&next, &pq_pub(&k2));
    assert!(observe(&t, &replace.to_bytes(), &sign(&replace, &[], Some(&elect)), Some(&ek), true).is_err());
    // Even with the new key's signature, Elect is not the previous control key.
    assert!(observe(&t, &replace.to_bytes(), &sign(&replace, &[&k2], Some(&elect)), Some(&ek), true).is_err());
    // A classical-only update that keeps the control key.
    let same = successor(&next, &pq_pub(&k));
    assert!(observe(&t, &same.to_bytes(), &sign(&same, &[], Some(&elect)), Some(&ek), true).is_err());
    assert_eq!(head_digest(&t), next.digest());
}

// ---------------------------------------------------------------------------
// duplicity
// ---------------------------------------------------------------------------

/// Two different valid successors of the same genesis head.
fn siblings() -> (SoftwareSigner, StateRecord, (StateRecord, StateSignatures), (StateRecord, StateSignatures), Trust) {
    let (k1, g, t) = genesis();
    let ka = keypair();
    let a = successor(&g, &pq_pub(&ka));
    let sa = sign(&a, &[&k1, &ka], None);
    let b = successor(&g, &pq_pub(&k1));
    let sb = sign(&b, &[&k1], None);
    assert_ne!(a.digest(), b.digest());
    (k1, g, (a, sa), (b, sb), t)
}

#[test]
fn either_order_is_duplicity() {
    let (_k1, _g, (a, sa), (b, sb), t) = siblings();
    for (first, s1, second, s2) in [(&a, &sa, &b, &sb), (&b, &sb, &a, &sa)] {
        let t1 = accept(&t, first, s1, None, true);
        assert_eq!(head_digest(&t1), first.digest());
        let t2 = accept(&t1, second, s2, None, true);
        assert!(t2.is_forked());
        assert!(t2.authority().is_none());
        assert!(t2.resolve(&first.digest()).is_none());
        assert!(t2.resolve(&second.digest()).is_none());
    }
}

#[test]
fn records_after_a_fork_do_not_restore_authority() {
    let (k1, _g, (a, sa), (b, sb), t) = siblings();
    let forked = accept(&accept(&t, &b, &sb, None, true), &a, &sa, None, true);
    assert!(forked.is_forked());
    // A valid successor of the first-accepted head.
    let next = successor(&b, &pq_pub(&k1));
    assert!(observe(&forked, &next.to_bytes(), &sign(&next, &[&k1], None), None, true).is_err());
    // A repeat of the earlier head.
    assert!(observe(&forked, &b.to_bytes(), &sb, None, true).is_err());
    assert!(forked.authority().is_none());
    assert!(forked.resolve(&b.digest()).is_none());
}

#[test]
fn a_repeat_is_not_a_fork() {
    let (_k1, _g, (a, sa), _, t) = siblings();
    let t1 = accept(&t, &a, &sa, None, true);
    let t2 = accept(&t1, &a, &sa, None, true);
    assert!(!t2.is_forked());
    assert_eq!(t2, t1);
    assert_eq!(t2.resolve(&a.digest()).unwrap().control_key(), &a.control);
}

#[test]
fn a_bad_signature_is_not_a_second_branch() {
    let (k1, _g, (a, sa), (b, _sb), t) = siblings();
    let t1 = accept(&t, &a, &sa, None, true);
    // Sibling signed by a key that is not the parent control key.
    let stranger = keypair();
    let r = observe(&t1, &b.to_bytes(), &sign(&b, &[&stranger], None), None, true);
    assert!(r.is_err());
    // Sibling with a tampered parent signature.
    let mut bad = sign(&b, &[&k1], None);
    bad.pq[0].bytes[0] ^= 0xff;
    assert!(observe(&t1, &b.to_bytes(), &bad, None, true).is_err());
    assert_eq!(head_digest(&t1), a.digest());
    assert!(!t1.is_forked());
}

#[test]
fn a_sibling_that_changes_xid_is_not_a_branch() {
    let (k1, g, (a, sa), _, t) = siblings();
    let t1 = accept(&t, &a, &sa, None, true);
    let odd = record([9; 32], 2, Some(g.digest()), &pq_pub(&k1));
    assert!(observe(&t1, &odd.to_bytes(), &sign(&odd, &[&k1], None), None, true).is_err());
    assert!(!t1.is_forked());
}
