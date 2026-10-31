//! Public behavior: multi-recipient open, rewrap, grant, and a PRE stand-in.

use identikey_share::{
    AccessMode, GrantKeys, PqAlg, PqPolicy, RecryptKem, RecryptPublic, Share, ShareError,
    WrapSecret, grant_access, rewrap_key, verify_grant,
};

struct XorKem;

fn mask(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

impl RecryptKem for XorKem {
    fn encapsulate(
        &self,
        backend: &str,
        recipient: &[u8],
        dek: &[u8; 32],
    ) -> Result<Vec<u8>, ShareError> {
        if backend != "xor" {
            return Err(ShareError::Recrypt);
        }
        let m = mask(recipient);
        Ok(dek.iter().zip(m).map(|(a, b)| a ^ b).collect())
    }

    fn decapsulate(
        &self,
        backend: &str,
        secret: &[u8],
        capsule: &[u8],
    ) -> Result<[u8; 32], ShareError> {
        if backend != "xor" || capsule.len() != 32 {
            return Err(ShareError::Recrypt);
        }
        let m = mask(secret);
        let mut dek = [0u8; 32];
        for (i, byte) in capsule.iter().enumerate() {
            dek[i] = byte ^ m[i];
        }
        Ok(dek)
    }

    fn transform(
        &self,
        backend: &str,
        transform_key: &[u8],
        capsule: &[u8],
    ) -> Result<Vec<u8>, ShareError> {
        if backend != "xor" || transform_key.len() < 2 || capsule.len() != 32 {
            return Err(ShareError::Recrypt);
        }
        let split = transform_key.len() / 2;
        let from = mask(&transform_key[..split]);
        let to = mask(&transform_key[split..]);
        Ok(capsule
            .iter()
            .zip(from)
            .zip(to)
            .map(|((c, f), t)| c ^ f ^ t)
            .collect())
    }
}

#[test]
fn two_holders_open_and_a_third_is_added_without_rewriting_payload() {
    let alice = WrapSecret::generate_ed25519();
    let bob = WrapSecret::generate_x25519();
    let carol = WrapSecret::generate_p256().unwrap();
    let share = Share::seal(
        b"minutes",
        &[alice.public().unwrap(), bob.public().unwrap()],
        0,
    )
    .unwrap();
    let bytes = share.to_cbor().unwrap();
    let parsed = Share::from_cbor(&bytes).unwrap();
    assert_eq!(&parsed.open(&alice).unwrap()[..], b"minutes");
    assert_eq!(&parsed.open(&bob).unwrap()[..], b"minutes");
    assert!(parsed.open(&carol).is_err());

    let shared = parsed
        .add_recipient(&alice, carol.public().unwrap())
        .unwrap();
    assert_ne!(shared.to_cbor().unwrap(), bytes);
    assert_eq!(shared.content_id(), parsed.content_id());
    assert_eq!(&shared.open(&carol).unwrap()[..], b"minutes");
    assert_eq!(&shared.open(&bob).unwrap()[..], b"minutes");

    let rotated = shared.rotate(&bob, &[bob.public().unwrap()], 1).unwrap();
    assert_eq!(rotated.content_id(), shared.content_id());
    assert_eq!(rotated.epoch(), 1);
    assert!(rotated.open(&alice).is_err());
    assert_eq!(&rotated.open(&bob).unwrap()[..], b"minutes");
}

#[test]
fn single_wrap_rewrap_is_the_ceremony_shape() {
    let alice = WrapSecret::generate_x25519();
    let bob = WrapSecret::generate_x25519();
    let dek = [5u8; 32];
    let wrapped = identikey_share::wrap_key(&alice.public().unwrap(), &dek, 0).unwrap();
    let for_bob = rewrap_key(&alice, &wrapped, &bob.public().unwrap(), 3).unwrap();
    assert_eq!(
        identikey_share::unwrap_key(&bob, &for_bob)
            .unwrap()
            .as_slice(),
        &dek
    );
    assert!(!for_bob.windows(32).any(|window| window == dek));
}

#[test]
fn classical_grant_is_optional_pq_and_breaks_when_a_recipient_is_added() {
    let alice = WrapSecret::generate_x25519();
    let share = Share::seal(b"note", &[alice.public().unwrap()], 0).unwrap();
    let keys = GrantKeys::from_ed25519_seed([9u8; 32]);
    let grant = grant_access(&share, &keys, AccessMode::Direct).unwrap();
    verify_grant(&grant, &share, PqPolicy::Optional).unwrap();
    assert!(matches!(
        verify_grant(&grant, &share, PqPolicy::Required),
        Err(ShareError::PqRequired)
    ));
    let bob = WrapSecret::generate_x25519();
    let wider = share.add_recipient(&alice, bob.public().unwrap()).unwrap();
    assert!(matches!(
        verify_grant(&grant, &wider, PqPolicy::Optional),
        Err(ShareError::GrantMismatch)
    ));
}

#[test]
fn ml_dsa_87_grant_verifies_and_a_bad_signature_does_not() {
    let alice = WrapSecret::generate_x25519();
    let share = Share::seal(b"long-lived", &[alice.public().unwrap()], 2).unwrap();
    let keys = GrantKeys::from_ed25519_seed([4u8; 32])
        .with_pq(PqAlg::MlDsa87)
        .unwrap();
    let grant = grant_access(&share, &keys, AccessMode::Direct).unwrap();
    let bytes = grant.to_cbor().unwrap();
    let parsed = identikey_share::AccessGrant::from_cbor(&bytes).unwrap();
    verify_grant(&parsed, &share, PqPolicy::Required).unwrap();
    verify_grant(&parsed, &share, PqPolicy::Optional).unwrap();

    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        identikey_share::AccessGrant::from_cbor(&tampered).is_err() || {
            identikey_share::AccessGrant::from_cbor(&tampered)
                .and_then(|g| verify_grant(&g, &share, PqPolicy::Required).map(|_| g))
                .is_err()
        }
    );
}

#[test]
fn recrypt_capsule_transforms_without_a_direct_wrap() {
    let kem = XorKem;
    let alice = [0x11u8; 16];
    let bob = [0x22u8; 16];
    let share = Share::seal_mixed(
        b"foreign",
        &[],
        &[RecryptPublic::new("xor", alice.to_vec()).unwrap()],
        &kem,
        0,
    )
    .unwrap();
    assert_eq!(
        &share.open_recrypt("xor", &alice, &alice, &kem).unwrap()[..],
        b"foreign"
    );
    let mut rk = alice.to_vec();
    rk.extend_from_slice(&bob);
    let moved = share
        .transform_recrypt(
            "xor",
            &alice,
            &RecryptPublic::new("xor", bob.to_vec()).unwrap(),
            &rk,
            &kem,
        )
        .unwrap();
    assert_eq!(moved.content_id(), share.content_id());
    assert!(moved.open_recrypt("xor", &alice, &alice, &kem).is_err());
    assert_eq!(
        &moved.open_recrypt("xor", &bob, &bob, &kem).unwrap()[..],
        b"foreign"
    );

    let keys = GrantKeys::from_ed25519_seed([8u8; 32]);
    let grant = grant_access(&moved, &keys, AccessMode::Recrypt).unwrap();
    verify_grant(&grant, &moved, PqPolicy::Optional).unwrap();
    assert!(grant_access(&moved, &keys, AccessMode::Direct).is_err());
}
