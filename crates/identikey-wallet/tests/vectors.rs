//! IKEYW v2 fixtures: tests verify AGAINST committed bytes, not merely roundtrip.

use identikey_wallet::basic::BasicIdentity;
use identikey_wallet::format::{
    decrypt_wallet_with_key, derive_key, extract_salt, encrypt_wallet_with_key_nonce, WalletData,
};
use identikey_wallet::IDENTIKEY_PARAMS;

const PASSWORD: &str = "vector-password";
const SALT: [u8; 32] = [0x11; 32];
const NONCE: [u8; 24] = [0x22; 24];

fn vector_wallet() -> WalletData<BasicIdentity> {
    let mut w = WalletData::new();
    w.active_identity = Some("alice".to_string());
    w.identities.insert(
        "alice".to_string(),
        BasicIdentity::new(1_704_067_200, vec![0x11; 32], vec![0x12; 32]),
    );
    w.unknown_assertions.push((
        bc_envelope::Envelope::new("delegated-capability"),
        bc_envelope::Envelope::new("future-token"),
    ));
    w
}

#[test]
fn ikeyw_v2_fixture_decrypts() {
    let bytes = include_bytes!("fixtures/ikeyw-v2.bin");
    assert_eq!(&bytes[0..5], b"IKEYW");
    assert_eq!(bytes[5], 2);
    let salt = extract_salt(bytes, &IDENTIKEY_PARAMS).unwrap();
    assert_eq!(salt, SALT);
    let key = derive_key(PASSWORD, &salt).unwrap();
    let data = decrypt_wallet_with_key::<BasicIdentity>(bytes, &key, &IDENTIKEY_PARAMS).unwrap();
    assert_eq!(data.active_identity.as_deref(), Some("alice"));
    assert!(data.identities.contains_key("alice"));
    assert_eq!(data.unknown_assertions.len(), 1);
}

#[test]
fn ikeyw_v2_fixture_matches_encoder() {
    let key = derive_key(PASSWORD, &SALT).unwrap();
    let got = encrypt_wallet_with_key_nonce(
        &vector_wallet(),
        &key,
        &SALT,
        &NONCE,
        &IDENTIKEY_PARAMS,
    )
    .unwrap();
    let want = include_bytes!("fixtures/ikeyw-v2.bin");
    assert_eq!(got, want, "IKEYW fixture drifted");
}

#[test]
fn ikeyw_v1_header_rejected() {
    let mut v1 = vec![b'I', b'K', b'E', b'Y', b'W', 1];
    v1.extend_from_slice(&[0u8; 32]);
    v1.extend_from_slice(&[0u8; 24]);
    v1.extend_from_slice(&[0u8; 16]);
    let err = extract_salt(&v1, &IDENTIKEY_PARAMS).unwrap_err();
    assert!(err.to_string().contains("v1"));
}

#[test]
fn unknown_assertion_survives_load_save() {
    let key = derive_key(PASSWORD, &SALT).unwrap();
    let bytes = include_bytes!("fixtures/ikeyw-v2.bin");
    let data = decrypt_wallet_with_key::<BasicIdentity>(bytes, &key, &IDENTIKEY_PARAMS).unwrap();
    let again = encrypt_wallet_with_key_nonce(&data, &key, &SALT, &NONCE, &IDENTIKEY_PARAMS).unwrap();
    let data2 = decrypt_wallet_with_key::<BasicIdentity>(&again, &key, &IDENTIKEY_PARAMS).unwrap();
    assert_eq!(data2.unknown_assertions.len(), 1);
}

#[test]
#[ignore]
fn write_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let key = derive_key(PASSWORD, &SALT).unwrap();
    let bytes = encrypt_wallet_with_key_nonce(
        &vector_wallet(),
        &key,
        &SALT,
        &NONCE,
        &IDENTIKEY_PARAMS,
    )
    .unwrap();
    std::fs::write(dir.join("ikeyw-v2.bin"), bytes).unwrap();
}
