//! A secret sealed in the wallet survives the IKEYW shell and is not plaintext on disk.

use identikey_wallet::format::{
    WalletData, decrypt_wallet_with_key, derive_key, encrypt_wallet_with_key_nonce,
};
use identikey_wallet::{BasicIdentity, IDENTIKEY_PARAMS, SecretStore};

const PASSWORD: &str = "vector-password";
const SALT: [u8; 32] = [0x11; 32];
const NONCE: [u8; 24] = [0x22; 24];

#[test]
fn secret_roundtrips_inside_the_wallet_shell() {
    let mut wallet = WalletData::<BasicIdentity>::new();
    let id = wallet
        .secrets
        .insert("github", b"ghp_disk_secret_value", 50)
        .unwrap();
    let key = derive_key(PASSWORD, &SALT).unwrap();
    let bytes =
        encrypt_wallet_with_key_nonce(&wallet, &key, &SALT, &NONCE, &IDENTIKEY_PARAMS).unwrap();
    assert!(
        !bytes
            .windows(b"ghp_disk_secret_value".len())
            .any(|w| w == b"ghp_disk_secret_value"),
        "secret bytes were written outside the wallet ciphertext"
    );
    let opened = decrypt_wallet_with_key::<BasicIdentity>(&bytes, &key, &IDENTIKEY_PARAMS).unwrap();
    assert_eq!(
        opened.secrets.get(&id).unwrap().value(),
        b"ghp_disk_secret_value"
    );
    assert_eq!(opened.secrets.list()[0].label, "github");
}
