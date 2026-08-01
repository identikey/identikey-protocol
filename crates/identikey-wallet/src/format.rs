//! Encrypted wallet file format (`IKEYW` v2) and in-memory data types.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use bc_envelope::Envelope;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::envelope::{self, WalletIdentity};

pub(crate) const MAGIC: &[u8; 5] = b"IKEYW";
pub(crate) const VERSION: u8 = 2;

// Argon2 params (OWASP recommendations)
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallelism

/// Application-level wallet parameters.
///
/// Each [`WalletIdentity`] implementation names its params via
/// `WalletIdentity::PARAMS`, tying an identity type to its wallet envelope
/// type string, keychain service, environment variables, and default path.
/// The file *cipher* format (magic, Argon2id, XChaCha20-Poly1305) is shared
/// by all applications; only the container metadata varies.
#[derive(Debug)]
pub struct WalletParams {
    /// Envelope subject `type` for the wallet container (e.g. `identikey.wallet`).
    pub wallet_type: &'static str,
    /// Envelope subject `format-version` for the wallet container.
    pub format_version: u32,
    /// OS keychain service name for cached wallet keys.
    pub keychain_service: &'static str,
    /// Env var for non-interactive password input (scripting/CI).
    pub env_password: &'static str,
    /// Env var holding a base64 32-byte wallet key (CI mode).
    pub env_key: &'static str,
    /// Env var that forces the in-memory credential provider (no keychain).
    pub env_no_keychain: &'static str,
    /// Exact error string for rejected v1 wallets (spec'd per application).
    pub v1_rejection_msg: &'static str,
    /// `directories::ProjectDirs` qualifier (e.g. "io").
    pub dir_qualifier: &'static str,
    /// `directories::ProjectDirs` organization (e.g. "identikey").
    pub dir_organization: &'static str,
    /// `directories::ProjectDirs` application (e.g. "identikey").
    pub dir_application: &'static str,
    /// Wallet file name inside the data directory (e.g. "wallet.ikeyw").
    pub wallet_file_name: &'static str,
}

#[derive(Debug)]
pub struct WalletData<I> {
    pub identities: HashMap<String, I>,
    /// Active identity name — lives in the wallet, single source of truth.
    pub active_identity: Option<String>,
    /// Wallet-level assertions whose predicates are not known to the
    /// container codec. Preserved verbatim across decode/encode so additive
    /// spec extensions survive a load+save round-trip.
    pub unknown_assertions: Vec<(Envelope, Envelope)>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl<I> WalletData<I> {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            active_identity: None,
            unknown_assertions: Vec::new(),
        }
    }
}

impl<I> Default for WalletData<I> {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract salt from encrypted wallet header (for key derivation).
///
/// Also checks the magic and version bytes, returning the spec'd error
/// for v1 wallets so callers can avoid wasting an Argon2 derivation.
pub fn extract_salt(data: &[u8], params: &WalletParams) -> Result<[u8; 32]> {
    if data.len() < 5 + 1 + 32 {
        return Err(anyhow!("Wallet file too short for salt extraction"));
    }
    if &data[0..5] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[5];
    if version == 1 {
        return Err(anyhow!(params.v1_rejection_msg.to_string()));
    }
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {version}"));
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&data[6..38]);
    Ok(salt)
}

/// Derive encryption key from password and salt using Argon2id
pub fn derive_key(password: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e:?}"))?;
    Ok(key)
}

/// Decrypt wallet with pre-derived key (no password prompt needed)
pub fn decrypt_wallet_with_key<I: WalletIdentity>(
    data: &[u8],
    key: &[u8; 32],
    params: &WalletParams,
) -> Result<WalletData<I>> {
    if data.len() < 5 + 1 + 32 + 24 + 16 {
        return Err(anyhow!("Wallet file too short"));
    }
    if &data[0..5] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[5];
    if version == 1 {
        return Err(anyhow!(params.v1_rejection_msg.to_string()));
    }
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {version}"));
    }

    let nonce = &data[38..62];
    let ciphertext = &data[62..];

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let nonce_arr: [u8; 24] = nonce.try_into()?;
    let plaintext = zeroize::Zeroizing::new(
        cipher
            .decrypt(&nonce_arr.into(), ciphertext)
            .map_err(|_| anyhow!("Decryption failed (wrong key?)"))?,
    );

    envelope::from_envelope(&plaintext, params)
}

/// Encrypt wallet with pre-derived key and salt (no password prompt needed)
pub fn encrypt_wallet_with_key<I: WalletIdentity>(
    data: &WalletData<I>,
    key: &[u8; 32],
    salt: &[u8; 32],
    params: &WalletParams,
) -> Result<Vec<u8>> {
    let plaintext = zeroize::Zeroizing::new(envelope::to_envelope(data, params)?);

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(5 + 1 + 32 + 24 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic::tests::test_identity;
    use crate::BasicIdentity;
    use crate::IDENTIKEY_PARAMS;

    fn encrypt_wallet(data: &WalletData<BasicIdentity>, password: &str) -> Result<Vec<u8>> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive_key(password, &salt)?;
        encrypt_wallet_with_key(data, &key, &salt, &IDENTIKEY_PARAMS)
    }

    fn decrypt_wallet(data: &[u8], password: &str) -> Result<WalletData<BasicIdentity>> {
        let salt = extract_salt(data, &IDENTIKEY_PARAMS)?;
        let key = derive_key(password, &salt)?;
        decrypt_wallet_with_key(data, &key, &IDENTIKEY_PARAMS)
    }

    #[test]
    fn test_wallet_encryption_roundtrip() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("test".to_string(), test_identity(1));

        let password = "test-password-123";
        let encrypted = encrypt_wallet(&wallet, password).unwrap();
        let decrypted = decrypt_wallet(&encrypted, password).unwrap();

        assert_eq!(wallet.identities.len(), decrypted.identities.len());
    }

    #[test]
    fn test_wrong_password_fails() {
        let wallet: WalletData<BasicIdentity> = WalletData::new();
        let encrypted = encrypt_wallet(&wallet, "correct-password").unwrap();
        let result = decrypt_wallet(&encrypted, "wrong-password");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong key"));
    }

    #[test]
    fn test_invalid_magic_fails() {
        let wallet: WalletData<BasicIdentity> = WalletData::new();
        let mut encrypted = encrypt_wallet(&wallet, "password").unwrap();
        encrypted[0] = b'X'; // Corrupt magic bytes

        let result = decrypt_wallet(&encrypted, "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }

    #[test]
    fn test_extract_salt() {
        let wallet: WalletData<BasicIdentity> = WalletData::new();
        let encrypted = encrypt_wallet(&wallet, "password").unwrap();
        let salt = extract_salt(&encrypted, &IDENTIKEY_PARAMS).unwrap();
        assert_eq!(salt.len(), 32);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0x42u8; 32];
        let key1 = derive_key("password", &salt).unwrap();
        let key2 = derive_key("password", &salt).unwrap();
        assert_eq!(key1, key2);

        let key3 = derive_key("different", &salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("test".to_string(), test_identity(7));

        let key = [0xABu8; 32];
        let salt = [0xCDu8; 32];

        let encrypted = encrypt_wallet_with_key(&wallet, &key, &salt, &IDENTIKEY_PARAMS).unwrap();
        let decrypted: WalletData<BasicIdentity> =
            decrypt_wallet_with_key(&encrypted, &key, &IDENTIKEY_PARAMS).unwrap();

        assert_eq!(wallet.identities.len(), decrypted.identities.len());
        assert!(decrypted.identities.contains_key("test"));
    }

    #[test]
    fn test_v1_wallet_rejected_with_spec_string() {
        // Build a v1-byte wallet header (magic + version=1 + zeroed salt/nonce/16B tag).
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(1u8);
        data.extend_from_slice(&[0u8; 32]); // salt
        data.extend_from_slice(&[0u8; 24]); // nonce
        data.extend_from_slice(&[0u8; 16]); // ciphertext (any 16+ bytes)

        let result: Result<WalletData<BasicIdentity>> =
            decrypt_wallet_with_key(&data, &[0u8; 32], &IDENTIKEY_PARAMS);
        let msg = result.unwrap_err().to_string();
        assert_eq!(msg, IDENTIKEY_PARAMS.v1_rejection_msg);

        // Same check via the salt-extract pre-Argon2 fast path.
        let msg = extract_salt(&data, &IDENTIKEY_PARAMS)
            .unwrap_err()
            .to_string();
        assert_eq!(msg, IDENTIKEY_PARAMS.v1_rejection_msg);
    }

    #[test]
    fn test_unknown_version_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(99u8);
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&[0u8; 16]);

        let err: anyhow::Error =
            decrypt_wallet_with_key::<BasicIdentity>(&data, &[0u8; 32], &IDENTIKEY_PARAMS)
                .unwrap_err();
        assert_eq!(err.to_string(), "Unsupported wallet version: 99");

        let err = extract_salt(&data, &IDENTIKEY_PARAMS).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported wallet version: 99");
    }

    #[test]
    fn test_active_identity_preserved_through_aead() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("alice".to_string(), test_identity(10));
        wallet
            .identities
            .insert("bob".to_string(), test_identity(20));
        wallet.active_identity = Some("bob".to_string());

        let key = [0x33u8; 32];
        let salt = [0x44u8; 32];
        let encrypted = encrypt_wallet_with_key(&wallet, &key, &salt, &IDENTIKEY_PARAMS).unwrap();
        let decrypted: WalletData<BasicIdentity> =
            decrypt_wallet_with_key(&encrypted, &key, &IDENTIKEY_PARAMS).unwrap();

        assert_eq!(decrypted.active_identity, Some("bob".to_string()));
        assert_eq!(decrypted.identities.len(), 2);
    }

    #[test]
    fn test_tampered_ciphertext_fails_aead() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("alice".to_string(), test_identity(50));
        let key = [0x12u8; 32];
        let salt = [0x34u8; 32];
        let mut encrypted =
            encrypt_wallet_with_key(&wallet, &key, &salt, &IDENTIKEY_PARAMS).unwrap();
        // Flip a bit in the ciphertext (after header bytes 0..62).
        encrypted[80] ^= 0x01;
        let err = decrypt_wallet_with_key::<BasicIdentity>(&encrypted, &key, &IDENTIKEY_PARAMS)
            .unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));
    }
}
