//! Password-encrypted identity wallet.
//!
//! File format (`IKEYW` v2): `magic(5) || version(1) || salt(32) || nonce(24)
//! || XChaCha20-Poly1305 ciphertext+tag`, key derived from the password with
//! Argon2id. The plaintext is a Gordian Envelope container holding named
//! identities plus an `active-identity` pointer, with unknown assertions
//! preserved verbatim for forward compatibility.
//!
//! The crate is generic over the identity type: implement [`WalletIdentity`]
//! to define how your identities encode to envelopes and which
//! [`WalletParams`] (envelope type string, keychain service, environment
//! variables, default path) your application uses. [`BasicIdentity`] is the
//! built-in identity type used by the `ikey` CLI: Ed25519 signing identity,
//! Blake3 fingerprint, optional ML-DSA-87 post-quantum keypair, and a
//! forward-compatible bag of app-specific assertions.

pub mod basic;
pub mod credential;
pub mod envelope;
pub mod format;
pub mod storage;

pub use basic::BasicIdentity;
pub use credential::{account_name_for_wallet, default_provider_for, CredentialProvider};
pub use envelope::WalletIdentity;
pub use format::{KeyPair, WalletData, WalletParams};
pub use storage::{write_secret_file, Wallet};

/// Wallet parameters for the generic `ikey` tool and IdentiKey applications.
pub const IDENTIKEY_PARAMS: WalletParams = WalletParams {
    wallet_type: "identikey.wallet",
    format_version: 2,
    keychain_service: "identikey",
    env_password: "IDENTIKEY_WALLET_PASSWORD",
    env_key: "IDENTIKEY_WALLET_KEY",
    env_no_keychain: "IDENTIKEY_NO_KEYCHAIN",
    v1_rejection_msg:
        "Wallet format v1 is no longer supported. Create a new wallet with `ikey identity new`.",
    dir_qualifier: "io",
    dir_organization: "identikey",
    dir_application: "identikey",
    wallet_file_name: "wallet.ikeyw",
};
