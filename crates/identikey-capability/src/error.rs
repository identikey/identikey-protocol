//! Fail-closed errors for capability tokens.

use thiserror::Error;

/// Everything that can go wrong minting, parsing, or verifying a token.
#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("biscuit: {0}")]
    Biscuit(String),

    #[error("key: {0}")]
    Key(String),

    #[error("ed25519 public key must be 32 bytes")]
    PublicLen,

    #[error("token asserts a holder fact; holder must be a check, injected by the verifier")]
    HolderFact,

    #[error("authorization header is not Bearer biscuit:<base64>")]
    Bearer,
}
