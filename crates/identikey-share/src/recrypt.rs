//! Opaque proxy-re-encryption capsule of the same 32-byte DEK.
//!
//! This crate does not link a PRE backend. A caller that has Recrypt
//! implements [`RecryptKem`] and stores the backend ciphertext here.
//! Transforming a capsule does not decrypt the share payload.

use crate::error::ShareError;

/// PRE public key for one backend. `backend` is a name such as `lattice-bfv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecryptPublic {
    /// Caller-defined backend id. Empty is rejected.
    pub backend: String,
    /// Backend public key bytes.
    pub key: Vec<u8>,
}

impl RecryptPublic {
    /// Build a capsule recipient. Both fields must be non-empty.
    pub fn new(backend: impl Into<String>, key: Vec<u8>) -> Result<Self, ShareError> {
        let backend = backend.into();
        if backend.is_empty() || key.is_empty() {
            return Err(ShareError::Recrypt);
        }
        Ok(Self { backend, key })
    }
}

/// One PRE ciphertext of the share DEK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecryptCapsule {
    /// Same backend string the encapsulator was given.
    pub backend: String,
    /// Recipient public key this capsule is currently encrypted to.
    pub recipient: Vec<u8>,
    /// Opaque PRE ciphertext. This crate never inspects it.
    pub ciphertext: Vec<u8>,
}

/// Operations a PRE backend must supply. The DEK is the only plaintext.
pub trait RecryptKem {
    /// Encrypt `dek` to `recipient` under `backend`.
    fn encapsulate(
        &self,
        backend: &str,
        recipient: &[u8],
        dek: &[u8; 32],
    ) -> Result<Vec<u8>, ShareError>;

    /// Decrypt a capsule. `secret` is backend secret-key bytes.
    fn decapsulate(
        &self,
        backend: &str,
        secret: &[u8],
        capsule: &[u8],
    ) -> Result<[u8; 32], ShareError>;

    /// Transform `capsule` under `transform_key` without revealing `dek`.
    fn transform(
        &self,
        backend: &str,
        transform_key: &[u8],
        capsule: &[u8],
    ) -> Result<Vec<u8>, ShareError>;
}
