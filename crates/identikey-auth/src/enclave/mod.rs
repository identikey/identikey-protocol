//! Hardware-enclave [`Signer`](crate::signer::Signer) backends (§8 of the protocol spec).
//!
//! Each platform module provides a signer whose private key lives in a hardware element
//! and whose use is gated by a biometric. The protocol's `Signer` trait is the only
//! integration surface, so the wire format and verification are identical to the
//! software signer.
//!
//! macOS Secure Enclave and Linux TPM 2.0 compile with `--features enclave`.
//! Windows TPM (CNG) is part of every Windows build.

#[cfg(all(target_os = "linux", feature = "enclave"))]
pub mod linux;
#[cfg(all(target_os = "macos", feature = "enclave"))]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(all(target_os = "linux", feature = "enclave"))]
pub use linux::TpmSigner;
#[cfg(all(target_os = "macos", feature = "enclave"))]
pub use macos::{SecureEnclaveEd25519Signer, SecureEnclaveSigner};
#[cfg(target_os = "windows")]
pub use windows::TpmSigner;
