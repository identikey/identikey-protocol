//! Fail-closed errors for the admit protocol.

use thiserror::Error;

/// Everything that can go wrong parsing or validating an admit envelope.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmitError {
    #[error("payload is not a JSON object")]
    NotAnObject,

    #[error("missing attestation")]
    MissingAttestation,

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("vm_id must be a non-empty string")]
    EmptyVmId,

    #[error("epoch must be a non-negative integer")]
    InvalidEpoch,

    #[error("unsupported envelope version: {0} (this implementation speaks 1)")]
    UnsupportedVersion(u64),

    #[error("unknown verdict: {0}")]
    UnknownVerdict(String),
}
