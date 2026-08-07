//! Error type for the IdentiKey op log.

/// Everything that can go wrong authoring, encoding, decoding or verifying an op.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("cbor: {0}")]
    Cbor(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("unexpected field value: {0}")]
    InvalidValue(&'static str),

    #[error("unsupported format-version: {0} (this implementation speaks 4)")]
    UnsupportedFormatVersion(u64),

    #[error("wrong envelope type: expected `ball.action`, got `{0}`")]
    WrongType(String),

    #[error("expected CBOR tag {expected}, got {got}")]
    WrongTag { expected: u64, got: u64 },

    #[error("`kind` must be a non-empty UTF-8 string")]
    EmptyKind,

    #[error("expected {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },

    #[error("body is not canonical (deterministic) CBOR")]
    NonCanonicalBody,

    #[error("unknown signature algorithm: {0}")]
    UnknownAlg(String),

    #[error("invalid {0} key bytes")]
    InvalidKey(&'static str),

    #[error("invalid {0} signature bytes")]
    InvalidSig(&'static str),

    #[error("signature verification failed")]
    BadSignature,

    #[error("op carries no signatures — treat as untrusted input")]
    Unsigned,

    #[error("post-quantum verification requested but the `ml-dsa` feature is not enabled")]
    PqUnavailable,

    #[error("post-quantum signature present with no public key to check it against")]
    PqDangling,
}

pub type Result<T> = core::result::Result<T, LogError>;

impl From<dcbor::Error> for LogError {
    fn from(e: dcbor::Error) -> Self { LogError::Cbor(e.to_string()) }
}
