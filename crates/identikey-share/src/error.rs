//! Failures from wrapping, opening, granting, or a Recrypt adapter.

use dcbor::Error as CborError;

/// A share, wrap, or grant was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    /// The encapsulation public key is the identity, small-order, or not a point.
    #[error("encapsulation public key was rejected")]
    RejectedKey,
    /// The wrap bytes are not a successful keyspace v1 unwrap.
    #[error("wrap is not a successful unwrap")]
    Wrap,
    /// The payload AEAD failed or the share envelope is not v1.
    #[error("share payload could not be opened")]
    Payload,
    /// A share needs at least one direct wrap or one Recrypt capsule.
    #[error("share has no recipient")]
    EmptyRecipients,
    /// This secret does not match a wrap on the share.
    #[error("no wrap matches this secret")]
    NoMatchingWrap,
    /// Two recipients resolve to the same encapsulation key or capsule.
    #[error("duplicate recipient")]
    DuplicateRecipient,
    /// The grant's mode does not match the share's access set.
    #[error("grant mode does not match the share")]
    Mode,
    /// The grant body does not commit to this share.
    #[error("grant does not match this share")]
    GrantMismatch,
    /// A classical or post-quantum signature failed.
    #[error("grant signature is invalid")]
    Signature,
    /// The verifier asked for a post-quantum signature and the grant has none.
    #[error("post-quantum grant signature is required")]
    PqRequired,
    /// The Recrypt adapter rejected the capsule, or the capsule slot is malformed.
    #[error("recrypt capsule was rejected")]
    Recrypt,
    /// dCBOR could not represent the value.
    #[error("cbor: {0}")]
    Cbor(#[from] CborError),
}
