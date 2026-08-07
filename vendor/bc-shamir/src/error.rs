use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("secret is too long")]
    SecretTooLong,

    #[error("too many shares")]
    TooManyShares,

    #[error("interpolation failed")]
    InterpolationFailure,

    #[error("checksum failure")]
    ChecksumFailure,

    #[error("secret is too short")]
    SecretTooShort,

    #[error("secret is not of even length")]
    SecretNotEvenLen,

    #[error("invalid threshold")]
    InvalidThreshold,

    #[error("shares have unequal length")]
    SharesUnequalLength,
}

pub type Result<T> = std::result::Result<T, Error>;
