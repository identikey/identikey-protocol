//! `Authorization: Bearer biscuit:<base64>` (identikey-capability-v1 §4).

use crate::error::CapabilityError;
use base64::Engine;

const PREFIX: &str = "biscuit:";

/// Encode token bytes as the Bearer credential (`biscuit:<standard-base64>`).
pub fn encode_bearer(token: &[u8]) -> String {
    format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(token)
    )
}

/// Parse `Authorization` (with or without the `Bearer ` scheme) into token bytes.
pub fn decode_bearer(header: &str) -> Result<Vec<u8>, CapabilityError> {
    let s = header.trim();
    let s = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
        .unwrap_or(s)
        .trim();
    let b64 = s.strip_prefix(PREFIX).ok_or(CapabilityError::Bearer)?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| CapabilityError::Bearer)
}
