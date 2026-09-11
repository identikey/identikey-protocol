//! Portable VM-thaw admission protocol.
//!
//! Wire + validators only. Lifecycle policy (run state, `restart_policy`,
//! restore, actor-to-VM map) belongs to the embedder (Mjolnir, a gateway
//! plugin, a CDN origin adapter). This crate **must not** depend on
//! `identikey-core`.
//!
//! v1 is a **shape check**, fail-closed: a thaw envelope carries an
//! [`Attestation`] with matching `vm_id` and a non-negative integer `epoch`.
//! Lifecycle epoch is a boot/restore/owner-start counter — not a host
//! persist generation.
//!
//! Verdict vocabulary: [`Verdict`] — `deny` / `drop` / `reply-here` / `deliver`.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod attestation;
mod envelope;
mod error;
mod verdict;

pub use attestation::Attestation;
pub use envelope::{ENVELOPE_VERSION, Envelope};
pub use error::AdmitError;
pub use verdict::Verdict;

use serde_json::Value;

/// True when `payload` may thaw `vm_id` under the v1 shape check.
///
/// Missing, non-object, or mismatched attestation is deny (`false`).
/// Matches `Mjolnir.Admit.thaw_allowed?/2`.
pub fn thaw_allowed(vm_id: &str, payload: &Value) -> bool {
    match Attestation::from_payload(payload) {
        Ok(att) => att.valid_for(vm_id),
        Err(_) => false,
    }
}

/// Parse an attestation out of a payload map (`{"attestation": {...}}`).
pub fn attestation(payload: &Value) -> Result<Attestation, AdmitError> {
    Attestation::from_payload(payload)
}
