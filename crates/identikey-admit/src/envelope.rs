//! v1 admit envelope: version + attestation. Body is opaque to this crate.

use serde_json::Value;

use crate::attestation::Attestation;
use crate::error::AdmitError;

/// Envelope format version spoken by this crate.
pub const ENVELOPE_VERSION: u32 = 1;

/// Portable thaw envelope. Does not carry lifecycle policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u32,
    pub attestation: Attestation,
}

impl Envelope {
    pub fn new(attestation: Attestation) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            attestation,
        }
    }

    /// Parse a JSON envelope or an Elixir-shaped payload (`attestation` key).
    ///
    /// Missing `version` is implied `1`. Any other version is fail-closed.
    pub fn from_value(value: &Value) -> Result<Self, AdmitError> {
        let obj = value.as_object().ok_or(AdmitError::NotAnObject)?;
        let version = match obj.get("version") {
            None => ENVELOPE_VERSION,
            Some(Value::Number(n)) => {
                let ver = n.as_u64().ok_or(AdmitError::UnsupportedVersion(0))?;
                if ver != u64::from(ENVELOPE_VERSION) {
                    return Err(AdmitError::UnsupportedVersion(ver));
                }
                ENVELOPE_VERSION
            }
            Some(_) => return Err(AdmitError::UnsupportedVersion(0)),
        };
        let attestation = Attestation::from_payload(value)?;
        Ok(Self {
            version,
            attestation,
        })
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AdmitError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| AdmitError::NotAnObject)?;
        Self::from_value(&value)
    }

    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "version": self.version,
            "attestation": self.attestation.to_value(),
        })
    }

    /// Shape-check against `vm_id`.
    pub fn valid_for(&self, vm_id: &str) -> bool {
        self.version == ENVELOPE_VERSION && self.attestation.valid_for(vm_id)
    }
}
