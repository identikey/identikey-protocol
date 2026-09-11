//! Attestation shape: `vm_id` + non-negative integer `epoch`.

use serde_json::Value;

use crate::error::AdmitError;

/// Signed (later) binding of a request to a VM and its lifecycle epoch.
///
/// v1 is the shape only. Cryptographic verification is a later embedder
/// concern; this crate checks types and matching `vm_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub vm_id: String,
    pub epoch: u64,
}

impl Attestation {
    /// Construct after validating a non-empty `vm_id`. `epoch` is already
    /// non-negative (`u64`).
    pub fn new(vm_id: impl Into<String>, epoch: u64) -> Result<Self, AdmitError> {
        let vm_id = vm_id.into();
        if vm_id.is_empty() {
            return Err(AdmitError::EmptyVmId);
        }
        Ok(Self { vm_id, epoch })
    }

    /// Extract `payload["attestation"]` and parse it.
    pub fn from_payload(payload: &Value) -> Result<Self, AdmitError> {
        let obj = payload.as_object().ok_or(AdmitError::NotAnObject)?;
        let att = obj
            .get("attestation")
            .ok_or(AdmitError::MissingAttestation)?;
        Self::from_value(att)
    }

    /// Parse `{"vm_id": "<string>", "epoch": <u64>}`.
    pub fn from_value(value: &Value) -> Result<Self, AdmitError> {
        let obj = value.as_object().ok_or(AdmitError::NotAnObject)?;
        let vm_id = obj
            .get("vm_id")
            .and_then(Value::as_str)
            .ok_or(AdmitError::MissingField("vm_id"))?;
        if vm_id.is_empty() {
            return Err(AdmitError::EmptyVmId);
        }
        let epoch = match obj.get("epoch") {
            Some(Value::Number(n)) => n.as_u64().ok_or(AdmitError::InvalidEpoch)?,
            Some(_) | None => return Err(AdmitError::InvalidEpoch),
        };
        Ok(Self {
            vm_id: vm_id.to_string(),
            epoch,
        })
    }

    /// JSON object form used on the Elixir v1 payload.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "vm_id": self.vm_id,
            "epoch": self.epoch,
        })
    }

    /// Matching `vm_id`. Epoch is already a non-negative integer.
    pub fn valid_for(&self, vm_id: &str) -> bool {
        self.vm_id == vm_id
    }
}
