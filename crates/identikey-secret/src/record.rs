//! One sealed secret and its public commitment.

use std::fmt;

use bc_envelope::prelude::*;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// Largest secret this store will accept.
pub const MAX_VALUE_LEN: usize = 64 * 1024;

const COMMIT_DOMAIN: &[u8] = b"identikey-secret-v1\n";
const SECRET_TYPE: &str = "identikey.sealed-secret";
const FORMAT_VERSION: u32 = 1;
const KNOWN: &[&str] = &["label", "created", "salt", "value"];

/// Why a secret record was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretError {
    /// The id is empty, too long, or not path-safe.
    #[error("secret id is not path-safe")]
    BadId,
    /// The label is empty or longer than 128 bytes.
    #[error("secret label is empty or too long")]
    BadLabel,
    /// The value is empty or larger than [`MAX_VALUE_LEN`].
    #[error("secret value is empty or too large")]
    BadValue,
    /// The envelope is not a v1 sealed secret.
    #[error("sealed secret envelope is not valid")]
    Envelope,
    /// This id is already in the store.
    #[error("secret id already exists")]
    Duplicate,
}

/// Path-safe secret id. No slash, no `..`, no NUL.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretId(String);

impl SecretId {
    /// Accept an id that can be a single path segment.
    pub fn new(raw: impl Into<String>) -> Result<Self, SecretError> {
        let raw = raw.into();
        if !is_path_safe(&raw) {
            return Err(SecretError::BadId);
        }
        Ok(Self(raw))
    }

    /// Borrow the id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Salt plus the commitment derived from it. The secret value is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretCommitment {
    /// 32 random bytes mixed into the commitment.
    pub salt: [u8; 32],
    /// `Blake3(domain || salt || value)`.
    pub commitment: [u8; 32],
}

/// What a listing may show. The value is not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    /// Stable id.
    pub id: SecretId,
    /// Caller-supplied name.
    pub label: String,
    /// Unix seconds chosen by the caller.
    pub created_at: u64,
    /// Public commitment.
    pub commitment: SecretCommitment,
}

/// One secret. The value is wiped when this value is dropped.
pub struct SealedSecret {
    id: SecretId,
    label: String,
    created_at: u64,
    salt: [u8; 32],
    value: Zeroizing<Vec<u8>>,
    unknown: Vec<(Envelope, Envelope)>,
}

impl Drop for SealedSecret {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSecret")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .field("value", &"[redacted]")
            .finish()
    }
}

impl SealedSecret {
    /// Seal `value` under a fresh salt and a fresh id.
    pub fn generate(label: &str, value: &[u8], created_at: u64) -> Result<Self, SecretError> {
        check_label(label)?;
        check_value(value)?;
        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Ok(Self {
            id: SecretId(hex_id(&id_bytes)),
            label: label.to_string(),
            created_at,
            salt,
            value: Zeroizing::new(value.to_vec()),
            unknown: Vec::new(),
        })
    }

    /// Id of this record.
    pub fn id(&self) -> &SecretId {
        &self.id
    }

    /// Label stored with the secret.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Unix seconds supplied when the secret was sealed.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Secret bytes. The caller must not log them.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Salt and commitment for a token or a log. The value is not included.
    pub fn commitment(&self) -> SecretCommitment {
        SecretCommitment {
            salt: self.salt,
            commitment: commitment(&self.salt, &self.value),
        }
    }

    /// Listing view of this record.
    pub fn meta(&self) -> SecretMeta {
        SecretMeta {
            id: self.id.clone(),
            label: self.label.clone(),
            created_at: self.created_at,
            commitment: self.commitment(),
        }
    }

    /// Gordian object embedded under the wallet predicate `sealed-secret`.
    pub fn to_envelope(&self) -> Result<Envelope, SecretError> {
        let mut subject = Map::new();
        subject.insert("type", SECRET_TYPE);
        subject.insert("format-version", FORMAT_VERSION);
        subject.insert("id", self.id.as_str());
        let mut envelope = Envelope::new(CBOR::from(subject));
        envelope = envelope.add_assertion("label", self.label.as_str());
        let created = CBOR::to_tagged_value(Tag::with_value(1), self.created_at);
        envelope = envelope.add_assertion("created", created);
        envelope = envelope.add_assertion("salt", ByteString::from(self.salt.to_vec()));
        envelope = envelope.add_assertion("value", ByteString::from(self.value.to_vec()));
        for (pred, obj) in &self.unknown {
            let assertion = Envelope::new_assertion(pred.clone(), obj.clone());
            envelope = envelope
                .add_assertion_envelope(assertion)
                .map_err(|_| SecretError::Envelope)?;
        }
        Ok(envelope)
    }

    /// Parse a sealed-secret object. Unknown assertions inside it are kept.
    pub fn from_envelope(envelope: &Envelope) -> Result<Self, SecretError> {
        let subject_cbor = envelope
            .subject()
            .try_leaf()
            .map_err(|_| SecretError::Envelope)?;
        let subject = match subject_cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(SecretError::Envelope),
        };
        let ty: String = subject.get("type").ok_or(SecretError::Envelope)?;
        if ty != SECRET_TYPE {
            return Err(SecretError::Envelope);
        }
        let version: u32 = subject.get("format-version").ok_or(SecretError::Envelope)?;
        if version != FORMAT_VERSION {
            return Err(SecretError::Envelope);
        }
        let id_text: String = subject.get("id").ok_or(SecretError::Envelope)?;
        let id = SecretId::new(id_text)?;
        let label: String = envelope
            .extract_object_for_predicate("label")
            .map_err(|_| SecretError::Envelope)?;
        check_label(&label)?;
        let created_at = created_at(envelope)?;
        let salt_bs: ByteString = envelope
            .extract_object_for_predicate("salt")
            .map_err(|_| SecretError::Envelope)?;
        let salt: [u8; 32] = salt_bs
            .as_ref()
            .try_into()
            .map_err(|_| SecretError::Envelope)?;
        let value_bs: ByteString = envelope
            .extract_object_for_predicate("value")
            .map_err(|_| SecretError::Envelope)?;
        let value = value_bs.as_ref();
        check_value(value)?;
        let known = known_digests();
        let mut unknown = Vec::new();
        for assertion in envelope.assertions() {
            let (pred, obj) = match (assertion.as_predicate(), assertion.as_object()) {
                (Some(pred), Some(obj)) => (pred, obj),
                _ => continue,
            };
            if !known.contains(&pred.digest()) {
                unknown.push((pred, obj));
            }
        }
        Ok(Self {
            id,
            label,
            created_at,
            salt,
            value: Zeroizing::new(value.to_vec()),
            unknown,
        })
    }
}

/// `Blake3("identikey-secret-v1\n" || salt || value)`.
#[must_use]
pub fn commitment(salt: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(salt);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

fn created_at(envelope: &Envelope) -> Result<u64, SecretError> {
    let obj = envelope
        .object_for_predicate("created")
        .map_err(|_| SecretError::Envelope)?;
    let cbor = obj.try_leaf().map_err(|_| SecretError::Envelope)?;
    let (_tag, value) = CBOR::try_into_tagged_value(cbor).map_err(|_| SecretError::Envelope)?;
    value.try_into().map_err(|_| SecretError::Envelope)
}

fn known_digests() -> Vec<Digest> {
    KNOWN
        .iter()
        .map(|pred| Envelope::new(*pred).digest())
        .collect()
}

fn check_label(label: &str) -> Result<(), SecretError> {
    if label.is_empty() || label.len() > 128 || label.contains('\0') || label.contains('/') {
        return Err(SecretError::BadLabel);
    }
    Ok(())
}

fn check_value(value: &[u8]) -> Result<(), SecretError> {
    if value.is_empty() || value.len() > MAX_VALUE_LEN {
        return Err(SecretError::BadValue);
    }
    Ok(())
}

fn is_path_safe(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || raw == "." || raw == ".." {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn hex_id(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_mixes_salt_and_hides_the_value_from_debug() {
        let secret = SealedSecret::generate("github", b"ghp_example", 1_700_000_000).unwrap();
        let shown = format!("{secret:?}");
        assert!(shown.contains("[redacted]"));
        assert!(!shown.contains("ghp_example"));
        let again = commitment(&secret.commitment().salt, b"other");
        assert_ne!(again, secret.commitment().commitment);
    }

    #[test]
    fn envelope_roundtrip_keeps_an_unknown_assertion() {
        let mut secret = SealedSecret::generate("pat", b"super-secret", 10).unwrap();
        secret
            .unknown
            .push((Envelope::new("note"), Envelope::new("desk")));
        let envelope = secret.to_envelope().unwrap();
        let decoded = SealedSecret::from_envelope(&envelope).unwrap();
        assert_eq!(decoded.id(), secret.id());
        assert_eq!(decoded.value(), b"super-secret");
        assert_eq!(decoded.commitment(), secret.commitment());
        assert_eq!(decoded.unknown.len(), 1);
    }

    #[test]
    fn rejects_unsafe_ids_and_unsalted_shape() {
        assert!(SecretId::new("../x").is_err());
        assert!(SecretId::new("a/b").is_err());
        assert!(SecretId::new("").is_err());
        assert!(SecretId::new("github.pat").is_ok());
        assert!(SealedSecret::generate("", b"x", 0).is_err());
        assert!(SealedSecret::generate("ok", b"", 0).is_err());
    }
}
