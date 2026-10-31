//! In-memory secret store. The wallet persists the same records.

use std::collections::BTreeMap;

use crate::record::{SealedSecret, SecretError, SecretId, SecretMeta};

/// Put, read, list, and remove opaque secrets. Listing does not return values.
pub trait SecretStore {
    /// Seal `value` and store it. `created_at` is unix seconds.
    fn insert(
        &mut self,
        label: &str,
        value: &[u8],
        created_at: u64,
    ) -> Result<SecretId, SecretError>;

    /// The secret, if this store holds `id`.
    fn get(&self, id: &SecretId) -> Option<&SealedSecret>;

    /// Id, label, time, and commitment. No values.
    fn list(&self) -> Vec<SecretMeta>;

    /// Remove `id`. Returns whether it was present.
    fn remove(&mut self, id: &SecretId) -> bool;
}

/// BTree-ordered memory store. Values are wiped when the record is removed or dropped.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    records: BTreeMap<SecretId, SealedSecret>,
}

impl MemorySecretStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Records in id order, for a container encoder.
    pub fn iter(&self) -> impl Iterator<Item = &SealedSecret> {
        self.records.values()
    }

    /// Insert a record that already has an id. Duplicate ids are rejected.
    pub fn insert_sealed(&mut self, secret: SealedSecret) -> Result<(), SecretError> {
        let id = secret.id().clone();
        if self.records.contains_key(&id) {
            return Err(SecretError::Duplicate);
        }
        self.records.insert(id, secret);
        Ok(())
    }
}

impl SecretStore for MemorySecretStore {
    fn insert(
        &mut self,
        label: &str,
        value: &[u8],
        created_at: u64,
    ) -> Result<SecretId, SecretError> {
        let secret = SealedSecret::generate(label, value, created_at)?;
        let id = secret.id().clone();
        self.insert_sealed(secret)?;
        Ok(id)
    }

    fn get(&self, id: &SecretId) -> Option<&SealedSecret> {
        self.records.get(id)
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.records.values().map(SealedSecret::meta).collect()
    }

    fn remove(&mut self, id: &SecretId) -> bool {
        self.records.remove(id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_list_and_remove() {
        let mut store = MemorySecretStore::new();
        let id = store.insert("github", b"ghp_one", 20).unwrap();
        let meta = store.list();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].label, "github");
        assert!(!format!("{meta:?}").contains("ghp_one"));
        assert_eq!(store.get(&id).unwrap().value(), b"ghp_one");
        assert!(store.remove(&id));
        assert!(store.get(&id).is_none());
    }
}
