//! Gordian Envelope encode/decode for the wallet container.
//!
//! The container structure is application-independent: a subject map
//! (`type`, `format-version` from [`WalletParams`]), an optional
//! `active-identity` assertion, one `identity` assertion per identity, and
//! verbatim round-tripping of any other (unknown) assertion for additive
//! forward compatibility.
//!
//! How each identity encodes is delegated to the [`WalletIdentity`]
//! implementation, so applications control their own identity envelope
//! format (and its byte-level stability guarantees).

use anyhow::{anyhow, Result};
use bc_envelope::prelude::*;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::format::{WalletData, WalletParams};

/// Identity type stored in a wallet.
///
/// Ties together three things: the app's wallet parameters, and the
/// envelope codec for a named identity. Implementations MUST make
/// `from_envelope(to_envelope(name, id)) == (name, id)` and SHOULD keep the
/// encoding byte-stable across a decode/encode round-trip (preserving any
/// unknown assertions) so wallets survive edits by older clients.
pub trait WalletIdentity: Sized {
    /// The application's wallet parameters (envelope type string, keychain
    /// service, environment variables, default path).
    const PARAMS: &'static WalletParams;

    /// Encode this identity (with its wallet name) as an envelope.
    fn to_envelope(&self, name: &str) -> Result<Envelope>;

    /// Decode an identity envelope, returning its wallet name and the identity.
    fn from_envelope(envelope: &Envelope) -> Result<(String, Self)>;
}

/// Wallet-level predicates the container codec recognizes. Any other
/// predicate is treated as an unknown forward-compat assertion and
/// round-tripped verbatim via `WalletData::unknown_assertions`.
const KNOWN_PREDICATES: &[&str] = &["active-identity", "identity"];

fn known_predicate_digests() -> &'static [Digest] {
    static CELL: OnceLock<Vec<Digest>> = OnceLock::new();
    CELL.get_or_init(|| {
        KNOWN_PREDICATES
            .iter()
            .map(|p| Envelope::new(*p).digest())
            .collect()
    })
}

/// Encode a wallet to dCBOR envelope bytes.
pub fn to_envelope<I: WalletIdentity>(
    wallet: &WalletData<I>,
    params: &WalletParams,
) -> Result<Vec<u8>> {
    let envelope = wallet_to_envelope(wallet, params)?;
    Ok(envelope.to_cbor_data())
}

/// Decode dCBOR envelope bytes into a WalletData.
pub fn from_envelope<I: WalletIdentity>(
    bytes: &[u8],
    params: &WalletParams,
) -> Result<WalletData<I>> {
    let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
        .map_err(|e| anyhow!("Failed to parse wallet envelope: {e}"))?;
    wallet_from_envelope(&envelope, params)
}

fn wallet_to_envelope<I: WalletIdentity>(
    wallet: &WalletData<I>,
    params: &WalletParams,
) -> Result<Envelope> {
    let mut subject = Map::new();
    subject.insert("type", params.wallet_type);
    subject.insert("format-version", params.format_version);

    let mut envelope = Envelope::new(CBOR::from(subject));

    if let Some(ref active) = wallet.active_identity {
        envelope = envelope.add_assertion("active-identity", active.as_str());
    }

    // Sort by name for stable encoding order across runs.
    let mut names: Vec<&String> = wallet.identities.keys().collect();
    names.sort();
    for name in names {
        let identity = &wallet.identities[name];
        let id_envelope = identity.to_envelope(name)?;
        envelope = envelope.add_assertion("identity", id_envelope);
    }

    // Re-emit unknown wallet-level assertions in their original order so
    // additive spec extensions survive a load+save round-trip.
    for (pred, obj) in &wallet.unknown_assertions {
        let assertion = Envelope::new_assertion(pred.clone(), obj.clone());
        envelope = envelope
            .add_assertion_envelope(assertion)
            .map_err(|e| anyhow!("add unknown wallet assertion: {e}"))?;
    }

    Ok(envelope)
}

fn wallet_from_envelope<I: WalletIdentity>(
    envelope: &Envelope,
    params: &WalletParams,
) -> Result<WalletData<I>> {
    let subject_cbor = envelope
        .subject()
        .try_leaf()
        .map_err(|e| anyhow!("Wallet envelope subject not a leaf: {e}"))?;

    let subject = match subject_cbor.into_case() {
        CBORCase::Map(m) => m,
        _ => return Err(anyhow!("Wallet envelope subject is not a map")),
    };

    let ty: String = subject
        .get("type")
        .ok_or_else(|| anyhow!("Wallet envelope subject missing 'type'"))?;
    if ty != params.wallet_type {
        return Err(anyhow!(
            "Expected wallet type '{}', got '{ty}'",
            params.wallet_type
        ));
    }

    let version: u32 = subject
        .get("format-version")
        .ok_or_else(|| anyhow!("Wallet envelope subject missing 'format-version'"))?;
    if version != params.format_version {
        return Err(anyhow!(
            "Unsupported wallet envelope format-version: {version}"
        ));
    }

    let active_identity: Option<String> = envelope
        .extract_optional_object_for_predicate::<String>("active-identity")
        .unwrap_or(None);

    let known = known_predicate_digests();
    let mut identities: HashMap<String, I> = HashMap::new();
    let mut unknown_assertions: Vec<(Envelope, Envelope)> = Vec::new();
    for assertion in envelope.assertions() {
        let (pred, obj) = match (assertion.as_predicate(), assertion.as_object()) {
            (Some(p), Some(o)) => (p, o),
            _ => continue,
        };

        if !known.contains(&pred.digest()) {
            unknown_assertions.push((pred, obj));
            continue;
        }

        // Known predicate. `active-identity` was already extracted above; we
        // only need to dispatch the `identity` arm here.
        let pred_str: String = match pred.try_leaf() {
            Ok(c) => match c.try_into_text() {
                Ok(s) => s,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        if pred_str != "identity" {
            continue;
        }
        let (name, identity) = I::from_envelope(&obj)?;
        if identities.insert(name.clone(), identity).is_some() {
            return Err(anyhow!("Duplicate identity name: {name}"));
        }
    }

    Ok(WalletData {
        identities,
        active_identity,
        unknown_assertions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic::tests::test_identity;
    use crate::{BasicIdentity, IDENTIKEY_PARAMS};

    fn assert_wallet_eq(a: &WalletData<BasicIdentity>, b: &WalletData<BasicIdentity>) {
        assert_eq!(a.active_identity, b.active_identity, "active-identity");
        assert_eq!(a.identities.len(), b.identities.len(), "identity count");
        for (name, id_a) in &a.identities {
            let id_b = b
                .identities
                .get(name)
                .unwrap_or_else(|| panic!("missing identity {name} after roundtrip"));
            assert_eq!(id_a.created_at, id_b.created_at, "{name}: created_at");
            assert_eq!(id_a.fingerprint, id_b.fingerprint, "{name}: fingerprint");
            assert_eq!(id_a.ed25519.public, id_b.ed25519.public, "{name}: ed pub");
            assert_eq!(id_a.ed25519.secret, id_b.ed25519.secret, "{name}: ed sec");
            assert_eq!(
                id_a.ml_dsa.as_ref().map(|k| (&k.public, &k.secret)),
                id_b.ml_dsa.as_ref().map(|k| (&k.public, &k.secret)),
                "{name}: ml_dsa"
            );
        }
    }

    #[test]
    fn roundtrip_identities_active_preserved() {
        let mut wallet: WalletData<BasicIdentity> = WalletData::new();
        wallet.active_identity = Some("bob".to_string());
        for (name, seed) in [("alice", 1), ("bob", 2), ("carol", 3)] {
            wallet.identities.insert(name.to_string(), test_identity(seed));
        }

        let bytes = to_envelope(&wallet, &IDENTIKEY_PARAMS).unwrap();
        let decoded = from_envelope(&bytes, &IDENTIKEY_PARAMS).unwrap();
        assert_wallet_eq(&wallet, &decoded);
        assert_eq!(decoded.active_identity, Some("bob".to_string()));
    }

    #[test]
    fn determinism_same_input_same_bytes() {
        let mut wallet: WalletData<BasicIdentity> = WalletData::new();
        wallet.identities.insert("alice".to_string(), test_identity(7));
        wallet.active_identity = Some("alice".to_string());

        let a = to_envelope(&wallet, &IDENTIKEY_PARAMS).unwrap();
        let b = to_envelope(&wallet, &IDENTIKEY_PARAMS).unwrap();
        assert_eq!(a, b, "envelope encoding is non-deterministic");
    }

    #[test]
    fn decode_rejects_wrong_wallet_type() {
        let mut subject = Map::new();
        subject.insert("type", "recrypt.identity"); // wrong!
        subject.insert("format-version", IDENTIKEY_PARAMS.format_version);
        let env = Envelope::new(CBOR::from(subject));
        let bytes = env.to_cbor_data();
        let err = from_envelope::<BasicIdentity>(&bytes, &IDENTIKEY_PARAMS).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Expected wallet type"), "unexpected: {msg}");
    }

    #[test]
    fn decode_rejects_wrong_format_version() {
        let mut subject = Map::new();
        subject.insert("type", IDENTIKEY_PARAMS.wallet_type);
        subject.insert("format-version", 99u32);
        let env = Envelope::new(CBOR::from(subject));
        let bytes = env.to_cbor_data();
        let err = from_envelope::<BasicIdentity>(&bytes, &IDENTIKEY_PARAMS).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Unsupported wallet envelope format-version"),
            "unexpected: {msg}"
        );
    }

    /// Forward-compat: a wallet-level assertion with an unknown predicate
    /// must survive a load+save round-trip — both decoded into
    /// `unknown_assertions` and re-emitted byte-stably on encode.
    #[test]
    fn wallet_level_unknown_assertion_roundtrips() {
        let wallet: WalletData<BasicIdentity> = WalletData {
            identities: HashMap::new(),
            active_identity: None,
            unknown_assertions: vec![(
                Envelope::new("keyspace-membership"),
                Envelope::new("future-namespace-value"),
            )],
        };

        let bytes = to_envelope(&wallet, &IDENTIKEY_PARAMS).unwrap();
        let decoded = from_envelope::<BasicIdentity>(&bytes, &IDENTIKEY_PARAMS).unwrap();
        assert_eq!(
            decoded.unknown_assertions.len(),
            1,
            "wallet-level unknown assertion was dropped on decode"
        );
        let pred_text: String = decoded.unknown_assertions[0]
            .0
            .clone()
            .try_leaf()
            .unwrap()
            .try_into_text()
            .unwrap();
        assert_eq!(pred_text, "keyspace-membership");

        let bytes_again = to_envelope(&decoded, &IDENTIKEY_PARAMS).unwrap();
        assert_eq!(
            bytes, bytes_again,
            "wallet-level unknowns are not byte-stable across load+save"
        );
    }
}
