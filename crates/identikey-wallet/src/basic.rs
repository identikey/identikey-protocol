//! `BasicIdentity` — the built-in identity type for `ikey` and IdentiKey
//! applications: Ed25519 signing identity with Blake3 fingerprint, optional
//! ML-DSA-87 post-quantum keypair, and forward-compatible preservation of
//! app-specific assertions.
//!
//! Envelope subject: `{type: "identikey.identity", format-version: 1,
//! fingerprint: <32 bytes>}`. Known assertion predicates: `created` (tag 1
//! epoch seconds), `ed25519-public`, `ed25519-secret`, `ml-dsa-public`,
//! `ml-dsa-secret`, `name`. Any other assertion is preserved verbatim in
//! `unknown_assertions` and re-emitted on encode, so application extensions
//! (e.g. Recrypt's `pre-*` key material) survive a load+save by a client
//! that doesn't understand them.

use anyhow::{anyhow, Result};
use bc_envelope::prelude::*;
use std::sync::OnceLock;
use zeroize::ZeroizeOnDrop;

use super::envelope::WalletIdentity;
use super::format::{KeyPair, WalletParams};
use super::IDENTIKEY_PARAMS;

const IDENTITY_TYPE: &str = "identikey.identity";
const IDENTITY_FORMAT_VERSION: u32 = 1;

const KNOWN_PREDICATES: &[&str] = &[
    "created",
    "ed25519-public",
    "ed25519-secret",
    "ml-dsa-public",
    "ml-dsa-secret",
    "name",
];

fn known_predicate_digests() -> &'static [Digest] {
    static CELL: OnceLock<Vec<Digest>> = OnceLock::new();
    CELL.get_or_init(|| {
        KNOWN_PREDICATES
            .iter()
            .map(|p| Envelope::new(*p).digest())
            .collect()
    })
}

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct BasicIdentity {
    #[zeroize(skip)]
    pub created_at: u64,
    /// Blake3(ed25519_public). Raw bytes; encode with bs58 for display/wire.
    #[zeroize(skip)]
    pub fingerprint: [u8; 32],
    pub ed25519: KeyPair,
    /// Optional ML-DSA-87 post-quantum signing keypair.
    pub ml_dsa: Option<KeyPair>,
    /// Assertions with predicates outside `KNOWN_PREDICATES`, preserved
    /// verbatim across decode/encode for forward compatibility.
    #[zeroize(skip)]
    pub unknown_assertions: Vec<(Envelope, Envelope)>,
}

impl BasicIdentity {
    /// Build an identity from an Ed25519 keypair, computing the fingerprint.
    pub fn new(created_at: u64, ed25519_public: Vec<u8>, ed25519_secret: Vec<u8>) -> Self {
        let fingerprint = *blake3::hash(&ed25519_public).as_bytes();
        Self {
            created_at,
            fingerprint,
            ed25519: KeyPair {
                public: ed25519_public,
                secret: ed25519_secret,
            },
            ml_dsa: None,
            unknown_assertions: Vec::new(),
        }
    }

    /// Base58 fingerprint for display.
    pub fn fingerprint_b58(&self) -> String {
        bs58_encode(&self.fingerprint)
    }
}

fn bs58_encode(bytes: &[u8]) -> String {
    // Minimal base58btc encoder (avoids a dependency for one call site).
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = String::with_capacity(leading_zeros + digits.len());
    out.extend(std::iter::repeat('1').take(leading_zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

impl WalletIdentity for BasicIdentity {
    const PARAMS: &'static WalletParams = &IDENTIKEY_PARAMS;

    fn to_envelope(&self, name: &str) -> Result<Envelope> {
        // Encoder-side fingerprint check: catches construction errors before
        // they hit the disk. Decoder enforces the same invariant on parse.
        let expected_fp = blake3::hash(&self.ed25519.public);
        if self.fingerprint != *expected_fp.as_bytes() {
            return Err(anyhow!(
                "fingerprint does not match Blake3(ed25519-public)"
            ));
        }

        let mut subject = Map::new();
        subject.insert("type", IDENTITY_TYPE);
        subject.insert("format-version", IDENTITY_FORMAT_VERSION);
        subject.insert("fingerprint", ByteString::from(self.fingerprint.to_vec()));

        let mut envelope = Envelope::new(CBOR::from(subject));

        let created = CBOR::to_tagged_value(Tag::with_value(1), self.created_at);
        envelope = envelope.add_assertion("created", created);

        envelope = envelope.add_assertion(
            "ed25519-public",
            ByteString::from(self.ed25519.public.clone()),
        );
        envelope = envelope.add_assertion(
            "ed25519-secret",
            ByteString::from(self.ed25519.secret.clone()),
        );

        if let Some(ref ml_dsa) = self.ml_dsa {
            envelope =
                envelope.add_assertion("ml-dsa-public", ByteString::from(ml_dsa.public.clone()));
            envelope =
                envelope.add_assertion("ml-dsa-secret", ByteString::from(ml_dsa.secret.clone()));
        }

        envelope = envelope.add_assertion("name", name);

        for (pred, obj) in &self.unknown_assertions {
            let assertion = Envelope::new_assertion(pred.clone(), obj.clone());
            envelope = envelope
                .add_assertion_envelope(assertion)
                .map_err(|e| anyhow!("add unknown identity assertion: {e}"))?;
        }

        Ok(envelope)
    }

    fn from_envelope(envelope: &Envelope) -> Result<(String, Self)> {
        let subject_cbor = envelope
            .subject()
            .try_leaf()
            .map_err(|e| anyhow!("Identity envelope subject not a leaf: {e}"))?;
        let subject = match subject_cbor.into_case() {
            CBORCase::Map(m) => m,
            _ => return Err(anyhow!("Identity envelope subject is not a map")),
        };

        let ty: String = subject
            .get("type")
            .ok_or_else(|| anyhow!("Identity envelope subject missing 'type'"))?;
        if ty != IDENTITY_TYPE {
            return Err(anyhow!(
                "Expected identity type '{IDENTITY_TYPE}', got '{ty}'"
            ));
        }
        let version: u32 = subject
            .get("format-version")
            .ok_or_else(|| anyhow!("Identity envelope subject missing 'format-version'"))?;
        if version != IDENTITY_FORMAT_VERSION {
            return Err(anyhow!("Unsupported identity format-version: {version}"));
        }
        let fingerprint_bytes: ByteString = subject
            .get("fingerprint")
            .ok_or_else(|| anyhow!("Identity envelope subject missing 'fingerprint'"))?;
        let fingerprint: [u8; 32] = fingerprint_bytes
            .to_vec()
            .try_into()
            .map_err(|_| anyhow!("Identity fingerprint must be 32 bytes"))?;

        let name: String = envelope
            .extract_object_for_predicate("name")
            .map_err(|e| anyhow!("Identity envelope missing 'name': {e}"))?;
        let created_at: u64 = {
            let obj = envelope
                .object_for_predicate("created")
                .map_err(|e| anyhow!("Identity envelope missing 'created': {e}"))?;
            let cbor = obj
                .try_leaf()
                .map_err(|e| anyhow!("'created' is not a leaf: {e}"))?;
            let (_tag, value) = CBOR::try_into_tagged_value(cbor)
                .map_err(|e| anyhow!("'created' is not a tagged value: {e}"))?;
            value
                .try_into()
                .map_err(|e| anyhow!("'created' is not an integer: {e}"))?
        };
        let ed25519_public: ByteString = envelope
            .extract_object_for_predicate("ed25519-public")
            .map_err(|e| anyhow!("Identity envelope missing 'ed25519-public': {e}"))?;
        let ed25519_secret: ByteString = envelope
            .extract_object_for_predicate("ed25519-secret")
            .map_err(|e| anyhow!("Identity envelope missing 'ed25519-secret': {e}"))?;

        let ml_dsa_public: Option<ByteString> = envelope
            .extract_optional_object_for_predicate("ml-dsa-public")
            .unwrap_or(None);
        let ml_dsa_secret: Option<ByteString> = envelope
            .extract_optional_object_for_predicate("ml-dsa-secret")
            .unwrap_or(None);
        let ml_dsa = match (ml_dsa_public, ml_dsa_secret) {
            (Some(public), Some(secret)) => Some(KeyPair {
                public: public.to_vec(),
                secret: secret.to_vec(),
            }),
            (None, None) => None,
            _ => {
                return Err(anyhow!(
                    "Identity envelope has only one of ml-dsa-public/ml-dsa-secret"
                ))
            }
        };

        // Decoder-side fingerprint enforcement.
        let ed25519_public = ed25519_public.to_vec();
        let ed25519_secret = ed25519_secret.to_vec();
        let expected_fp = blake3::hash(&ed25519_public);
        if fingerprint != *expected_fp.as_bytes() {
            return Err(anyhow!(
                "fingerprint does not match Blake3(ed25519-public)"
            ));
        }

        let known = known_predicate_digests();
        let mut unknown_assertions: Vec<(Envelope, Envelope)> = Vec::new();
        for assertion in envelope.assertions() {
            if let (Some(pred), Some(obj)) = (assertion.as_predicate(), assertion.as_object()) {
                if !known.contains(&pred.digest()) {
                    unknown_assertions.push((pred, obj));
                }
            }
        }

        Ok((
            name,
            Self {
                created_at,
                fingerprint,
                ed25519: KeyPair {
                    public: ed25519_public,
                    secret: ed25519_secret,
                },
                ml_dsa,
                unknown_assertions,
            },
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn test_identity(seed: u8) -> BasicIdentity {
        let ed_public = vec![seed; 32];
        let mut id = BasicIdentity::new(
            1_704_067_200 + seed as u64,
            ed_public,
            vec![seed.wrapping_add(1); 32],
        );
        id.ml_dsa = Some(KeyPair {
            public: vec![seed.wrapping_add(2); 16],
            secret: vec![seed.wrapping_add(3); 32],
        });
        id
    }

    #[test]
    fn roundtrip_with_and_without_ml_dsa() {
        for with_pq in [true, false] {
            let mut id = test_identity(9);
            if !with_pq {
                id.ml_dsa = None;
            }
            let env = id.to_envelope("alice").unwrap();
            let (name, decoded) = BasicIdentity::from_envelope(&env).unwrap();
            assert_eq!(name, "alice");
            assert_eq!(decoded.created_at, id.created_at);
            assert_eq!(decoded.fingerprint, id.fingerprint);
            assert_eq!(decoded.ed25519.public, id.ed25519.public);
            assert_eq!(decoded.ed25519.secret, id.ed25519.secret);
            assert_eq!(decoded.ml_dsa.is_some(), with_pq);
        }
    }

    #[test]
    fn encode_rejects_tampered_fingerprint() {
        let mut id = test_identity(1);
        id.fingerprint = [0xFFu8; 32];
        let err = id.to_envelope("alice").unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("fingerprint"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decode_rejects_tampered_fingerprint() {
        let id = test_identity(2);
        let env = id.to_envelope("alice").unwrap();
        // Rebuild the envelope with a corrupted subject fingerprint.
        let mut subject = Map::new();
        subject.insert("type", IDENTITY_TYPE);
        subject.insert("format-version", IDENTITY_FORMAT_VERSION);
        subject.insert("fingerprint", ByteString::from(vec![0xFF; 32]));
        let mut bad = Envelope::new(CBOR::from(subject));
        for assertion in env.assertions() {
            bad = bad.add_assertion_envelope(assertion).unwrap();
        }
        let err = BasicIdentity::from_envelope(&bad).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("fingerprint"),
            "unexpected error: {err}"
        );
    }

    /// Unknown identity-level assertions (e.g. an application's extension
    /// key material) must survive a decode/encode round-trip byte-stably.
    #[test]
    fn unknown_assertion_roundtrips_byte_stably() {
        let mut id = test_identity(3);
        id.unknown_assertions.push((
            Envelope::new("pre-backend"),
            Envelope::new("lattice"),
        ));
        let env = id.to_envelope("alice").unwrap();
        let bytes = env.to_cbor_data();

        let (_, decoded) = BasicIdentity::from_envelope(&env).unwrap();
        assert_eq!(decoded.unknown_assertions.len(), 1);

        let env_again = decoded.to_envelope("alice").unwrap();
        assert_eq!(
            bytes,
            env_again.to_cbor_data(),
            "unknown assertions are not byte-stable across decode/encode"
        );
    }

    #[test]
    fn fingerprint_b58_matches_bs58_alphabet() {
        let id = test_identity(4);
        let b58 = id.fingerprint_b58();
        assert!(!b58.is_empty());
        assert!(b58.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!b58.contains('0') && !b58.contains('O') && !b58.contains('l'));
    }
}
