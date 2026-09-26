//! IdentiKey agency capability tokens (Biscuit).
//!
//! Wire + validators only. Application profiles (Mjolnir login Datalog,
//! tokenator, HTTP) belong to the embedder. This crate **must not** depend
//! on `identikey-core`.
//!
//! Spec: `docs/standards/identikey-capability-v1.md`.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod bearer;
mod error;

pub use bearer::{decode_bearer, encode_bearer};
pub use biscuit_auth::{Biscuit, KeyPair, PublicKey};
pub use error::CapabilityError;

use biscuit_auth::{
    builder::Algorithm,
    macros::{authorizer, biscuit, block},
    PrivateKey,
};
use identikey_auth::{ClassicalAlg, ClassicalPublicKey};

/// Official Blake3 empty-string digest (FIPS 202 / BLAKE3 vectors).
pub const EMPTY_BLAKE3: [u8; 32] = [
    0xAF, 0x13, 0x49, 0xB9, 0xF5, 0xF9, 0xA1, 0xA6, 0xA0, 0x40, 0x4D, 0xEA, 0x36, 0xDC, 0xC9,
    0x49, 0x9B, 0xCB, 0x25, 0xC9, 0xAD, 0xC1, 0x12, 0xB7, 0xCC, 0x9A, 0x93, 0xCA, 0xE4, 0x1F,
    0x32, 0x62,
];

/// Blake3-256 of `data`.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// identikey-auth v1 §5 fingerprint of an Ed25519 public key.
///
/// `Blake3(dcbor({"alg":"ed25519","key": pub}))`. Not Blake3 of the raw 32 bytes.
pub fn holder_fingerprint(ed25519_pub: &[u8]) -> Result<[u8; 32], CapabilityError> {
    if ed25519_pub.len() != 32 {
        return Err(CapabilityError::PublicLen);
    }
    let pk = ClassicalPublicKey {
        alg: ClassicalAlg::Ed25519,
        bytes: ed25519_pub.to_vec(),
    };
    Ok(*pk.fingerprint().as_bytes())
}

/// Domain-separated secret commitment: `Blake3(domain || salt || secret)`.
///
/// `domain` is a caller argument. Product profiles pass their own
/// (Mjolnir uses `mjolnir/secret-commit/v1`). This crate does not name one.
pub fn secret_commit(domain: &[u8], salt: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(domain.len() + salt.len() + secret.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(secret);
    blake3_hash(&buf)
}

/// Fresh Ed25519 Biscuit authority keypair.
pub fn new_keypair() -> KeyPair {
    KeyPair::new()
}

/// Rebuild a keypair from a 32-byte Ed25519 private key (hex).
pub fn keypair_from_private_hex(hex_str: &str) -> Result<KeyPair, CapabilityError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| CapabilityError::Key(e.to_string()))?;
    let private = PrivateKey::from_bytes(&bytes, Algorithm::Ed25519)
        .map_err(|e| CapabilityError::Key(e.to_string()))?;
    Ok(KeyPair::from(&private))
}

/// Parse an Ed25519 public key from hex.
pub fn public_from_hex(hex_str: &str) -> Result<PublicKey, CapabilityError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| CapabilityError::Key(e.to_string()))?;
    PublicKey::from_bytes(&bytes, Algorithm::Ed25519).map_err(|e| CapabilityError::Key(e.to_string()))
}

/// Mint a root token whose authority block is `right(<resource>, <operation>);`.
///
/// That fact is a **vector / generic right**, not a Mjolnir profile. Embedders
/// mint their own Datalog; this helper is the protocol round-trip.
pub fn mint_right(
    root: &KeyPair,
    resource: &str,
    operation: &str,
) -> Result<Vec<u8>, CapabilityError> {
    let tok = biscuit!(
        r#"right({resource}, {operation});"#,
        resource = resource,
        operation = operation,
    )
    .build(root)
    .map_err(|e| CapabilityError::Biscuit(e.to_string()))?;
    tok.to_vec()
        .map_err(|e| CapabilityError::Biscuit(e.to_string()))
}

/// Parse token bytes and reject any block that **asserts** a `holder` fact.
pub fn parse(bytes: &[u8], root_public: PublicKey) -> Result<Biscuit, CapabilityError> {
    let tok =
        Biscuit::from(bytes, root_public).map_err(|e| CapabilityError::Biscuit(e.to_string()))?;
    reject_holder_facts(&tok)?;
    Ok(tok)
}

/// Append `check if holder($fp), $fp == "<fp>";`. Cannot widen.
pub fn append_holder_check(tok: &Biscuit, fp: &str) -> Result<Vec<u8>, CapabilityError> {
    let next = tok
        .append(block!(
            r#"check if holder($fp), $fp == {fp};"#,
            fp = fp,
        ))
        .map_err(|e| CapabilityError::Biscuit(e.to_string()))?;
    next.to_vec()
        .map_err(|e| CapabilityError::Biscuit(e.to_string()))
}

/// Verify the authority chain and evaluate Datalog.
///
/// When `holder_fp` is `Some`, the verifier injects `holder("<fp>")` — the
/// token must not have asserted that fact. Missing injection fails closed if
/// the token carries a holder check.
pub fn authorize(
    bytes: &[u8],
    root_public: PublicKey,
    holder_fp: Option<&str>,
    resource: &str,
    operation: &str,
) -> Result<(), CapabilityError> {
    let tok = parse(bytes, root_public)?;
    let mut built = match holder_fp {
        Some(fp) => authorizer!(
            r#"
            holder({fp});
            allow if right({resource}, {operation});
            "#,
            fp = fp,
            resource = resource,
            operation = operation,
        )
        .build(&tok)
        .map_err(|e| CapabilityError::Biscuit(e.to_string()))?,
        None => authorizer!(
            r#"
            allow if right({resource}, {operation});
            "#,
            resource = resource,
            operation = operation,
        )
        .build(&tok)
        .map_err(|e| CapabilityError::Biscuit(e.to_string()))?,
    };
    built
        .authorize()
        .map(|_| ())
        .map_err(|e| CapabilityError::Biscuit(e.to_string()))
}

/// True when any block **asserts** `holder(...)` rather than checking it.
fn reject_holder_facts(tok: &Biscuit) -> Result<(), CapabilityError> {
    let src = tok.to_string();
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t.starts_with("check ") || t.starts_with("check if ") {
            continue;
        }
        if t.contains("holder(") {
            return Err(CapabilityError::HolderFact);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blake3_vector() {
        assert_eq!(blake3_hash(b""), EMPTY_BLAKE3);
    }

    #[test]
    fn holder_fp_matches_identikey_auth() {
        let pub_bytes = [0x11u8; 32];
        let fp = holder_fingerprint(&pub_bytes).unwrap();
        let auth = ClassicalPublicKey {
            alg: ClassicalAlg::Ed25519,
            bytes: pub_bytes.to_vec(),
        };
        assert_eq!(&fp, auth.fingerprint().as_bytes());
        assert_ne!(fp, blake3_hash(&pub_bytes));
        assert_eq!(
            hex::encode(fp),
            "082474a2550d241689396cae8be5b2aa8a63e82509b6a5ca4aaf57592e2a74a1"
        );
    }

    #[test]
    fn commit_is_domain_separated() {
        let c = secret_commit(b"example/v1", b"salt", b"secret");
        assert_ne!(c, blake3_hash(b"secret"));
        assert_ne!(c, secret_commit(b"other/v1", b"salt", b"secret"));
        assert_eq!(c.len(), 32);
    }

    #[test]
    fn mint_round_trip() {
        let root = KeyPair::new();
        let bytes = mint_right(&root, "example", "read").unwrap();
        parse(&bytes, root.public()).unwrap();
    }

    #[test]
    fn holder_check_fail_closed() {
        let root = KeyPair::new();
        let fp = "FP";
        let minted = mint_right(&root, "example", "read").unwrap();
        let tok = parse(&minted, root.public()).unwrap();
        let held = append_holder_check(&tok, fp).unwrap();

        authorize(&held, root.public(), Some(fp), "example", "read").unwrap();
        assert!(authorize(&held, root.public(), None, "example", "read").is_err());
    }

    #[test]
    fn tamper_is_rejected() {
        let root = KeyPair::new();
        let mut bad = mint_right(&root, "example", "read").unwrap();
        let i = bad.len() / 2;
        bad[i] ^= 0xff;
        assert!(parse(&bad, root.public()).is_err());
    }

    #[test]
    fn holder_fact_is_rejected() {
        let root = KeyPair::new();
        let tok = biscuit!(r#"holder("FP"); right("example", "read");"#)
            .build(&root)
            .unwrap();
        let bytes = tok.to_vec().unwrap();
        match parse(&bytes, root.public()) {
            Err(CapabilityError::HolderFact) => {}
            other => panic!("expected HolderFact, got {other:?}"),
        }
    }

    #[test]
    fn bearer_round_trip() {
        let root = KeyPair::new();
        let bytes = mint_right(&root, "example", "read").unwrap();
        let header = format!("Bearer {}", encode_bearer(&bytes));
        let back = decode_bearer(&header).unwrap();
        assert_eq!(back, bytes);
        assert!(decode_bearer("Bearer tok_abc").is_err());
    }
}
