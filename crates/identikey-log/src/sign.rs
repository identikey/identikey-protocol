//! Signing and verification.
//!
//! What is signed: the **canonical unsigned envelope bytes** — exactly the
//! bytes `content_hash` digests. Signatures are detached attributes and are
//! excluded from their own input, so a second author can co-sign the same op
//! without perturbing anyone else's signature or the op's identity.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::{
    codec,
    error::{LogError, Result},
    op::{Hash32, Op, SigAlg, Signature, SignedOp},
};

/// An Ed25519 author identity.
///
/// The op's `actor` field is the raw 32-byte Ed25519 public key.
pub struct Author {
    key: SigningKey,
}

impl Author {
    /// Build an author from a 32-byte RFC 8032 seed.
    ///
    /// Deterministic: the same seed always yields the same public key and, for
    /// a given message, the same signature. That is what makes cross-runtime
    /// golden vectors possible at all.
    pub fn from_seed(seed: &Hash32) -> Self { Self { key: SigningKey::from_bytes(seed) } }

    /// The 32-byte public key, i.e. the value that goes in `Op::actor`.
    pub fn actor(&self) -> Hash32 { self.key.verifying_key().to_bytes() }

    /// Sign an op, returning it with one `ed25519` signature attached.
    pub fn sign(&self, op: Op) -> Result<SignedOp> {
        let bytes = codec::encode(&op)?;
        let sig = self.key.sign(&bytes);
        Ok(SignedOp::new(
            op,
            vec![Signature { alg: SigAlg::Ed25519, value: sig.to_bytes().to_vec() }],
        ))
    }

    /// Co-sign an already-signed op, appending a second `ed25519` signature.
    pub fn counter_sign(&self, mut signed: SignedOp) -> Result<SignedOp> {
        let bytes = codec::encode(&signed.op)?;
        let sig = self.key.sign(&bytes);
        signed
            .signatures
            .push(Signature { alg: SigAlg::Ed25519, value: sig.to_bytes().to_vec() });
        Ok(signed)
    }
}

/// Verify every attached signature against the op's own `actor`.
///
/// Policy (inherited from the envelope signature model): **all present must
/// verify**, but there is no minimum count — an Ed25519-only op is valid. An
/// op with *zero* signatures is rejected here with [`LogError::Unsigned`]
/// rather than silently passing; callers that genuinely want unsigned input
/// should not be calling a verifier.
pub fn verify(signed: &SignedOp) -> Result<()> { verify_with_pq_key(signed, None) }

/// As [`verify`], but with the actor's ML-DSA-87 public key supplied out of
/// band.
///
/// The op's core map has room for exactly one key — the Ed25519 `actor` — so
/// there is nowhere on the wire for a PQ public key to live. That is a
/// deliberate size decision (an ML-DSA-87 public key is 2592 bytes, roughly
/// twenty times the whole rest of a typical op), and it means PQ verification
/// is only possible when the caller can resolve `actor` to a PQ key through
/// some directory of its own. An ML-DSA-87 signature with no key to check it
/// against is an error, never a pass.
pub fn verify_with_pq_key(signed: &SignedOp, pq_public_key: Option<&[u8]>) -> Result<()> {
    if !signed.is_signed() {
        return Err(LogError::Unsigned);
    }
    let bytes = codec::encode(&signed.op)?;
    for sig in &signed.signatures {
        match sig.alg {
            SigAlg::Ed25519 => verify_ed25519(&signed.op.actor, &bytes, &sig.value)?,
            SigAlg::MlDsa87 => {
                let pk = pq_public_key.ok_or(LogError::PqDangling)?;
                verify_ml_dsa_87(pk, &bytes, &sig.value)?
            }
        }
    }
    Ok(())
}

/// Verify raw Ed25519 over a message.
pub fn verify_ed25519(public_key: &Hash32, msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|_| LogError::InvalidKey("ed25519"))?;
    let sig: [u8; 64] =
        sig.try_into().map_err(|_| LogError::InvalidSig("ed25519"))?;
    vk.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| LogError::BadSignature)
}

/// Decode and verify in one step, returning the op and its `content_hash`.
pub fn decode_and_verify(bytes: &[u8]) -> Result<(SignedOp, Hash32)> {
    let signed = codec::decode(bytes)?;
    verify(&signed)?;
    let hash = codec::content_hash(&signed.op)?;
    Ok((signed, hash))
}

// ---------------------------------------------------------------------------
// Post-quantum seam
// ---------------------------------------------------------------------------

/// ML-DSA-87 (FIPS 204) verification — the whole PQ surface, deliberately one
/// function.
///
/// The seam exists so the choice of PQ crate stays swappable and so exactly one
/// call site has to get the FIPS 204 mode right. **Pure** mode with the empty
/// context string (`verify(msg, sig, &[])`) — never the `*_internal` entry
/// points, which skip the domain separator and fail pure-mode vectors.
#[cfg(feature = "ml-dsa")]
pub fn verify_ml_dsa_87(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use fips204::{
        ml_dsa_87,
        traits::{SerDes as _, Verifier as _},
    };

    let pk_bytes: &[u8; ml_dsa_87::PK_LEN] =
        public_key.try_into().map_err(|_| LogError::InvalidKey("ml-dsa-87"))?;
    let sig_bytes: &[u8; ml_dsa_87::SIG_LEN] =
        sig.try_into().map_err(|_| LogError::InvalidSig("ml-dsa-87"))?;
    let pk = ml_dsa_87::PublicKey::try_from_bytes(*pk_bytes)
        .map_err(|_| LogError::InvalidKey("ml-dsa-87"))?;
    // The trailing `&[]` is the empty context string. Not optional.
    if pk.verify(msg, sig_bytes, &[]) {
        Ok(())
    } else {
        Err(LogError::BadSignature)
    }
}

#[cfg(not(feature = "ml-dsa"))]
pub fn verify_ml_dsa_87(_public_key: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<()> {
    Err(LogError::PqUnavailable)
}
