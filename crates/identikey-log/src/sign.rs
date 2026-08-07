//! Signing and verification, on Gordian Envelope's digest tree.
//!
//! # What is signed
//!
//! The op's unsigned envelope is **wrapped**, and the signature covers the
//! wrapper's SHA-256 digest. Because a Gordian digest is a Merkle tree over
//! subject and assertions — each assertion digested independently — this has
//! two consequences that the pre-Gordian, sign-the-literal-bytes design could
//! not have:
//!
//! 1. **Elision preserves the signature.** Replacing an assertion with its own
//!    digest leaves every enclosing digest unchanged, so a redacted op still
//!    verifies against the author's key. See `tests/elision.rs`.
//! 2. **Tampering still breaks it.** Changing an assertion changes its digest,
//!    which changes the wrapper's, which the signature covers. Elision and
//!    substitution are not the same operation, and the digest tree tells them
//!    apart.
//!
//! Wrapping is what makes the signature cover the *assertions* rather than
//! just the subject. `Envelope::add_signature` alone signs
//! `subject().digest()`; on an unwrapped op that would leave `deps`, `nacks`,
//! `target-fp` and `timestamp` outside the signed region — a silent regression
//! against the format this replaces, which signed all of them.

use bc_components::{
    Ed25519PrivateKey, Ed25519PublicKey, Signature, Signer, SigningPrivateKey,
    SigningPublicKey, Verifier,
};
use bc_envelope::prelude::*;

use crate::{
    codec,
    error::{LogError, Result},
    op::{Hash32, Op, SignedOp},
};

/// An Ed25519 author identity.
///
/// The op's `actor` field is the raw 32-byte Ed25519 public key.
pub struct Author {
    key: SigningPrivateKey,
}

impl Author {
    /// Build an author from a 32-byte RFC 8032 seed.
    ///
    /// Deterministic: the same seed always yields the same public key and, for
    /// a given message, the same signature. That is what makes cross-runtime
    /// golden vectors possible at all — and it survives the move to Gordian,
    /// because `bc-components` signs Ed25519 through the same `ed25519-dalek`
    /// 2.x this crate used directly before.
    pub fn from_seed(seed: &Hash32) -> Self {
        Self { key: SigningPrivateKey::new_ed25519(Ed25519PrivateKey::from_data(*seed)) }
    }

    /// The 32-byte public key, i.e. the value that goes in `Op::actor`.
    pub fn actor(&self) -> Hash32 {
        match self.key.public_key() {
            Ok(SigningPublicKey::Ed25519(pk)) => *pk.data(),
            // `from_seed` only ever builds an Ed25519 key.
            _ => unreachable!("Author is always Ed25519"),
        }
    }

    /// The underlying signer, for callers that want to drive `Envelope`
    /// directly (elision, inclusion proofs, salted assertions).
    pub fn signer(&self) -> &SigningPrivateKey { &self.key }

    /// Wrap an envelope and sign it — the operation `sign` performs on an op,
    /// exposed for callers working at the envelope layer.
    pub fn sign_envelope(&self, envelope: &Envelope) -> Envelope {
        envelope.sign(&self.key)
    }

    /// Sign an op, returning it with one signature attached.
    pub fn sign(&self, op: Op) -> Result<SignedOp> {
        let signature = self.raw_sign(&codec::to_envelope(&op)?)?;
        Ok(SignedOp::new(op, vec![signature]))
    }

    /// Co-sign an already-signed op, appending a second signature.
    ///
    /// Additive: every signature covers the same wrapped unsigned envelope, so
    /// co-signing perturbs neither the existing signatures nor `content_hash`.
    pub fn counter_sign(&self, mut signed: SignedOp) -> Result<SignedOp> {
        let signature = self.raw_sign(&codec::to_envelope(&signed.op)?)?;
        signed.signatures.push(signature);
        Ok(signed)
    }

    /// The signature an `Envelope::sign` would attach, without building the
    /// signed envelope: sign the wrapper's digest.
    fn raw_sign(&self, unsigned: &Envelope) -> Result<Signature> {
        let digest = *unsigned.wrap().digest().data();
        self.key
            .sign(&(&digest as &dyn AsRef<[u8]>))
            .map_err(|e| LogError::Envelope(e.to_string()))
    }
}

/// Verify every attached signature against the op's own `actor`.
///
/// Policy: **all present must verify**, but there is no minimum count. An op
/// with *zero* signatures is rejected with [`LogError::Unsigned`] rather than
/// silently passing; callers that genuinely want unsigned input should not be
/// calling a verifier.
pub fn verify(signed: &SignedOp) -> Result<()> { verify_with_pq_key(signed, None) }

/// As [`verify`], but with the actor's post-quantum public key supplied out of
/// band.
///
/// The op's core map has room for exactly one key — the Ed25519 `actor` — so
/// there is nowhere on the wire for an ML-DSA public key to live. That is a
/// deliberate size decision (an ML-DSA-87 public key is 2592 bytes, roughly
/// twenty times the whole rest of a typical op), and it means PQ verification
/// is only possible when the caller can resolve `actor` to a PQ key through
/// some directory of its own. A PQ signature with no key to check it against
/// is an error, never a pass.
pub fn verify_with_pq_key(
    signed: &SignedOp,
    pq_public_key: Option<&SigningPublicKey>,
) -> Result<()> {
    if !signed.is_signed() {
        return Err(LogError::Unsigned);
    }
    let digest = *codec::to_envelope(&signed.op)?.wrap().digest().data();
    verify_signatures(&signed.signatures, &digest, &signed.op.actor, pq_public_key)
}

/// Verify an arbitrary — possibly partially elided — signed envelope against
/// an actor key.
///
/// This is the honest verification entry point once elision is in play: the
/// message is read off the envelope's own digest tree rather than
/// reconstructed from a decoded [`Op`], so a redacted assertion (which a
/// logical round trip cannot reproduce) is verified exactly as the author
/// signed it.
///
/// Policy matches [`verify`]: every signature present must check out, and an
/// envelope with none is [`LogError::Unsigned`].
pub fn verify_envelope(envelope: &Envelope, actor: &Hash32) -> Result<()> {
    verify_envelope_with_pq_key(envelope, actor, None)
}

/// As [`verify_envelope`], with an out-of-band post-quantum public key.
pub fn verify_envelope_with_pq_key(
    envelope: &Envelope,
    actor: &Hash32,
    pq_public_key: Option<&SigningPublicKey>,
) -> Result<()> {
    let signatures = signatures_of(envelope)?;
    if signatures.is_empty() {
        return Err(LogError::Unsigned);
    }
    // `subject()` of a signed op is the wrapped unsigned envelope; its digest
    // is precisely what `Envelope::sign` signed.
    let digest = *envelope.subject().digest().data();
    verify_signatures(&signatures, &digest, actor, pq_public_key)
}

/// The `'signed'` objects carried by an envelope, in wire order.
pub fn signatures_of(envelope: &Envelope) -> Result<Vec<Signature>> {
    Ok(codec::from_envelope(envelope)?.signatures)
}

#[allow(unused_variables)]
fn verify_signatures(
    signatures: &[Signature],
    digest: &[u8; 32],
    actor: &Hash32,
    pq_public_key: Option<&SigningPublicKey>,
) -> Result<()> {
    let actor = actor_key(actor)?;
    for sig in signatures {
        let ok = match sig {
            // PQ verification does NOT go through `SigningPublicKey::verify`
            // even when `pqcrypto` is on. It goes through the one seam below,
            // so that native and browser builds run the *same* ML-DSA
            // implementation and a divergence between them is impossible by
            // construction rather than by discipline. The
            // `a_pq_signature_with_no_pq_key_is_rejected_not_ignored` test
            // signs with pqcrypto-mldsa and verifies with fips204, which makes
            // it a live cross-implementation KAT on every run.
            #[cfg(feature = "pqcrypto")]
            Signature::MLDSA(sig) => {
                let pk = match pq_public_key.ok_or(LogError::PqDangling)? {
                    SigningPublicKey::MLDSA(pk) => pk,
                    _ => return Err(LogError::InvalidKey("ml-dsa-87")),
                };
                if sig.level() != bc_components::MLDSA::MLDSA87 {
                    return Err(LogError::PqUnsupportedLevel(sig.level() as u64));
                }
                verify_ml_dsa_87(pk.as_bytes(), digest, sig.as_bytes()).is_ok()
            }
            _ => actor.verify(sig, digest),
        };
        if !ok {
            return Err(LogError::BadSignature);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-quantum seam
// ---------------------------------------------------------------------------

/// ML-DSA-87 (FIPS 204) verification — the whole PQ surface, deliberately one
/// function.
///
/// The seam exists so the choice of PQ crate stays swappable (Dreamball-y4t.2
/// chose `fips204` 0.4.6 over `ml-dsa` 0.1.1 on measured evidence, and made
/// the decision reversible precisely by keeping it behind this function), and
/// so exactly one call site has to get the FIPS 204 mode right.
///
/// **Pure** mode with the empty context string — `verify(msg, sig, &[])`, i.e.
/// `M' = 0x00 || 0x00 || M`. Never the `*_internal` entry points: they skip the
/// domain separator and fail this project's golden vectors, which are FIPS 204
/// final pure-mode with an empty context.
///
/// `fips204` is pure Rust and `no_std`-capable, which is the reason it, and
/// not `pqcrypto-mldsa`, is the implementation here: `pqcrypto-mldsa` is a
/// PQClean C binding that cannot be built for `wasm32-unknown-unknown`. This
/// function is therefore available in **every** build configuration, including
/// the browser one, with or without the `pqcrypto` feature.
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

/// The actor field, as a key something can be verified against.
pub fn actor_key(actor: &Hash32) -> Result<SigningPublicKey> {
    Ok(SigningPublicKey::from_ed25519(Ed25519PublicKey::from_data(*actor)))
}

/// Decode and verify in one step, returning the op and its `content_hash`.
///
/// Note the `content_hash` of an op decoded from a **partially elided**
/// envelope is not the author's `content_hash` — the elided assertions are
/// missing from the bytes it is taken over. `SignedOp::elided` says whether
/// that applies; when it does, take the identity from the unredacted source or
/// from the envelope's `Digest` instead.
pub fn decode_and_verify(bytes: &[u8]) -> Result<(SignedOp, Hash32)> {
    let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
        .map_err(|e| LogError::Envelope(e.to_string()))?;
    let signed = codec::from_envelope(&envelope)?;
    verify_envelope(&envelope, &signed.op.actor)?;
    let hash = codec::content_hash(&signed.op)?;
    Ok((signed, hash))
}
