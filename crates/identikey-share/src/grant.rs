//! Signed statement that a share's current access set is authorized.
//!
//! Ed25519 is required. ML-DSA (44, 65, or 87) is optional and, when present,
//! is verified. A verifier may demand it. The signature covers the content id
//! and the access commitment, so a rewrap needs a new grant. This is not a
//! holder class and not a Biscuit.

use dcbor::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fips204::traits::{SerDes, Signer as _, Verifier as _};

use crate::error::ShareError;
use crate::share::Share;

const GRANT_DOMAIN: &[u8] = b"identikey-share-v1-grant\n";

/// Which access set the signer claims to authorize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    /// Direct KEK wraps only.
    Direct,
    /// Recrypt capsules only.
    Recrypt,
    /// At least one of each.
    Either,
}

impl AccessMode {
    fn tag(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Recrypt => "recrypt",
            Self::Either => "either",
        }
    }

    fn from_tag(tag: &str) -> Result<Self, ShareError> {
        match tag {
            "direct" => Ok(Self::Direct),
            "recrypt" => Ok(Self::Recrypt),
            "either" => Ok(Self::Either),
            _ => Err(ShareError::Mode),
        }
    }
}

/// How much post-quantum assurance the verifier demands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPolicy {
    /// A missing ML-DSA signature is acceptable. A present one must verify.
    Optional,
    /// Reject a classical-only grant.
    Required,
}

/// ML-DSA parameter set. 87 is the ~4KB public key. Smaller sets are allowed
/// so a wallet that already holds 44 or 65 can sign without a second key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAlg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl PqAlg {
    fn tag(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }

    fn from_tag(tag: &str) -> Result<Self, ShareError> {
        match tag {
            "ml-dsa-44" => Ok(Self::MlDsa44),
            "ml-dsa-65" => Ok(Self::MlDsa65),
            "ml-dsa-87" => Ok(Self::MlDsa87),
            _ => Err(ShareError::Signature),
        }
    }
}

enum PqSecret {
    MlDsa44(Box<fips204::ml_dsa_44::PrivateKey>),
    MlDsa65(Box<fips204::ml_dsa_65::PrivateKey>),
    MlDsa87(Box<fips204::ml_dsa_87::PrivateKey>),
}

/// Ed25519 grant signer. Attach ML-DSA only when the signer has a PQ key.
pub struct GrantKeys {
    ed25519: SigningKey,
    pq: Option<(PqAlg, Vec<u8>, PqSecret)>,
}

impl GrantKeys {
    /// Ed25519-only signer from a seed.
    pub fn from_ed25519_seed(seed: [u8; 32]) -> Self {
        Self {
            ed25519: SigningKey::from_bytes(&seed),
            pq: None,
        }
    }

    /// Generate an ML-DSA key and keep it on this signer.
    pub fn with_pq(mut self, alg: PqAlg) -> Result<Self, ShareError> {
        let (tag_alg, pk, secret) = match alg {
            PqAlg::MlDsa44 => {
                let (pk, sk) =
                    fips204::ml_dsa_44::try_keygen().map_err(|_| ShareError::Signature)?;
                (
                    alg,
                    pk.into_bytes().to_vec(),
                    PqSecret::MlDsa44(Box::new(sk)),
                )
            }
            PqAlg::MlDsa65 => {
                let (pk, sk) =
                    fips204::ml_dsa_65::try_keygen().map_err(|_| ShareError::Signature)?;
                (
                    alg,
                    pk.into_bytes().to_vec(),
                    PqSecret::MlDsa65(Box::new(sk)),
                )
            }
            PqAlg::MlDsa87 => {
                let (pk, sk) =
                    fips204::ml_dsa_87::try_keygen().map_err(|_| ShareError::Signature)?;
                (
                    alg,
                    pk.into_bytes().to_vec(),
                    PqSecret::MlDsa87(Box::new(sk)),
                )
            }
        };
        self.pq = Some((tag_alg, pk, secret));
        Ok(self)
    }

    /// Ed25519 verifying key.
    pub fn ed25519_public(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }
}

/// A grant bound to one share content id and one access commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessGrant {
    content: [u8; 32],
    commitment: [u8; 32],
    epoch: u64,
    mode: AccessMode,
    signer: [u8; 32],
    pq_alg: Option<PqAlg>,
    pq_pk: Option<Vec<u8>>,
    ed25519_sig: [u8; 64],
    ml_dsa_sig: Option<Vec<u8>>,
}

impl AccessGrant {
    /// Canonical dCBOR, signatures included.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ShareError> {
        Ok(CBOR::from(self.to_map()?).to_cbor_data())
    }

    /// Parse a canonical grant. Does not check the signature.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ShareError> {
        let cbor = CBOR::try_from_data(bytes)?;
        if cbor.to_cbor_data().as_slice() != bytes {
            return Err(ShareError::Signature);
        }
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(ShareError::Signature),
        };
        let version: u64 = map.extract("v").map_err(|_| ShareError::Signature)?;
        if version != 1 {
            return Err(ShareError::Signature);
        }
        let content_bs: ByteString = map.extract("content").map_err(|_| ShareError::Signature)?;
        let commitment_bs: ByteString = map
            .extract("commitment")
            .map_err(|_| ShareError::Signature)?;
        let epoch: u64 = map.extract("epoch").map_err(|_| ShareError::Signature)?;
        let mode_tag: String = map.extract("mode").map_err(|_| ShareError::Signature)?;
        let signer_bs: ByteString = map.extract("signer").map_err(|_| ShareError::Signature)?;
        let ed_sig_bs: ByteString = map
            .extract("ed25519-sig")
            .map_err(|_| ShareError::Signature)?;
        let pq_alg = match map.get::<_, String>("pq-alg") {
            Some(tag) => Some(PqAlg::from_tag(&tag)?),
            None => None,
        };
        let pq_pk = map
            .get::<_, ByteString>("pq-pk")
            .map(|bytes| bytes.as_ref().to_vec());
        let ml_dsa_sig = map
            .get::<_, ByteString>("ml-dsa-sig")
            .map(|bytes| bytes.as_ref().to_vec());
        let pq_parts = match (&pq_alg, &pq_pk, &ml_dsa_sig) {
            (None, None, None) => 0,
            (Some(_), Some(pk), Some(sig)) if !pk.is_empty() && !sig.is_empty() => 3,
            _ => return Err(ShareError::Signature),
        };
        if map.len() != 7 + pq_parts {
            return Err(ShareError::Signature);
        }
        let content: [u8; 32] = content_bs
            .as_ref()
            .try_into()
            .map_err(|_| ShareError::Signature)?;
        let commitment: [u8; 32] = commitment_bs
            .as_ref()
            .try_into()
            .map_err(|_| ShareError::Signature)?;
        let signer: [u8; 32] = signer_bs
            .as_ref()
            .try_into()
            .map_err(|_| ShareError::Signature)?;
        let ed25519_sig: [u8; 64] = ed_sig_bs
            .as_ref()
            .try_into()
            .map_err(|_| ShareError::Signature)?;
        Ok(Self {
            content,
            commitment,
            epoch,
            mode: AccessMode::from_tag(&mode_tag)?,
            signer,
            pq_alg,
            pq_pk,
            ed25519_sig,
            ml_dsa_sig,
        })
    }

    fn to_map(&self) -> Result<Map, ShareError> {
        let mut map = self.signed_map()?;
        map.insert("ed25519-sig", CBOR::to_byte_string(self.ed25519_sig));
        if let Some(sig) = &self.ml_dsa_sig {
            map.insert("ml-dsa-sig", CBOR::to_byte_string(sig));
        }
        Ok(map)
    }

    fn signed_map(&self) -> Result<Map, ShareError> {
        let mut map = Map::new();
        map.insert("v", 1_u64);
        map.insert("content", CBOR::to_byte_string(self.content));
        map.insert("commitment", CBOR::to_byte_string(self.commitment));
        map.insert("epoch", self.epoch);
        map.insert("mode", self.mode.tag());
        map.insert("signer", CBOR::to_byte_string(self.signer));
        if let (Some(alg), Some(pk)) = (self.pq_alg, self.pq_pk.as_ref()) {
            map.insert("pq-alg", alg.tag());
            map.insert("pq-pk", CBOR::to_byte_string(pk));
        }
        Ok(map)
    }

    fn message(&self) -> Result<Vec<u8>, ShareError> {
        let body = CBOR::from(self.signed_map()?).to_cbor_data();
        let mut message = Vec::with_capacity(GRANT_DOMAIN.len() + body.len());
        message.extend_from_slice(GRANT_DOMAIN);
        message.extend_from_slice(&body);
        Ok(message)
    }
}

/// Sign `share`'s content id and access commitment.
pub fn grant_access(
    share: &Share,
    keys: &GrantKeys,
    mode: AccessMode,
) -> Result<AccessGrant, ShareError> {
    match mode {
        AccessMode::Direct => {
            if !share.has_direct() || share.has_recrypt() {
                return Err(ShareError::Mode);
            }
        }
        AccessMode::Recrypt => {
            if share.has_direct() || !share.has_recrypt() {
                return Err(ShareError::Mode);
            }
        }
        AccessMode::Either => {
            if !share.has_direct() || !share.has_recrypt() {
                return Err(ShareError::Mode);
            }
        }
    }
    let (pq_alg, pq_pk, ml_dsa_sig) = match &keys.pq {
        None => (None, None, None),
        Some((alg, pk, secret)) => {
            let unsigned = AccessGrant {
                content: share.content_id(),
                commitment: share.access_commitment()?,
                epoch: share.epoch(),
                mode,
                signer: keys.ed25519_public(),
                pq_alg: Some(*alg),
                pq_pk: Some(pk.clone()),
                ed25519_sig: [0u8; 64],
                ml_dsa_sig: None,
            };
            let message = unsigned.message()?;
            let sig = sign_pq(secret, &message)?;
            (Some(*alg), Some(pk.clone()), Some(sig))
        }
    };
    let mut grant = AccessGrant {
        content: share.content_id(),
        commitment: share.access_commitment()?,
        epoch: share.epoch(),
        mode,
        signer: keys.ed25519_public(),
        pq_alg,
        pq_pk,
        ed25519_sig: [0u8; 64],
        ml_dsa_sig,
    };
    let message = grant.message()?;
    grant.ed25519_sig = keys.ed25519.sign(&message).to_bytes();
    Ok(grant)
}

/// Check the signature and that the grant commits to `share`.
pub fn verify_grant(
    grant: &AccessGrant,
    share: &Share,
    policy: PqPolicy,
) -> Result<(), ShareError> {
    if grant.content != share.content_id()
        || grant.commitment != share.access_commitment()?
        || grant.epoch != share.epoch()
    {
        return Err(ShareError::GrantMismatch);
    }
    match grant.mode {
        AccessMode::Direct if share.has_direct() && !share.has_recrypt() => {}
        AccessMode::Recrypt if !share.has_direct() && share.has_recrypt() => {}
        AccessMode::Either if share.has_direct() && share.has_recrypt() => {}
        _ => return Err(ShareError::Mode),
    }
    let message = grant.message()?;
    let vk = VerifyingKey::from_bytes(&grant.signer).map_err(|_| ShareError::Signature)?;
    let signature = Signature::from_bytes(&grant.ed25519_sig);
    vk.verify_strict(&message, &signature)
        .map_err(|_| ShareError::Signature)?;
    match (&grant.ml_dsa_sig, &grant.pq_alg, &grant.pq_pk) {
        (None, None, None) => {
            if policy == PqPolicy::Required {
                return Err(ShareError::PqRequired);
            }
        }
        (Some(sig), Some(alg), Some(pk)) => verify_pq(*alg, pk, &message, sig)?,
        _ => return Err(ShareError::Signature),
    }
    Ok(())
}

fn sign_pq(secret: &PqSecret, message: &[u8]) -> Result<Vec<u8>, ShareError> {
    match secret {
        PqSecret::MlDsa44(sk) => sk
            .try_sign(message, &[])
            .map(|sig| sig.to_vec())
            .map_err(|_| ShareError::Signature),
        PqSecret::MlDsa65(sk) => sk
            .try_sign(message, &[])
            .map(|sig| sig.to_vec())
            .map_err(|_| ShareError::Signature),
        PqSecret::MlDsa87(sk) => sk
            .try_sign(message, &[])
            .map(|sig| sig.to_vec())
            .map_err(|_| ShareError::Signature),
    }
}

fn verify_pq(alg: PqAlg, pk: &[u8], message: &[u8], sig: &[u8]) -> Result<(), ShareError> {
    macro_rules! verify_with {
        ($module:path) => {{
            use $module as m;
            let pk_bytes: [u8; m::PK_LEN] = pk.try_into().map_err(|_| ShareError::Signature)?;
            let sig_bytes: [u8; m::SIG_LEN] = sig.try_into().map_err(|_| ShareError::Signature)?;
            let public =
                m::PublicKey::try_from_bytes(pk_bytes).map_err(|_| ShareError::Signature)?;
            if public.verify(message, &sig_bytes, &[]) {
                Ok(())
            } else {
                Err(ShareError::Signature)
            }
        }};
    }
    match alg {
        PqAlg::MlDsa44 => verify_with!(fips204::ml_dsa_44),
        PqAlg::MlDsa65 => verify_with!(fips204::ml_dsa_65),
        PqAlg::MlDsa87 => verify_with!(fips204::ml_dsa_87),
    }
}
