//! Keyspace v1 KEK wrap of a 32-byte key.
//!
//! `k = blake3("identikey-keyspace-v1-wrap" || dh || ephemeral || recipient)`.
//! The wrapped key is XChaCha20-Poly1305 under `k`. Ed25519 recipients are
//! converted to X25519 with the RFC 7748 birational map. Post-quantum KEMs
//! are not a v1 wrap.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dcbor::prelude::*;
use ed25519_dalek::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::ShareError;

const WRAP_LABEL: &[u8] = b"identikey-keyspace-v1-wrap";
const ALG_X25519: &str = "x25519-xchacha20poly1305";
const ALG_P256: &str = "p256-xchacha20poly1305";

/// Eight small-order Montgomery u-coordinates, little-endian.
/// The last entry is the non-canonical high-bit encoding of zero.
const SMALL_ORDER: [[u8; 32]; 8] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
];

/// Who a wrap is sealed to. The value is the caller's public key, not the
/// Montgomery point written into a wrap of an Ed25519 identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapPublic {
    /// Native X25519 u-coordinate. Not an Ed25519 key.
    X25519([u8; 32]),
    /// Ed25519 verifying key. The wrap stores the RFC 7748 Montgomery image.
    Ed25519([u8; 32]),
    /// Compressed SEC1 P-256 point, 33 bytes.
    P256([u8; 33]),
}

impl WrapPublic {
    /// Accept an X25519 public key that is not a small-order point.
    pub fn x25519(bytes: [u8; 32]) -> Result<Self, ShareError> {
        if is_small_order(&bytes) {
            return Err(ShareError::RejectedKey);
        }
        Ok(Self::X25519(bytes))
    }

    /// Accept an Ed25519 verifying key whose Montgomery image is not small-order.
    pub fn ed25519(bytes: [u8; 32]) -> Result<Self, ShareError> {
        let point = ed25519_to_x25519(&bytes)?;
        if is_small_order(&point) {
            return Err(ShareError::RejectedKey);
        }
        Ok(Self::Ed25519(bytes))
    }

    /// Accept a compressed P-256 point that is on the curve and not infinity.
    pub fn p256(bytes: [u8; 33]) -> Result<Self, ShareError> {
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| ShareError::RejectedKey)?;
        Ok(Self::P256(bytes))
    }

    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::X25519(_) => "x25519",
            Self::Ed25519(_) => "ed25519",
            Self::P256(_) => "p256",
        }
    }

    pub(crate) fn key_bytes(self) -> Vec<u8> {
        match self {
            Self::X25519(b) | Self::Ed25519(b) => b.to_vec(),
            Self::P256(b) => b.to_vec(),
        }
    }

    pub(crate) fn encapsulation(&self) -> Result<Encapsulation, ShareError> {
        match *self {
            Self::X25519(bytes) => Ok(Encapsulation {
                alg: ALG_X25519,
                recipient: bytes.to_vec(),
            }),
            Self::Ed25519(bytes) => Ok(Encapsulation {
                alg: ALG_X25519,
                recipient: ed25519_to_x25519(&bytes)?.to_vec(),
            }),
            Self::P256(bytes) => Ok(Encapsulation {
                alg: ALG_P256,
                recipient: bytes.to_vec(),
            }),
        }
    }
}

/// Secret that can open a wrap sealed to the matching public key.
pub enum WrapSecret {
    /// Clamped X25519 scalar. Not an Ed25519 seed.
    X25519([u8; 32]),
    /// Ed25519 seed. The X25519 scalar is SHA-512(seed)[..32], then RFC 7748 clamp.
    Ed25519Seed([u8; 32]),
    /// P-256 scalar, 32 bytes, big-endian.
    P256Scalar([u8; 32]),
}

impl Drop for WrapSecret {
    fn drop(&mut self) {
        match self {
            Self::X25519(b) | Self::Ed25519Seed(b) | Self::P256Scalar(b) => b.zeroize(),
        }
    }
}

impl WrapSecret {
    /// Fresh X25519 key.
    pub fn generate_x25519() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::X25519(seed)
    }

    /// Fresh Ed25519 seed.
    pub fn generate_ed25519() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::Ed25519Seed(seed)
    }

    /// Fresh P-256 scalar.
    pub fn generate_p256() -> Result<Self, ShareError> {
        let sk = SecretKey::random(&mut rand::rngs::OsRng);
        let bytes = sk.to_bytes();
        Ok(Self::P256Scalar(bytes.into()))
    }

    /// Public key this secret opens.
    pub fn public(&self) -> Result<WrapPublic, ShareError> {
        match self {
            Self::X25519(seed) => {
                let sk = StaticSecret::from(*seed);
                WrapPublic::x25519(*X25519Public::from(&sk).as_bytes())
            }
            Self::Ed25519Seed(seed) => {
                let sk = SigningKey::from_bytes(seed);
                WrapPublic::ed25519(sk.verifying_key().to_bytes())
            }
            Self::P256Scalar(scalar) => {
                let sk = SecretKey::from_slice(scalar).map_err(|_| ShareError::RejectedKey)?;
                let encoded = sk.public_key().to_encoded_point(true);
                let bytes: [u8; 33] = encoded
                    .as_bytes()
                    .try_into()
                    .map_err(|_| ShareError::RejectedKey)?;
                WrapPublic::p256(bytes)
            }
        }
    }

    fn encapsulation_public(&self) -> Result<Vec<u8>, ShareError> {
        Ok(self.public()?.encapsulation()?.recipient)
    }
}

pub(crate) struct Encapsulation {
    pub alg: &'static str,
    pub recipient: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wrap {
    pub alg: String,
    pub recipient: Vec<u8>,
    pub ephemeral: Vec<u8>,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub epoch: u64,
}

impl Wrap {
    pub fn to_cbor(&self) -> Result<Vec<u8>, ShareError> {
        let mut map = Map::new();
        map.insert("alg", self.alg.as_str());
        map.insert("recipient", CBOR::to_byte_string(&self.recipient));
        map.insert("ephemeral", CBOR::to_byte_string(&self.ephemeral));
        map.insert("nonce", CBOR::to_byte_string(self.nonce));
        map.insert("ciphertext", CBOR::to_byte_string(&self.ciphertext));
        map.insert("epoch", self.epoch);
        Ok(CBOR::from(map).to_cbor_data())
    }
}

/// Seal `dek` to `recipient`. The returned bytes are one keyspace v1 wrap.
pub fn wrap_key(recipient: &WrapPublic, dek: &[u8; 32], epoch: u64) -> Result<Vec<u8>, ShareError> {
    let wrap = seal(recipient, dek, epoch)?;
    wrap.to_cbor()
}

/// Open one wrap. The secret's encapsulation public key must equal `recipient`.
pub fn unwrap_key(secret: &WrapSecret, wrap: &[u8]) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    let parsed = parse_wrap(wrap)?;
    let expected = secret.encapsulation_public()?;
    if parsed.recipient != expected {
        return Err(ShareError::Wrap);
    }
    open_with(secret, &parsed)
}

/// Open `wrap` and seal the same key to `recipient`. The key is wiped before return.
pub fn rewrap_key(
    secret: &WrapSecret,
    wrap: &[u8],
    recipient: &WrapPublic,
    epoch: u64,
) -> Result<Vec<u8>, ShareError> {
    let mut dek = unwrap_key(secret, wrap)?;
    let sealed = wrap_key(recipient, &dek, epoch);
    dek.zeroize();
    sealed
}

pub(crate) fn seal(recipient: &WrapPublic, dek: &[u8; 32], epoch: u64) -> Result<Wrap, ShareError> {
    let enc = recipient.encapsulation()?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    match enc.alg {
        ALG_X25519 => {
            let recipient_bytes: [u8; 32] = enc
                .recipient
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::RejectedKey)?;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let ephemeral_sk = StaticSecret::from(seed);
            seed.zeroize();
            let ephemeral_pk = X25519Public::from(&ephemeral_sk);
            let ciphertext = seal_x25519(
                &ephemeral_sk,
                ephemeral_pk.as_bytes(),
                &recipient_bytes,
                dek,
                &nonce,
            )?;
            Ok(Wrap {
                alg: ALG_X25519.to_string(),
                recipient: enc.recipient,
                ephemeral: ephemeral_pk.as_bytes().to_vec(),
                nonce,
                ciphertext,
                epoch,
            })
        }
        ALG_P256 => seal_p256(&enc.recipient, dek, &nonce, epoch),
        _ => Err(ShareError::Wrap),
    }
}

pub(crate) fn parse_wrap(bytes: &[u8]) -> Result<Wrap, ShareError> {
    let cbor = CBOR::try_from_data(bytes)?;
    let encoded = cbor.to_cbor_data();
    if encoded.as_slice() != bytes {
        return Err(ShareError::Wrap);
    }
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return Err(ShareError::Wrap),
    };
    if map.len() != 6 {
        return Err(ShareError::Wrap);
    }
    let alg: String = map.extract("alg").map_err(|_| ShareError::Wrap)?;
    if alg != ALG_X25519 && alg != ALG_P256 {
        return Err(ShareError::Wrap);
    }
    let recipient: ByteString = map.extract("recipient").map_err(|_| ShareError::Wrap)?;
    let ephemeral: ByteString = map.extract("ephemeral").map_err(|_| ShareError::Wrap)?;
    let nonce_bs: ByteString = map.extract("nonce").map_err(|_| ShareError::Wrap)?;
    let ciphertext: ByteString = map.extract("ciphertext").map_err(|_| ShareError::Wrap)?;
    let epoch: u64 = map.extract("epoch").map_err(|_| ShareError::Wrap)?;
    let nonce: [u8; 24] = nonce_bs.as_ref().try_into().map_err(|_| ShareError::Wrap)?;
    let recipient = recipient.as_ref().to_vec();
    let ephemeral = ephemeral.as_ref().to_vec();
    match alg.as_str() {
        ALG_X25519 => {
            if recipient.len() != 32 || ephemeral.len() != 32 {
                return Err(ShareError::Wrap);
            }
            let r: [u8; 32] = recipient
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::Wrap)?;
            let e: [u8; 32] = ephemeral
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::Wrap)?;
            if is_small_order(&r) || is_small_order(&e) {
                return Err(ShareError::Wrap);
            }
        }
        ALG_P256 => {
            if recipient.len() != 33 || ephemeral.len() != 33 {
                return Err(ShareError::Wrap);
            }
            PublicKey::from_sec1_bytes(&recipient).map_err(|_| ShareError::Wrap)?;
            PublicKey::from_sec1_bytes(&ephemeral).map_err(|_| ShareError::Wrap)?;
        }
        _ => return Err(ShareError::Wrap),
    }
    Ok(Wrap {
        alg,
        recipient,
        ephemeral,
        nonce,
        ciphertext: ciphertext.as_ref().to_vec(),
        epoch,
    })
}

pub(crate) fn open_with(
    secret: &WrapSecret,
    wrap: &Wrap,
) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    let mut key = match (secret, wrap.alg.as_str()) {
        (WrapSecret::X25519(scalar), ALG_X25519) => {
            let recipient: [u8; 32] = wrap
                .recipient
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::Wrap)?;
            let ephemeral: [u8; 32] = wrap
                .ephemeral
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::Wrap)?;
            let sk = StaticSecret::from(*scalar);
            dh_kdf_x25519(&sk, &ephemeral, &recipient)?
        }
        (WrapSecret::Ed25519Seed(seed), ALG_X25519) => {
            let recipient: [u8; 32] = wrap
                .recipient
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::Wrap)?;
            let ephemeral: [u8; 32] = wrap
                .ephemeral
                .as_slice()
                .try_into()
                .map_err(|_| ShareError::Wrap)?;
            let scalar = ed25519_seed_to_x25519(seed);
            let sk = StaticSecret::from(scalar);
            dh_kdf_x25519(&sk, &ephemeral, &recipient)?
        }
        (WrapSecret::P256Scalar(scalar), ALG_P256) => {
            dh_kdf_p256(scalar, &wrap.ephemeral, &wrap.recipient)?
        }
        _ => return Err(ShareError::Wrap),
    };
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut plain = cipher
        .decrypt(XNonce::from_slice(&wrap.nonce), wrap.ciphertext.as_slice())
        .map_err(|_| ShareError::Wrap)?;
    key.zeroize();
    if plain.len() != 32 {
        plain.zeroize();
        return Err(ShareError::Wrap);
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&plain);
    plain.zeroize();
    Ok(dek)
}

fn seal_x25519(
    ephemeral_sk: &StaticSecret,
    ephemeral_pub: &[u8; 32],
    recipient: &[u8; 32],
    dek: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, ShareError> {
    if is_small_order(recipient) {
        return Err(ShareError::RejectedKey);
    }
    let their = X25519Public::from(*recipient);
    let shared = ephemeral_sk.diffie_hellman(&their);
    if !shared.was_contributory() {
        return Err(ShareError::Wrap);
    }
    let mut dh = *shared.as_bytes();
    if dh == [0u8; 32] {
        dh.zeroize();
        return Err(ShareError::Wrap);
    }
    let mut key = wrap_kdf(&dh, ephemeral_pub, recipient);
    dh.zeroize();
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), dek.as_slice())
        .map_err(|_| ShareError::Wrap)?;
    key.zeroize();
    Ok(ciphertext)
}

fn seal_p256(
    recipient: &[u8],
    dek: &[u8; 32],
    nonce: &[u8; 24],
    epoch: u64,
) -> Result<Wrap, ShareError> {
    let their = PublicKey::from_sec1_bytes(recipient).map_err(|_| ShareError::RejectedKey)?;
    let ephemeral_sk = SecretKey::random(&mut rand::rngs::OsRng);
    let ephemeral_pub = ephemeral_sk.public_key().to_encoded_point(true);
    let ephemeral = ephemeral_pub.as_bytes().to_vec();
    let mut key = {
        let shared =
            p256::ecdh::diffie_hellman(ephemeral_sk.to_nonzero_scalar(), their.as_affine());
        let raw = shared.raw_secret_bytes();
        if raw.as_slice() == [0u8; 32] {
            return Err(ShareError::Wrap);
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(raw.as_slice());
        let key = wrap_kdf(&dh, &ephemeral, recipient);
        dh.zeroize();
        key
    };
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), dek.as_slice())
        .map_err(|_| ShareError::Wrap)?;
    key.zeroize();
    Ok(Wrap {
        alg: ALG_P256.to_string(),
        recipient: recipient.to_vec(),
        ephemeral,
        nonce: *nonce,
        ciphertext,
        epoch,
    })
}

fn dh_kdf_x25519(
    sk: &StaticSecret,
    ephemeral_or_peer: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    if is_small_order(ephemeral_or_peer) || is_small_order(recipient) {
        return Err(ShareError::Wrap);
    }
    let their = X25519Public::from(*ephemeral_or_peer);
    let shared = sk.diffie_hellman(&their);
    if !shared.was_contributory() {
        return Err(ShareError::Wrap);
    }
    let mut dh = *shared.as_bytes();
    if dh == [0u8; 32] {
        dh.zeroize();
        return Err(ShareError::Wrap);
    }
    let key = wrap_kdf(&dh, ephemeral_or_peer, recipient);
    dh.zeroize();
    Ok(key)
}

fn dh_kdf_p256(
    scalar: &[u8; 32],
    ephemeral: &[u8],
    recipient: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    let sk = SecretKey::from_slice(scalar).map_err(|_| ShareError::Wrap)?;
    let their = PublicKey::from_sec1_bytes(ephemeral).map_err(|_| ShareError::Wrap)?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), their.as_affine());
    let raw = shared.raw_secret_bytes();
    if raw.as_slice() == [0u8; 32] {
        return Err(ShareError::Wrap);
    }
    let mut dh = [0u8; 32];
    dh.copy_from_slice(raw.as_slice());
    let key = wrap_kdf(&dh, ephemeral, recipient);
    dh.zeroize();
    Ok(key)
}

fn wrap_kdf(dh: &[u8; 32], ephemeral: &[u8], recipient: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut material =
        Vec::with_capacity(WRAP_LABEL.len() + 32 + ephemeral.len() + recipient.len());
    material.extend_from_slice(WRAP_LABEL);
    material.extend_from_slice(dh);
    material.extend_from_slice(ephemeral);
    material.extend_from_slice(recipient);
    let hash = blake3::hash(&material);
    material.zeroize();
    Zeroizing::new(*hash.as_bytes())
}

pub(crate) fn is_small_order(point: &[u8; 32]) -> bool {
    SMALL_ORDER.iter().any(|bad| bad == point)
}

fn ed25519_to_x25519(pk: &[u8; 32]) -> Result<[u8; 32], ShareError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| ShareError::RejectedKey)?;
    Ok(vk.to_montgomery().to_bytes())
}

fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_roundtrip_and_rewrap() {
        let alice = WrapSecret::generate_x25519();
        let bob = WrapSecret::generate_x25519();
        let alice_pk = alice.public().unwrap();
        let bob_pk = bob.public().unwrap();
        let dek = [7u8; 32];
        let wrap = wrap_key(&alice_pk, &dek, 0).unwrap();
        let opened = unwrap_key(&alice, &wrap).unwrap();
        assert_eq!(opened.as_slice(), &dek);
        let for_bob = rewrap_key(&alice, &wrap, &bob_pk, 1).unwrap();
        assert!(unwrap_key(&bob, &for_bob).unwrap().as_slice() == dek);
        assert!(unwrap_key(&alice, &for_bob).is_err());
        assert!(!for_bob.windows(32).any(|w| w == dek));
    }

    #[test]
    fn ed25519_seed_opens_its_montgomery_wrap() {
        let secret = WrapSecret::generate_ed25519();
        let public = secret.public().unwrap();
        let dek = [9u8; 32];
        let wrap = wrap_key(&public, &dek, 4).unwrap();
        assert_eq!(unwrap_key(&secret, &wrap).unwrap().as_slice(), &dek);
    }

    #[test]
    fn p256_roundtrip() {
        let secret = WrapSecret::generate_p256().unwrap();
        let public = secret.public().unwrap();
        let dek = [3u8; 32];
        let wrap = wrap_key(&public, &dek, 2).unwrap();
        assert_eq!(unwrap_key(&secret, &wrap).unwrap().as_slice(), &dek);
    }

    #[test]
    fn small_order_and_unknown_alg_fail() {
        assert!(WrapPublic::x25519([0u8; 32]).is_err());
        let mut map = Map::new();
        map.insert("alg", "mlkem768");
        map.insert("recipient", CBOR::to_byte_string([1u8; 32]));
        map.insert("ephemeral", CBOR::to_byte_string([2u8; 32]));
        map.insert("nonce", CBOR::to_byte_string([3u8; 24]));
        map.insert("ciphertext", CBOR::to_byte_string([4u8; 48]));
        map.insert("epoch", 0_u64);
        let bytes = CBOR::from(map).to_cbor_data();
        assert!(matches!(parse_wrap(&bytes), Err(ShareError::Wrap)));
    }
}
