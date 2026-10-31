//! A payload encrypted under one DEK, with one wrap or capsule per recipient.
//!
//! Adding a recipient re-wraps the DEK. The payload ciphertext stays put.
//! A grant covers this access set. It is not a Biscuit and not a guild holder.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dcbor::prelude::*;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::error::ShareError;
use crate::recrypt::{RecryptCapsule, RecryptKem, RecryptPublic};
use crate::wrap::{self, Wrap, WrapPublic, WrapSecret};

const PAYLOAD_ALG: &str = "xchacha20poly1305";
const PAYLOAD_AAD: &[u8] = b"identikey-share-v1-payload";
const CONTENT_DOMAIN: &[u8] = b"identikey-share-v1-content\n";
const ACCESS_DOMAIN: &[u8] = b"identikey-share-v1-access\n";

/// Ciphertext plus the wraps and capsules that hold its DEK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    epoch: u64,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    wraps: Vec<Wrap>,
    targets: Vec<WrapPublic>,
    recrypt: Vec<RecryptCapsule>,
}

impl Share {
    /// Seal `plaintext` to each direct recipient at `epoch`.
    pub fn seal(
        plaintext: &[u8],
        recipients: &[WrapPublic],
        epoch: u64,
    ) -> Result<Self, ShareError> {
        Self::seal_mixed(plaintext, recipients, &[], &NopKem, epoch)
    }

    /// Seal to direct recipients and PRE recipients. `kem` is used only when
    /// `recrypt` is non-empty.
    pub fn seal_mixed(
        plaintext: &[u8],
        recipients: &[WrapPublic],
        recrypt: &[RecryptPublic],
        kem: &dyn RecryptKem,
        epoch: u64,
    ) -> Result<Self, ShareError> {
        if recipients.is_empty() && recrypt.is_empty() {
            return Err(ShareError::EmptyRecipients);
        }
        reject_duplicate_direct(recipients)?;
        reject_duplicate_recrypt(recrypt)?;
        let mut dek = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(dek.as_mut());
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = encrypt_payload(&dek, &nonce, plaintext)?;
        let mut wraps = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            wraps.push(wrap::seal(recipient, &dek, epoch)?);
        }
        let mut capsules = Vec::with_capacity(recrypt.len());
        for recipient in recrypt {
            let capsule = kem.encapsulate(&recipient.backend, &recipient.key, &dek)?;
            if capsule.is_empty() {
                dek.zeroize();
                return Err(ShareError::Recrypt);
            }
            capsules.push(RecryptCapsule {
                backend: recipient.backend.clone(),
                recipient: recipient.key.clone(),
                ciphertext: capsule,
            });
        }
        dek.zeroize();
        Ok(Self {
            epoch,
            nonce,
            ciphertext,
            wraps,
            targets: recipients.to_vec(),
            recrypt: capsules,
        })
    }

    /// Open with a direct encapsulation secret.
    pub fn open(&self, secret: &WrapSecret) -> Result<Zeroizing<Vec<u8>>, ShareError> {
        let expected = secret.public()?.encapsulation()?.recipient;
        let mut opened = None;
        for wrap in &self.wraps {
            if wrap.recipient == expected {
                opened = Some(wrap::open_with(secret, wrap)?);
                break;
            }
        }
        let Some(dek) = opened else {
            return Err(ShareError::NoMatchingWrap);
        };
        decrypt_payload(&dek, &self.nonce, &self.ciphertext)
    }

    /// Open with a PRE secret. `recipient` selects the capsule.
    pub fn open_recrypt(
        &self,
        backend: &str,
        recipient: &[u8],
        secret: &[u8],
        kem: &dyn RecryptKem,
    ) -> Result<Zeroizing<Vec<u8>>, ShareError> {
        let capsule = self
            .recrypt
            .iter()
            .find(|c| c.backend == backend && c.recipient == recipient)
            .ok_or(ShareError::NoMatchingWrap)?;
        let mut dek = Zeroizing::new(kem.decapsulate(backend, secret, &capsule.ciphertext)?);
        let plain = decrypt_payload(&dek, &self.nonce, &self.ciphertext);
        dek.zeroize();
        plain
    }

    /// Append a direct wrap of the same DEK. Payload bytes stay as they are.
    pub fn add_recipient(
        &self,
        opener: &WrapSecret,
        recipient: WrapPublic,
    ) -> Result<Self, ShareError> {
        if self.targets.contains(&recipient) {
            return Err(ShareError::DuplicateRecipient);
        }
        let enc = recipient.encapsulation()?;
        if self
            .wraps
            .iter()
            .any(|wrap| wrap.recipient == enc.recipient)
        {
            return Err(ShareError::DuplicateRecipient);
        }
        let mut dek = self.open_dek(opener)?;
        let wrap = wrap::seal(&recipient, &dek, self.epoch);
        dek.zeroize();
        let wrap = wrap?;
        let mut next = self.clone();
        next.wraps.push(wrap);
        next.targets.push(recipient);
        Ok(next)
    }

    /// Replace every direct wrap. Recrypt capsules must be absent, so a
    /// rotation cannot drop a PRE recipient by accident. Payload bytes stay.
    pub fn rotate(
        &self,
        opener: &WrapSecret,
        recipients: &[WrapPublic],
        epoch: u64,
    ) -> Result<Self, ShareError> {
        if !self.recrypt.is_empty() {
            return Err(ShareError::Mode);
        }
        if recipients.is_empty() {
            return Err(ShareError::EmptyRecipients);
        }
        reject_duplicate_direct(recipients)?;
        let mut dek = self.open_dek(opener)?;
        let mut wraps = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            match wrap::seal(recipient, &dek, epoch) {
                Ok(wrap) => wraps.push(wrap),
                Err(err) => {
                    dek.zeroize();
                    return Err(err);
                }
            }
        }
        dek.zeroize();
        Ok(Self {
            epoch,
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
            wraps,
            targets: recipients.to_vec(),
            recrypt: Vec::new(),
        })
    }

    /// Transform one capsule to `to` and leave the payload ciphertext alone.
    pub fn transform_recrypt(
        &self,
        backend: &str,
        from: &[u8],
        to: &RecryptPublic,
        transform_key: &[u8],
        kem: &dyn RecryptKem,
    ) -> Result<Self, ShareError> {
        if to.backend != backend {
            return Err(ShareError::Recrypt);
        }
        if self
            .recrypt
            .iter()
            .any(|c| c.backend == backend && c.recipient == to.key)
        {
            return Err(ShareError::DuplicateRecipient);
        }
        let index = self
            .recrypt
            .iter()
            .position(|c| c.backend == backend && c.recipient == from)
            .ok_or(ShareError::NoMatchingWrap)?;
        let next_ct = kem.transform(backend, transform_key, &self.recrypt[index].ciphertext)?;
        if next_ct.is_empty() {
            return Err(ShareError::Recrypt);
        }
        let mut next = self.clone();
        next.recrypt[index] = RecryptCapsule {
            backend: backend.to_string(),
            recipient: to.key.clone(),
            ciphertext: next_ct,
        };
        Ok(next)
    }

    /// Epoch stamped on the share and on direct wraps made with it.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Blake3 of the payload nonce and ciphertext. Stable across rewrap.
    pub fn content_id(&self) -> [u8; 32] {
        let mut material =
            Vec::with_capacity(CONTENT_DOMAIN.len() + 24 + 8 + self.ciphertext.len());
        material.extend_from_slice(CONTENT_DOMAIN);
        material.extend_from_slice(&self.nonce);
        material.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        material.extend_from_slice(&self.ciphertext);
        *blake3::hash(&material).as_bytes()
    }

    /// Blake3 of the sorted direct targets and Recrypt capsules.
    pub fn access_commitment(&self) -> Result<[u8; 32], ShareError> {
        let mut parts = Vec::with_capacity(self.targets.len() + self.recrypt.len());
        for target in &self.targets {
            parts.push(target_cbor(target)?);
        }
        for capsule in &self.recrypt {
            parts.push(capsule_cbor(capsule)?);
        }
        parts.sort();
        let mut material = Vec::new();
        material.extend_from_slice(ACCESS_DOMAIN);
        material.extend_from_slice(&(parts.len() as u64).to_be_bytes());
        for part in &parts {
            material.extend_from_slice(&(part.len() as u64).to_be_bytes());
            material.extend_from_slice(part);
        }
        Ok(*blake3::hash(&material).as_bytes())
    }

    pub fn has_direct(&self) -> bool {
        !self.targets.is_empty()
    }

    pub fn has_recrypt(&self) -> bool {
        !self.recrypt.is_empty()
    }

    /// Canonical dCBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ShareError> {
        Ok(CBOR::from(self.to_map()?).to_cbor_data())
    }

    /// Parse a canonical share.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ShareError> {
        let cbor = CBOR::try_from_data(bytes)?;
        if cbor.to_cbor_data().as_slice() != bytes {
            return Err(ShareError::Payload);
        }
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(ShareError::Payload),
        };
        if map.len() != 6 {
            return Err(ShareError::Payload);
        }
        let version: u64 = map.extract("v").map_err(|_| ShareError::Payload)?;
        if version != 1 {
            return Err(ShareError::Payload);
        }
        let epoch: u64 = map.extract("epoch").map_err(|_| ShareError::Payload)?;
        let payload = map_cbor(&map, "payload")?
            .try_into_map()
            .map_err(|_| ShareError::Payload)?;
        if payload.len() != 3 {
            return Err(ShareError::Payload);
        }
        let alg: String = payload.extract("alg").map_err(|_| ShareError::Payload)?;
        if alg != PAYLOAD_ALG {
            return Err(ShareError::Payload);
        }
        let nonce_bs: ByteString = payload.extract("nonce").map_err(|_| ShareError::Payload)?;
        let ciphertext: ByteString = payload
            .extract("ciphertext")
            .map_err(|_| ShareError::Payload)?;
        let nonce: [u8; 24] = nonce_bs
            .as_ref()
            .try_into()
            .map_err(|_| ShareError::Payload)?;
        let wrap_values = map_cbor(&map, "wraps")?
            .try_into_array()
            .map_err(|_| ShareError::Payload)?;
        let target_values = map_cbor(&map, "targets")?
            .try_into_array()
            .map_err(|_| ShareError::Payload)?;
        let recrypt_values = map_cbor(&map, "recrypt")?
            .try_into_array()
            .map_err(|_| ShareError::Payload)?;
        if wrap_values.len() != target_values.len() {
            return Err(ShareError::Payload);
        }
        let mut wraps = Vec::with_capacity(wrap_values.len());
        let mut targets = Vec::with_capacity(target_values.len());
        for (wrap_cbor, target_cbor) in wrap_values.into_iter().zip(target_values) {
            let wrap = parse_embedded_wrap(wrap_cbor)?;
            let target = parse_target(target_cbor)?;
            let enc = target.encapsulation()?;
            if wrap.alg != enc.alg || wrap.recipient != enc.recipient || wrap.epoch != epoch {
                return Err(ShareError::Payload);
            }
            wraps.push(wrap);
            targets.push(target);
        }
        let mut recrypt = Vec::with_capacity(recrypt_values.len());
        for value in recrypt_values {
            recrypt.push(parse_capsule(value)?);
        }
        if wraps.is_empty() && recrypt.is_empty() {
            return Err(ShareError::EmptyRecipients);
        }
        Ok(Self {
            epoch,
            nonce,
            ciphertext: ciphertext.as_ref().to_vec(),
            wraps,
            targets,
            recrypt,
        })
    }

    fn open_dek(&self, opener: &WrapSecret) -> Result<Zeroizing<[u8; 32]>, ShareError> {
        let expected = opener.public()?.encapsulation()?.recipient;
        for wrap in &self.wraps {
            if wrap.recipient == expected {
                return wrap::open_with(opener, wrap);
            }
        }
        Err(ShareError::NoMatchingWrap)
    }

    fn to_map(&self) -> Result<Map, ShareError> {
        let mut payload = Map::new();
        payload.insert("alg", PAYLOAD_ALG);
        payload.insert("nonce", CBOR::to_byte_string(self.nonce));
        payload.insert("ciphertext", CBOR::to_byte_string(&self.ciphertext));
        let mut wraps = Vec::with_capacity(self.wraps.len());
        for wrap in &self.wraps {
            let bytes = wrap.to_cbor()?;
            wraps.push(CBOR::try_from_data(bytes)?);
        }
        let mut targets = Vec::with_capacity(self.targets.len());
        for target in &self.targets {
            targets.push(CBOR::try_from_data(target_cbor(target)?)?);
        }
        let mut recrypt = Vec::with_capacity(self.recrypt.len());
        for capsule in &self.recrypt {
            recrypt.push(CBOR::try_from_data(capsule_cbor(capsule)?)?);
        }
        let mut map = Map::new();
        map.insert("v", 1_u64);
        map.insert("epoch", self.epoch);
        map.insert("payload", payload);
        map.insert("wraps", wraps);
        map.insert("targets", targets);
        map.insert("recrypt", recrypt);
        Ok(map)
    }
}

struct NopKem;

impl RecryptKem for NopKem {
    fn encapsulate(
        &self,
        _backend: &str,
        _recipient: &[u8],
        _dek: &[u8; 32],
    ) -> Result<Vec<u8>, ShareError> {
        Err(ShareError::Recrypt)
    }

    fn decapsulate(
        &self,
        _backend: &str,
        _secret: &[u8],
        _capsule: &[u8],
    ) -> Result<[u8; 32], ShareError> {
        Err(ShareError::Recrypt)
    }

    fn transform(
        &self,
        _backend: &str,
        _transform_key: &[u8],
        _capsule: &[u8],
    ) -> Result<Vec<u8>, ShareError> {
        Err(ShareError::Recrypt)
    }
}

fn encrypt_payload(
    dek: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, ShareError> {
    let cipher = XChaCha20Poly1305::new(dek.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: PAYLOAD_AAD,
            },
        )
        .map_err(|_| ShareError::Payload)
}

fn decrypt_payload(
    dek: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ShareError> {
    let cipher = XChaCha20Poly1305::new(dek.into());
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: PAYLOAD_AAD,
            },
        )
        .map_err(|_| ShareError::Payload)?;
    Ok(Zeroizing::new(plain))
}

fn map_cbor(map: &Map, key: &str) -> Result<CBOR, ShareError> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, value)| value.clone())
        .ok_or(ShareError::Payload)
}

fn reject_duplicate_direct(recipients: &[WrapPublic]) -> Result<(), ShareError> {
    let mut seen = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let enc = recipient.encapsulation()?;
        if seen.iter().any(|have: &Vec<u8>| have == &enc.recipient)
            || recipients.iter().filter(|r| *r == recipient).count() > 1
        {
            return Err(ShareError::DuplicateRecipient);
        }
        seen.push(enc.recipient);
    }
    Ok(())
}

fn reject_duplicate_recrypt(recipients: &[RecryptPublic]) -> Result<(), ShareError> {
    for (i, recipient) in recipients.iter().enumerate() {
        if recipients
            .iter()
            .skip(i + 1)
            .any(|other| other.backend == recipient.backend && other.key == recipient.key)
        {
            return Err(ShareError::DuplicateRecipient);
        }
    }
    Ok(())
}

pub(crate) fn target_cbor(target: &WrapPublic) -> Result<Vec<u8>, ShareError> {
    let mut map = Map::new();
    map.insert("alg", target.tag());
    map.insert("key", CBOR::to_byte_string(target.key_bytes()));
    Ok(CBOR::from(map).to_cbor_data())
}

pub(crate) fn capsule_cbor(capsule: &RecryptCapsule) -> Result<Vec<u8>, ShareError> {
    let mut map = Map::new();
    map.insert("alg", "recrypt-pre");
    map.insert("backend", capsule.backend.as_str());
    map.insert("recipient", CBOR::to_byte_string(&capsule.recipient));
    map.insert("ciphertext", CBOR::to_byte_string(&capsule.ciphertext));
    Ok(CBOR::from(map).to_cbor_data())
}

fn parse_embedded_wrap(cbor: CBOR) -> Result<Wrap, ShareError> {
    wrap::parse_wrap(&cbor.to_cbor_data())
}

fn parse_target(cbor: CBOR) -> Result<WrapPublic, ShareError> {
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return Err(ShareError::Payload),
    };
    if map.len() != 2 {
        return Err(ShareError::Payload);
    }
    let alg: String = map.extract("alg").map_err(|_| ShareError::Payload)?;
    let key: ByteString = map.extract("key").map_err(|_| ShareError::Payload)?;
    match alg.as_str() {
        "x25519" => {
            let bytes: [u8; 32] = key.as_ref().try_into().map_err(|_| ShareError::Payload)?;
            WrapPublic::x25519(bytes)
        }
        "ed25519" => {
            let bytes: [u8; 32] = key.as_ref().try_into().map_err(|_| ShareError::Payload)?;
            WrapPublic::ed25519(bytes)
        }
        "p256" => {
            let bytes: [u8; 33] = key.as_ref().try_into().map_err(|_| ShareError::Payload)?;
            WrapPublic::p256(bytes)
        }
        _ => Err(ShareError::Payload),
    }
}

fn parse_capsule(cbor: CBOR) -> Result<RecryptCapsule, ShareError> {
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return Err(ShareError::Recrypt),
    };
    if map.len() != 4 {
        return Err(ShareError::Recrypt);
    }
    let alg: String = map.extract("alg").map_err(|_| ShareError::Recrypt)?;
    if alg != "recrypt-pre" {
        return Err(ShareError::Recrypt);
    }
    let backend: String = map.extract("backend").map_err(|_| ShareError::Recrypt)?;
    let recipient: ByteString = map.extract("recipient").map_err(|_| ShareError::Recrypt)?;
    let ciphertext: ByteString = map.extract("ciphertext").map_err(|_| ShareError::Recrypt)?;
    if backend.is_empty() || recipient.as_ref().is_empty() || ciphertext.as_ref().is_empty() {
        return Err(ShareError::Recrypt);
    }
    Ok(RecryptCapsule {
        backend,
        recipient: recipient.as_ref().to_vec(),
        ciphertext: ciphertext.as_ref().to_vec(),
    })
}
