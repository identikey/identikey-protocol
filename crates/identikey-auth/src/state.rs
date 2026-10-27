//! Post-quantum state chain, version 1.
//!
//! A XID's post-quantum authority is a chain of records. Each **unsigned record** is a
//! canonical dCBOR map:
//!
//! ```text
//! { "v": 1, "xid": bstr(32), "seq": uint, ?"prev": bstr(32),
//!   "control": { "alg": "ml-dsa-65", "key": bstr(1952), "threshold": 1 },
//!   "operational": [ { "alg": tstr, "key": bstr, "privileges": [tstr],
//!                      ?"not_before": uint, ?"not_after": uint } ] }
//! ```
//!
//! `prev` is absent on the first record (`seq` 1) and present on every later one.
//! Operational keys are committed by the record but carry no authority over it.
//!
//! The record **digest** is SHA-256 of the unsigned canonical bytes. Detached
//! signatures cover the domain-separated payload
//! `[ "identikey-pq-state/v1", bstr(unsigned bytes) ]`; they are not part of the hashed
//! map. ML-DSA signs that payload with an empty context string, as in [`crate::signer`].
//!
//! Trust is a [`Trust`] value the caller keeps per XID and feeds to [`observe`]. It
//! holds at most one anchor digest and one head, the parent control key and the
//! head's `(prev, seq)` (to recognize a sibling of the head), and a fork flag. Nothing
//! here reads disk, a resolver, or a server-supplied digest.
//!
//! Only a sibling of the *current* head is detectable: a verifier that never saw both
//! branches, or saw them after the head moved past their parent, does not claim to.

use crate::algorithm::PqAlg;
use crate::cbor::{map, Value};
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature, PqPublicKey, PqSignature};
use crate::signer::{verify_classical, verify_pq};

/// State record version this module implements.
pub const STATE_VERSION: u64 = 1;

/// Domain-separation tag, the first element of the signing payload.
pub const STATE_DOMAIN: &str = "identikey-pq-state/v1";

/// Raw ML-DSA-65 public key length (FIPS 204).
pub const ML_DSA_65_PK_LEN: usize = 1952;

/// A 32-byte SHA-256 digest (XID or record digest).
pub type Digest32 = [u8; 32];

/// An operational authentication key committed by a record. Not authority over the
/// chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalKey {
    pub alg: String,
    pub key: Vec<u8>,
    pub privileges: Vec<String>,
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
}

/// A decoded v1 unsigned state record.
///
/// [`StateRecord::to_bytes`] encodes whatever the fields hold; [`StateRecord::from_bytes`]
/// is the validating decoder (and [`observe`] only accepts bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRecord {
    pub xid: Digest32,
    pub seq: u64,
    pub prev: Option<Digest32>,
    /// The single v1 control key (threshold 1).
    pub control: PqPublicKey,
    pub operational: Vec<OperationalKey>,
}

impl OperationalKey {
    fn to_value(&self) -> Value {
        let mut entries = vec![
            ("alg", Value::Text(self.alg.clone())),
            ("key", Value::Bytes(self.key.clone())),
            (
                "privileges",
                Value::Array(self.privileges.iter().cloned().map(Value::Text).collect()),
            ),
        ];
        if let Some(t) = self.not_before {
            entries.push(("not_before", Value::Uint(t)));
        }
        if let Some(t) = self.not_after {
            entries.push(("not_after", Value::Uint(t)));
        }
        map(entries)
    }

    fn from_value(v: &Value) -> Result<Self> {
        let entries = map_entries(
            v,
            &["alg", "key", "privileges", "not_before", "not_after"],
            "unknown key in operational entry",
        )?;
        let alg = required(entries, "alg", "operational alg missing")?
            .as_text()?
            .to_string();
        let key = required(entries, "key", "operational key missing")?
            .as_bytes()?
            .to_vec();
        let privileges = match required(entries, "privileges", "operational privileges missing")? {
            Value::Array(items) => items
                .iter()
                .map(|p| p.as_text().map(str::to_string))
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(AuthError::State("operational privileges must be an array")),
        };
        let not_before = optional(entries, "not_before").map(Value::as_uint).transpose()?;
        let not_after = optional(entries, "not_after").map(Value::as_uint).transpose()?;
        Ok(Self { alg, key, privileges, not_before, not_after })
    }
}

impl StateRecord {
    fn to_value(&self) -> Value {
        let control = map(vec![
            ("alg", Value::Text(self.control.alg.tag().to_string())),
            ("key", Value::Bytes(self.control.bytes.clone())),
            ("threshold", Value::Uint(1)),
        ]);
        let mut entries = vec![
            ("v", Value::Uint(STATE_VERSION)),
            ("xid", Value::Bytes(self.xid.to_vec())),
            ("seq", Value::Uint(self.seq)),
            ("control", control),
            (
                "operational",
                Value::Array(self.operational.iter().map(OperationalKey::to_value).collect()),
            ),
        ];
        if let Some(prev) = self.prev {
            entries.push(("prev", Value::Bytes(prev.to_vec())));
        }
        map(entries)
    }

    /// Canonical unsigned record bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_value().to_bytes()
    }

    /// Strictly decode and validate unsigned v1 record bytes.
    ///
    /// Rejects non-canonical encoding, a version other than 1 (before reading any other
    /// field), unknown keys at any level, and any control profile other than one
    /// ML-DSA-65 key with threshold 1.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = Value::from_bytes(bytes)?;
        if v.to_bytes() != bytes {
            return Err(AuthError::Cbor("non-canonical state record".into()));
        }
        let version = match &v {
            Value::Map(_) => match v.get_opt("v")? {
                Some(ver) => ver.as_uint()?,
                None => return Err(AuthError::MissingField("v")),
            },
            _ => return Err(AuthError::State("record must be a map")),
        };
        if version != STATE_VERSION {
            return Err(AuthError::Version(version));
        }

        let entries = map_entries(
            &v,
            &["v", "xid", "seq", "prev", "control", "operational"],
            "unknown key in state record",
        )?;
        let xid = digest32(required(entries, "xid", "xid missing")?, "xid must be 32 bytes")?;
        let seq = required(entries, "seq", "seq missing")?.as_uint()?;
        let prev = optional(entries, "prev")
            .map(|p| digest32(p, "prev must be 32 bytes"))
            .transpose()?;
        match (seq, prev) {
            (0, _) => return Err(AuthError::State("seq starts at 1")),
            (1, Some(_)) => return Err(AuthError::State("first record must not carry prev")),
            (n, None) if n > 1 => return Err(AuthError::State("record after the first needs prev")),
            _ => {}
        }

        let control = parse_control(required(entries, "control", "control missing")?)?;
        let operational = match required(entries, "operational", "operational missing")? {
            Value::Array(items) => items
                .iter()
                .map(OperationalKey::from_value)
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(AuthError::State("operational must be an array")),
        };

        Ok(Self { xid, seq, prev, control, operational })
    }

    /// SHA-256 of the canonical unsigned bytes.
    pub fn digest(&self) -> Digest32 {
        sha256(&self.to_bytes())
    }

    /// The payload detached signatures cover.
    pub fn signing_payload(&self) -> Vec<u8> {
        state_signing_payload(&self.to_bytes())
    }
}

fn parse_control(v: &Value) -> Result<PqPublicKey> {
    let entries = map_entries(v, &["alg", "key", "threshold"], "unknown key in control")?;
    let alg = required(entries, "alg", "control alg missing")?.as_text()?;
    if alg != PqAlg::MlDsa65.tag() {
        return Err(AuthError::State("control alg must be ml-dsa-65"));
    }
    let key = required(entries, "key", "control key missing")?.as_bytes()?;
    if key.len() != ML_DSA_65_PK_LEN {
        return Err(AuthError::State("control key must be 1952 bytes"));
    }
    if required(entries, "threshold", "control threshold missing")?.as_uint()? != 1 {
        return Err(AuthError::State("control threshold must be 1"));
    }
    Ok(PqPublicKey { alg: PqAlg::MlDsa65, bytes: key.to_vec() })
}

fn map_entries<'a>(
    v: &'a Value,
    allowed: &[&str],
    unknown: &'static str,
) -> Result<&'a [(String, Value)]> {
    match v {
        Value::Map(entries) => {
            if entries.iter().any(|(k, _)| !allowed.contains(&k.as_str())) {
                return Err(AuthError::State(unknown));
            }
            Ok(entries)
        }
        _ => Err(AuthError::State("expected a map")),
    }
}

fn optional<'a>(entries: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn required<'a>(
    entries: &'a [(String, Value)],
    key: &str,
    missing: &'static str,
) -> Result<&'a Value> {
    optional(entries, key).ok_or(AuthError::State(missing))
}

fn digest32(v: &Value, wrong_len: &'static str) -> Result<Digest32> {
    v.as_bytes()?
        .try_into()
        .map_err(|_| AuthError::State(wrong_len))
}

/// `[ "identikey-pq-state/v1", bstr(unsigned) ]` as canonical CBOR.
pub fn state_signing_payload(unsigned: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Text(STATE_DOMAIN.to_string()),
        Value::Bytes(unsigned.to_vec()),
    ])
    .to_bytes()
}

/// SHA-256 of a post-quantum public key's canonical CBOR (`{alg, key}` map) — the XID
/// of a new identity whose inception key is that key.
pub fn xid_for_control_key(pk: &PqPublicKey) -> Digest32 {
    sha256(&pk.to_value().to_bytes())
}

/// Detached signatures supplied with a record.
#[derive(Clone, Debug, Default)]
pub struct StateSignatures {
    /// ML-DSA signatures; each required control key must have one that verifies.
    pub pq: Vec<PqSignature>,
    /// The Elect key's classical signature (migration only).
    pub classical: Option<ClassicalSignature>,
}

/// The accepted head of a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub digest: Digest32,
    pub record: StateRecord,
}

impl Head {
    pub fn xid(&self) -> &Digest32 {
        &self.record.xid
    }
    pub fn seq(&self) -> u64 {
        self.record.seq
    }
    pub fn control_key(&self) -> &PqPublicKey {
        &self.record.control
    }
}

/// What the verifier needs to recognize a sibling of the head: the control key that
/// authorized it and the head's `(prev, seq)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Parent {
    control: PqPublicKey,
    prev: Digest32,
    seq: u64,
}

/// Verifier-local trust for one XID. The caller keeps it; [`observe`] returns the next
/// value and leaves the given one untouched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trust {
    anchor: Option<Digest32>,
    head: Option<Head>,
    parent: Option<Parent>,
    forked: bool,
}

impl Trust {
    /// Empty trust: no anchor, no head.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust that already retains a migration anchor digest (e.g. kept from when
    /// classical signatures were sound) but no head.
    pub fn with_anchor(anchor: Digest32) -> Self {
        Self { anchor: Some(anchor), ..Self::default() }
    }

    pub fn anchor(&self) -> Option<&Digest32> {
        self.anchor.as_ref()
    }

    pub fn is_forked(&self) -> bool {
        self.forked
    }

    /// The current authority, or `None` with no head or after a fork.
    pub fn authority(&self) -> Option<&Head> {
        if self.forked {
            None
        } else {
            self.head.as_ref()
        }
    }

    /// Resolve a cited digest. Only the accepted head resolves, and nothing does after
    /// a fork.
    pub fn resolve(&self, digest: &Digest32) -> Option<&Head> {
        self.authority().filter(|h| &h.digest == digest)
    }
}

/// Check one record against `trust` and return the resulting trust.
///
/// `record` is the unsigned canonical record bytes, `elect` is the caller-supplied key
/// holding Elect on the current classical document, and `classical_sound` says whether
/// this verifier still treats classical signatures as sound. An `Err` means the record
/// was rejected and the caller's trust stands as it was. A detected fork is `Ok` with
/// [`Trust::is_forked`] set.
pub fn observe(
    trust: &Trust,
    record: &[u8],
    sigs: &StateSignatures,
    elect: Option<&ClassicalPublicKey>,
    classical_sound: bool,
) -> Result<Trust> {
    if trust.forked {
        return Err(AuthError::State("duplicity recorded for this xid"));
    }
    let rec = StateRecord::from_bytes(record)?;
    let digest = sha256(record);
    let payload = state_signing_payload(record);

    if let Some(head) = &trust.head {
        // A byte-identical repeat of the head is not a branch.
        if head.digest == digest {
            return Ok(trust.clone());
        }
        if rec.seq == 1 {
            // Rechecking the anchor does not move the head; any other first record does
            // not replace the chain.
            if trust.anchor == Some(digest) {
                return Ok(trust.clone());
            }
            return Err(AuthError::State("chain already established"));
        }
        return successor(trust, head, rec, digest, &payload, sigs);
    }

    if rec.seq != 1 {
        return Err(AuthError::State("no accepted head"));
    }

    if let Some(anchor) = trust.anchor {
        // A stored anchor is the only first record this verifier accepts.
        if anchor != digest {
            return Err(AuthError::State("first record is not the stored anchor"));
        }
        check_migration_sigs(&rec, &payload, sigs, elect)?;
        return Ok(Trust {
            head: Some(Head { digest, record: rec }),
            ..trust.clone()
        });
    }

    if rec.xid == xid_for_control_key(&rec.control) {
        // New identity: the inception key is the control key.
        if !pq_signed(&rec.control, &payload, &sigs.pq) {
            return Err(AuthError::BadSignature);
        }
        return Ok(Trust {
            head: Some(Head { digest, record: rec }),
            ..trust.clone()
        });
    }

    // Migration of an existing classical XID.
    check_migration_sigs(&rec, &payload, sigs, elect)?;
    if !classical_sound {
        return Err(AuthError::State("classical signatures are not sound and no anchor is stored"));
    }
    Ok(Trust {
        anchor: Some(digest),
        head: Some(Head { digest, record: rec }),
        ..trust.clone()
    })
}

fn successor(
    trust: &Trust,
    head: &Head,
    rec: StateRecord,
    digest: Digest32,
    payload: &[u8],
    sigs: &StateSignatures,
) -> Result<Trust> {
    if rec.prev == Some(head.digest) && Some(rec.seq) == head.seq().checked_add(1) {
        check_rotation(&rec, head.xid(), head.control_key(), payload, sigs)?;
        let parent = Parent {
            control: head.record.control.clone(),
            prev: head.digest,
            seq: rec.seq,
        };
        return Ok(Trust {
            anchor: trust.anchor,
            head: Some(Head { digest, record: rec }),
            parent: Some(parent),
            forked: false,
        });
    }

    if let Some(parent) = &trust.parent {
        if rec.prev == Some(parent.prev) && rec.seq == parent.seq {
            // A second valid successor of the head's parent. A failing signature is not a
            // branch: reject and keep the head.
            check_rotation(&rec, head.xid(), &parent.control, payload, sigs)?;
            return Ok(Trust { forked: true, ..trust.clone() });
        }
    }

    Err(AuthError::State("record does not extend the accepted head"))
}

fn check_rotation(
    rec: &StateRecord,
    xid: &Digest32,
    prev_control: &PqPublicKey,
    payload: &[u8],
    sigs: &StateSignatures,
) -> Result<()> {
    if &rec.xid != xid {
        return Err(AuthError::State("xid changed"));
    }
    if !pq_signed(prev_control, payload, &sigs.pq) {
        return Err(AuthError::BadSignature);
    }
    if rec.control != *prev_control && !pq_signed(&rec.control, payload, &sigs.pq) {
        return Err(AuthError::BadSignature);
    }
    Ok(())
}

fn check_migration_sigs(
    rec: &StateRecord,
    payload: &[u8],
    sigs: &StateSignatures,
    elect: Option<&ClassicalPublicKey>,
) -> Result<()> {
    let (Some(elect), Some(sig)) = (elect, sigs.classical.as_ref()) else {
        return Err(AuthError::State("migration needs an elect key and its signature"));
    };
    verify_classical(elect, payload, sig)?;
    if !pq_signed(&rec.control, payload, &sigs.pq) {
        return Err(AuthError::BadSignature);
    }
    Ok(())
}

fn pq_signed(key: &PqPublicKey, payload: &[u8], sigs: &[PqSignature]) -> bool {
    sigs.iter().any(|s| verify_pq(key, payload, s).is_ok())
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Local because `sha2` is only a platform-gated dependency of
// this crate; checked against the NIST vectors below.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> Digest32 {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }

    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sha256;

    fn hex(d: [u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
