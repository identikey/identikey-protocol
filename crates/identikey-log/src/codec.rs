//! The wire codec: logical [`Op`] ⇄ canonical bytes.
//!
//! # Why this is not `bc_envelope::Envelope`
//!
//! This format borrows Blockchain Commons' envelope CBOR **tags** (`#6.200`
//! envelope, `#6.201` leaf) but not Gordian Envelope's **structure**. See
//! `tests/envelope_interop.rs` for an executable characterisation of the three
//! differences; in short:
//!
//! 1. A subject-only value here is `200([201(core)])` — a *one*-element array.
//!    Gordian Envelope encodes a bare subject as `200(201(core))` with no
//!    array, and its decoder explicitly rejects arrays shorter than two
//!    elements ("node must have at least two elements").
//! 2. An attribute here is a 2-element **array** `[label, value]`. A Gordian
//!    assertion is a single-entry **map** `{predicate: object}` whose
//!    predicate and object are themselves envelopes.
//! 3. Signatures here are raw detached signatures over the canonical *bytes*.
//!    Gordian Envelope signs the subject's **digest tree** (SHA-256 Merkle
//!    digests) and carries the signature as a tagged `Signature` object under
//!    the `'signed'` known value.
//!
//! Those are semantic, not cosmetic, differences: (3) in particular means a
//! Gordian signature survives elision and this one does not. Preserving the
//! bytes therefore means implementing the format on top of the deterministic
//! CBOR codec (`dcbor`) rather than on top of `Envelope`. Nothing here
//! hand-rolls CBOR — every byte comes out of `dcbor`.
//!
//! # Layout
//!
//! ```text
//! 200([ 201({core map}), [attr-label, attr-value], ... ])
//! ```
//!
//! Core map keys, in dCBOR order (which sorts by *encoded* key bytes, and so
//! is length-first, lexicographic within equal length):
//!
//! | key | len | type |
//! |---|---|---|
//! | `hlc`            | 3  | `[uint, uint]`, untagged |
//! | `body`           | 4  | bytes (optional — key omitted when absent) |
//! | `kind`           | 4  | text, non-empty |
//! | `type`           | 4  | text, `"ball.action"` |
//! | `actor`          | 5  | bytes(32) |
//! | `parent-hashes`  | 13 | array of bytes(32) |
//! | `format-version` | 14 | uint, `4` |
//!
//! Attributes are emitted in the same length-first order, and repeat freely:
//! `deps`(4) · `nacks`(5) · `signed`(6) · `target-fp`(9) · `timestamp`(9).

use dcbor::prelude::*;

use crate::{
    error::{LogError, Result},
    hlc::Hlc,
    op::{Hash32, Op, SigAlg, Signature, SignedOp, FORMAT_VERSION, OP_TYPE},
};

/// CBOR tag `#6.200` — envelope.
pub const TAG_ENVELOPE: u64 = 200;
/// CBOR tag `#6.201` — leaf (the dCBOR-encoded core).
pub const TAG_LEAF: u64 = 201;
/// CBOR tag `#6.1` — epoch time (RFC 8949).
pub const TAG_EPOCH_TIME: u64 = 1;

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode the **canonical unsigned bytes** — the form that `content_hash`
/// covers and that a signature is computed over.
pub fn encode(op: &Op) -> Result<Vec<u8>> { encode_signed(&SignedOp::new(op.clone(), vec![])) }

/// Encode with `signed` attributes appended.
pub fn encode_signed(signed: &SignedOp) -> Result<Vec<u8>> {
    let op = &signed.op;
    op.validate()?;

    // The body is opaque once embedded, so this is the encoder's only window
    // to enforce its canonicality. `dcbor`'s decoder is strict about
    // determinism, so a successful round-trip to identical bytes is the check.
    if let Some(body) = &op.body {
        assert_canonical(body)?;
    }

    let mut core = Map::new();
    core.insert("hlc", vec![op.hlc.l, op.hlc.c]);
    if let Some(body) = &op.body {
        core.insert("body", CBOR::to_byte_string(body));
    }
    core.insert("kind", op.kind.as_str());
    core.insert("type", OP_TYPE);
    core.insert("actor", CBOR::to_byte_string(op.actor));
    core.insert(
        "parent-hashes",
        op.parent_hashes.iter().map(CBOR::to_byte_string).collect::<Vec<_>>(),
    );
    core.insert("format-version", FORMAT_VERSION);

    let mut items = vec![CBOR::to_tagged_value(TAG_LEAF, core)];
    for d in &op.deps {
        items.push(attribute("deps", CBOR::to_byte_string(d)));
    }
    for n in &op.nacks {
        items.push(attribute("nacks", CBOR::to_byte_string(n)));
    }
    for s in &signed.signatures {
        let pair: CBOR =
            vec![CBOR::from(s.alg.tag()), CBOR::to_byte_string(&s.value)].into();
        items.push(attribute("signed", pair));
    }
    if let Some(fp) = &op.target_fp {
        items.push(attribute("target-fp", CBOR::to_byte_string(fp)));
    }
    if let Some(ts) = op.timestamp {
        items.push(attribute("timestamp", CBOR::to_tagged_value(TAG_EPOCH_TIME, ts)));
    }

    Ok(CBOR::to_tagged_value(TAG_ENVELOPE, items).to_cbor_data())
}

fn attribute(label: &str, value: CBOR) -> CBOR {
    vec![CBOR::from(label), value].into()
}

/// `content_hash` — the op's portable identity.
///
/// `blake3(canonical unsigned envelope bytes)`, with **no** domain-separation
/// prefix. The unsigned bytes are self-describing (they carry `type` and
/// `format-version` inside the hashed region), so a prefix would add nothing a
/// collision-finder could not already see.
pub fn content_hash(op: &Op) -> Result<Hash32> {
    Ok(*blake3::hash(&encode(op)?).as_bytes())
}

/// Reject a body that is not canonical (deterministic) CBOR. A non-canonical
/// body would let two byte-distinct ops carry the same logical payload, which
/// breaks content-addressing.
fn assert_canonical(bytes: &[u8]) -> Result<()> {
    let cbor = CBOR::try_from_data(bytes).map_err(|_| LogError::NonCanonicalBody)?;
    if cbor.to_cbor_data() != bytes {
        return Err(LogError::NonCanonicalBody);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode canonical bytes into an op plus any attached signatures.
///
/// Strict: non-canonical CBOR, an unexpected tag, a `format-version` other
/// than 4, a wrong `type`, an empty `kind`, a missing required core key, or a
/// mis-sized hash are all errors. `format-version` is checked *before* the
/// rest of the core map is interpreted.
pub fn decode(bytes: &[u8]) -> Result<SignedOp> {
    let cbor = CBOR::try_from_data(bytes)?;
    let items = into_array(expect_tag(cbor, TAG_ENVELOPE)?)?;
    let (core, attrs) = items.split_first().ok_or(LogError::MissingField("core"))?;

    let core = into_map(expect_tag(core.clone(), TAG_LEAF)?)?;
    let field = |k: &'static str| core.get::<_, CBOR>(k).ok_or(LogError::MissingField(k));

    // Discriminant first — never interpret the rest of the map before it.
    let version = into_uint(field("format-version")?)?;
    if version != FORMAT_VERSION {
        return Err(LogError::UnsupportedFormatVersion(version));
    }
    let ty = into_text(field("type")?)?;
    if ty != OP_TYPE {
        return Err(LogError::WrongType(ty));
    }

    let kind = into_text(field("kind")?)?;
    if kind.is_empty() {
        return Err(LogError::EmptyKind);
    }

    let hlc = into_array(field("hlc")?)?;
    if hlc.len() != 2 {
        return Err(LogError::InvalidValue("hlc must be [l, c]"));
    }

    let body = match core.get::<_, CBOR>("body") {
        Some(b) => {
            let b = into_bytes(b)?;
            assert_canonical(&b)?;
            Some(b)
        }
        None => None,
    };

    let mut op = Op {
        kind,
        body,
        hlc: Hlc::new(into_uint(hlc[0].clone())?, into_uint(hlc[1].clone())?),
        actor: hash32(into_bytes(field("actor")?)?)?,
        parent_hashes: into_array(field("parent-hashes")?)?
            .into_iter()
            .map(|p| hash32(into_bytes(p)?))
            .collect::<Result<Vec<_>>>()?,
        ..Default::default()
    };

    let mut signatures = Vec::new();
    for attr in attrs {
        let pair = into_array(attr.clone())?;
        if pair.len() != 2 {
            return Err(LogError::InvalidValue("attribute must be [label, value]"));
        }
        let label = into_text(pair[0].clone())?;
        let value = pair[1].clone();
        match label.as_str() {
            "deps" => op.deps.push(hash32(into_bytes(value)?)?),
            "nacks" => op.nacks.push(hash32(into_bytes(value)?)?),
            "target-fp" => op.target_fp = Some(hash32(into_bytes(value)?)?),
            "timestamp" => {
                op.timestamp = Some(into_uint(expect_tag(value, TAG_EPOCH_TIME)?)?)
            }
            "signed" => {
                let sig = into_array(value)?;
                if sig.len() != 2 {
                    return Err(LogError::InvalidValue("signed must be [alg, value]"));
                }
                signatures.push(Signature {
                    alg: SigAlg::from_tag(&into_text(sig[0].clone())?)?,
                    value: into_bytes(sig[1].clone())?,
                });
            }
            // An unknown attribute would be silently dropped on re-encode,
            // breaking byte-stable round-tripping. Reject instead.
            _ => return Err(LogError::InvalidValue("unknown attribute label")),
        }
    }

    Ok(SignedOp::new(op, signatures))
}

fn expect_tag(cbor: CBOR, expected: u64) -> Result<CBOR> {
    match cbor.into_case() {
        CBORCase::Tagged(tag, item) if tag.value() == expected => Ok(item),
        CBORCase::Tagged(tag, _) => Err(LogError::WrongTag { expected, got: tag.value() }),
        _ => Err(LogError::InvalidValue("expected a tagged value")),
    }
}

fn into_array(cbor: CBOR) -> Result<Vec<CBOR>> {
    match cbor.into_case() {
        CBORCase::Array(items) => Ok(items),
        _ => Err(LogError::InvalidValue("expected an array")),
    }
}

fn into_map(cbor: CBOR) -> Result<Map> {
    match cbor.into_case() {
        CBORCase::Map(m) => Ok(m),
        _ => Err(LogError::InvalidValue("expected a map")),
    }
}

fn into_text(cbor: CBOR) -> Result<String> {
    match cbor.into_case() {
        CBORCase::Text(s) => Ok(s),
        _ => Err(LogError::InvalidValue("expected a text string")),
    }
}

fn into_bytes(cbor: CBOR) -> Result<Vec<u8>> {
    match cbor.into_case() {
        CBORCase::ByteString(b) => Ok(b.into()),
        _ => Err(LogError::InvalidValue("expected a byte string")),
    }
}

fn into_uint(cbor: CBOR) -> Result<u64> {
    match cbor.into_case() {
        CBORCase::Unsigned(n) => Ok(n),
        _ => Err(LogError::InvalidValue("expected an unsigned integer")),
    }
}

fn hash32(bytes: Vec<u8>) -> Result<Hash32> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| LogError::BadLength { expected: 32, got: bytes.len() })
}
