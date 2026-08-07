//! The wire codec: logical [`Op`] ⇄ [`Envelope`] ⇄ canonical bytes.
//!
//! # This is a *profile* of Gordian Envelope, not a format of its own
//!
//! Before Dreamball-y4t.16 this module built an envelope-*shaped* value on the
//! `dcbor` codec: it borrowed the `#6.200` / `#6.201` tags but used a
//! one-element array for a subject-only envelope, encoded attributes as
//! two-element arrays, and signed the literal canonical bytes with raw
//! Ed25519. Every test passed, and none of them could have caught the problem,
//! because a lookalike format passes every test a real one does — except the
//! elision test, which is why `tests/elision.rs` now exists.
//!
//! Everything here is now `bc_envelope::Envelope`. This module chooses only:
//!
//! * what the **subject** is — a leaf holding the core map;
//! * which **predicates** mean what;
//! * where the signature sits.
//!
//! # Layout
//!
//! ```text
//! unsigned:                          signed:
//!                                    {                       ← wrap
//!   {core map} [                       {core map} [
//!     "deps": Bytes                      "deps": Bytes
//!     "timestamp": Date                  "timestamp": Date
//!   ]                                  ]
//!                                    } [
//!                                      'signed': Signature
//!                                    ]
//! ```
//!
//! A signed op **wraps** the unsigned envelope before signing. That is the
//! Gordian idiom for "this signature covers the assertions too": a bare
//! `add_signature` would sign only `subject().digest()`, i.e. the core map,
//! silently dropping `deps` / `nacks` / `target-fp` / `timestamp` out of the
//! signed region. The pre-Gordian format covered them (it signed the whole
//! canonical byte string), so wrapping is what *preserves* the old security
//! property while gaining the new one.
//!
//! # Core map
//!
//! The subject is one dCBOR map, unchanged from the pre-Gordian format. Keys
//! in dCBOR order (sorts by *encoded* key bytes: length first, then
//! lexicographic):
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
//! # Assertions
//!
//! | predicate | object | repeatable |
//! |---|---|---|
//! | `"deps"`      | bytes(32)              | yes |
//! | `"nacks"`     | bytes(32)              | yes |
//! | `"target-fp"` | bytes(32)              | no |
//! | `"timestamp"` | `#6.1` tagged uint     | no |
//! | `'signed'`    | tagged `Signature`     | yes (on the wrapped form) |
//!
//! `'signed'` is [`known_values::SIGNED`] — a small integer, not the text
//! string `"signed"`. Assertion order on the wire is not ours to choose:
//! Gordian sorts assertions by digest, which is deterministic and
//! implementation-independent.

use bc_components::Signature;
use bc_envelope::prelude::*;
use dcbor::prelude::{CBORCase, Map};

use crate::{
    error::{LogError, Result},
    hlc::Hlc,
    op::{Hash32, Op, SignedOp, FORMAT_VERSION, OP_TYPE},
};

/// CBOR tag `#6.1` — epoch time (RFC 8949). Carried inside the `timestamp`
/// assertion's leaf.
pub const TAG_EPOCH_TIME: u64 = 1;

/// Assertion predicates this profile recognises, other than `'signed'`.
pub const PRED_DEPS: &str = "deps";
pub const PRED_NACKS: &str = "nacks";
pub const PRED_TARGET_FP: &str = "target-fp";
pub const PRED_TIMESTAMP: &str = "timestamp";

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Build the **unsigned** envelope: core-map subject plus attribute
/// assertions. This is the form `content_hash` covers and the form a signature
/// wraps.
pub fn to_envelope(op: &Op) -> Result<Envelope> {
    op.validate()?;

    // The body is opaque once embedded, so this is the encoder's only window
    // to enforce its canonicality.
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

    let mut envelope = Envelope::new(CBOR::from(core));
    for d in &op.deps {
        envelope = envelope.add_assertion(PRED_DEPS, CBOR::to_byte_string(d));
    }
    for n in &op.nacks {
        envelope = envelope.add_assertion(PRED_NACKS, CBOR::to_byte_string(n));
    }
    if let Some(fp) = &op.target_fp {
        envelope = envelope.add_assertion(PRED_TARGET_FP, CBOR::to_byte_string(fp));
    }
    if let Some(ts) = op.timestamp {
        envelope = envelope
            .add_assertion(PRED_TIMESTAMP, CBOR::to_tagged_value(TAG_EPOCH_TIME, ts));
    }
    Ok(envelope)
}

/// Build the envelope for an op plus its signatures.
///
/// With no signatures this is exactly [`to_envelope`] — an op is not wrapped
/// until there is something to sign. With signatures the unsigned envelope is
/// wrapped and each signature is attached as a `'signed'` assertion on the
/// wrapper.
pub fn to_signed_envelope(signed: &SignedOp) -> Result<Envelope> {
    let inner = to_envelope(&signed.op)?;
    if signed.signatures.is_empty() {
        return Ok(inner);
    }
    let mut envelope = inner.wrap();
    for sig in &signed.signatures {
        envelope = envelope.add_assertion(known_values::SIGNED, sig.clone());
    }
    Ok(envelope)
}

/// Return the envelope with every assertion **salted**.
///
/// Elision hides an assertion's content but not its digest, and a digest over
/// a low-entropy value is guessable: an attacker who knows the predicate and
/// can enumerate plausible objects simply recomputes digests until one
/// matches. `timestamp` and `target-fp` are exactly that kind of value. A salt
/// assertion adds unguessable entropy under the same digest, so the redacted
/// digest reveals nothing.
///
/// This is an **authoring-time** decision, not something a holder can do
/// later: salt is part of the bytes, so it changes the op's `content_hash`,
/// and it must be in place before the op is signed. Salting is also
/// per-envelope random, so a salted op is not byte-reproducible from its
/// logical value — that is the point (it defeats correlation), but it means a
/// salted op cannot be a golden vector.
pub fn salt_assertions(envelope: &Envelope) -> Result<Envelope> {
    let mut out = envelope.subject();
    for assertion in envelope.assertions() {
        out = out
            .add_assertion_envelope(assertion.add_salt())
            .map_err(|e| LogError::Envelope(e.to_string()))?;
    }
    Ok(out)
}

/// Encode the **canonical unsigned bytes** — the form `content_hash` covers.
pub fn encode(op: &Op) -> Result<Vec<u8>> { Ok(to_envelope(op)?.to_cbor_data()) }

/// Encode with `'signed'` assertions attached.
pub fn encode_signed(signed: &SignedOp) -> Result<Vec<u8>> {
    Ok(to_signed_envelope(signed)?.to_cbor_data())
}

/// `content_hash` — the op's portable identity.
///
/// `blake3(canonical unsigned envelope bytes)`, with **no** domain-separation
/// prefix. The unsigned bytes are self-describing (they carry `type` and
/// `format-version` inside the hashed region), so a prefix would add nothing a
/// collision-finder could not already see.
///
/// Note this is deliberately *not* the envelope's own SHA-256 [`Digest`]. The
/// digest is the structural, elision-stable identity Gordian uses internally;
/// `content_hash` is the log's DAG identity, and DAG links are Blake3
/// throughout this stack. Both exist; they answer different questions.
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
/// Strict: non-canonical CBOR, a structure that is not a Gordian Envelope, a
/// `format-version` other than 4, a wrong `type`, an empty `kind`, a missing
/// required core key, a mis-sized hash, or an unrecognised predicate are all
/// errors. `format-version` is checked *before* the rest of the core map is
/// interpreted.
pub fn decode(bytes: &[u8]) -> Result<SignedOp> {
    let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
        .map_err(|e| LogError::Envelope(e.to_string()))?;
    from_envelope(&envelope)
}

/// Interpret an [`Envelope`] as an op.
///
/// **Elided assertions are skipped, not rejected**, and counted in
/// [`SignedOp::elided`]. A redacted op is the normal case for a log that is
/// shared selectively — that is the entire reason this crate moved onto
/// Gordian Envelope — so a decoder that refused one would defeat the purpose.
/// The consequence is that re-encoding a decoded *elided* op does not
/// reproduce its bytes; keep the [`Envelope`] itself if you need that.
pub fn from_envelope(envelope: &Envelope) -> Result<SignedOp> {
    // A signed op wraps its unsigned form; an unsigned op does not.
    let (inner, outer_assertions) = match envelope.try_unwrap() {
        Ok(inner) => (inner, envelope.assertions()),
        Err(_) => (envelope.clone(), Vec::new()),
    };

    let core = match inner
        .subject()
        .try_leaf()
        .map_err(|e| LogError::Envelope(e.to_string()))?
        .into_case()
    {
        CBORCase::Map(m) => m,
        _ => return Err(LogError::InvalidValue("subject is not a map")),
    };
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

    let mut elided = 0usize;

    for assertion in inner.assertions() {
        let Some(predicate) = assertion.as_predicate() else {
            elided += 1;
            continue;
        };
        let object = assertion
            .as_object()
            .ok_or(LogError::InvalidValue("assertion without an object"))?;
        let label = predicate
            .extract_subject::<String>()
            .map_err(|_| LogError::InvalidValue("assertion predicate is not text"))?;
        let value = object
            .try_leaf()
            .map_err(|e| LogError::Envelope(e.to_string()))?;
        match label.as_str() {
            PRED_DEPS => op.deps.push(hash32(into_bytes(value)?)?),
            PRED_NACKS => op.nacks.push(hash32(into_bytes(value)?)?),
            PRED_TARGET_FP => op.target_fp = Some(hash32(into_bytes(value)?)?),
            PRED_TIMESTAMP => {
                op.timestamp = Some(into_uint(expect_tag(value, TAG_EPOCH_TIME)?)?)
            }
            // An unknown predicate would be silently dropped on re-encode,
            // breaking byte-stable round-tripping. Reject instead.
            _ => return Err(LogError::UnknownPredicate(label)),
        }
    }
    // `deps` and `nacks` are repeatable and Gordian orders assertions by
    // digest, not by insertion, so a round trip must not depend on the order
    // they came back in.
    op.deps.sort_unstable();
    op.nacks.sort_unstable();

    let mut signatures = Vec::new();
    for assertion in outer_assertions {
        let Some(predicate) = assertion.as_predicate() else {
            elided += 1;
            continue;
        };
        match predicate.subject().as_known_value() {
            Some(kv) if *kv == known_values::SIGNED => {}
            _ => {
                return Err(LogError::UnknownPredicate(
                    "non-'signed' assertion on a wrapped op".to_string(),
                ))
            }
        }
        let object = assertion
            .as_object()
            .ok_or(LogError::InvalidValue("assertion without an object"))?;
        signatures.push(object.extract_subject::<Signature>().map_err(|_| {
            // Distinguish "this build cannot represent that signature type"
            // from "that is not a signature at all". Without the `pqcrypto`
            // feature the `Signature::MLDSA` enum variant does not exist, so
            // bc-components' decoder rejects a `#6.40105` object with the same
            // generic error it gives for garbage. Conflating the two would
            // make an interop split look like a corrupt op.
            if is_mldsa_signature_object(&object) {
                LogError::PqUnavailable
            } else {
                LogError::InvalidValue("'signed' object is not a Signature")
            }
        })?);
    }

    Ok(SignedOp { op, signatures, elided })
}

/// Is this `'signed'` object a `#6.40105` ML-DSA signature?
///
/// Checked structurally rather than by asking bc-components, because the whole
/// point is that bc-components cannot answer the question in a build without
/// the `pqcrypto` feature. The tag constant lives in `bc-tags` and is not
/// itself feature-gated, so this compiles in every configuration.
fn is_mldsa_signature_object(object: &Envelope) -> bool {
    matches!(
        object.subject().try_leaf().map(|c| c.into_case()),
        Ok(CBORCase::Tagged(tag, _))
            if tag.value() == bc_components::tags::TAG_MLDSA_SIGNATURE
    )
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
