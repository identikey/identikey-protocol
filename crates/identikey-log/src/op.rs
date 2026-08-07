//! The op itself: a signed, actor-attributed, content-addressed, causally
//! ordered, DAG-linked record with an opaque typed body.

use crate::{
    error::{LogError, Result},
    hlc::Hlc,
};

/// A 32-byte hash / fingerprint. Used for DAG parent links, dependency links
/// and the actor's Ed25519 public key.
pub type Hash32 = [u8; 32];

/// The wire `type` discriminant. Historical: this format was born as
/// Dreamball's `ball.action` v4 and the string is part of the signed bytes, so
/// it is frozen regardless of where the code now lives.
pub const OP_TYPE: &str = "ball.action";

/// The only `format-version` this implementation speaks.
pub const FORMAT_VERSION: u64 = 4;

/// Signature algorithms carried in a `signed` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    /// Ed25519, RFC 8032. Verified against the op's `actor`.
    Ed25519,
    /// ML-DSA-87, FIPS 204 **pure** mode with the empty context string.
    MlDsa87,
}

impl SigAlg {
    pub fn tag(self) -> &'static str {
        match self {
            SigAlg::Ed25519 => "ed25519",
            SigAlg::MlDsa87 => "ml-dsa-87",
        }
    }

    pub fn from_tag(tag: &str) -> Result<Self> {
        match tag {
            "ed25519" => Ok(SigAlg::Ed25519),
            "ml-dsa-87" => Ok(SigAlg::MlDsa87),
            other => Err(LogError::UnknownAlg(other.to_string())),
        }
    }
}

/// One `signed` attribute: `[alg, value]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub alg: SigAlg,
    pub value: Vec<u8>,
}

/// An unsigned op.
///
/// The first seven fields are the **core map** — the load-bearing, always
/// present anchors that `content_hash` covers. The last four are
/// **attributes**: optional, repeatable, and (by the envelope convention this
/// format inherits) elidable descriptive metadata.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Op {
    /// Open UTF-8 kind string; `<namespace>.<noun>.<verb>` by convention
    /// (PROTOCOL §18). Must be non-empty.
    pub kind: String,
    /// Opaque consumer payload: canonical CBOR bytes, embedded as a CBOR byte
    /// string (CBOR-in-CBOR). `None` omits the key entirely, making the core
    /// map 6 keys instead of 7.
    pub body: Option<Vec<u8>>,
    /// Causal position.
    pub hlc: Hlc,
    /// Ed25519 public key of the author.
    pub actor: Hash32,
    /// DAG parent `content_hash`es.
    pub parent_hashes: Vec<Hash32>,
    /// Additional causal dependencies (attribute, repeatable).
    pub deps: Vec<Hash32>,
    /// Negative acknowledgements (attribute, repeatable).
    pub nacks: Vec<Hash32>,
    /// Optional target fingerprint (attribute).
    pub target_fp: Option<Hash32>,
    /// Optional wall-clock timestamp, seconds since the epoch, encoded as a
    /// CBOR `#6.1` tagged integer (attribute). Advisory only — `hlc` is the
    /// ordering authority.
    pub timestamp: Option<u64>,
}

impl Op {
    /// Construct the minimum viable op. Everything else is a builder setter.
    pub fn new(kind: impl Into<String>, actor: Hash32, hlc: Hlc) -> Self {
        Self { kind: kind.into(), actor, hlc, ..Default::default() }
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn with_parents(mut self, parents: impl IntoIterator<Item = Hash32>) -> Self {
        self.parent_hashes = parents.into_iter().collect();
        self
    }

    pub fn with_deps(mut self, deps: impl IntoIterator<Item = Hash32>) -> Self {
        self.deps = deps.into_iter().collect();
        self
    }

    pub fn with_nacks(mut self, nacks: impl IntoIterator<Item = Hash32>) -> Self {
        self.nacks = nacks.into_iter().collect();
        self
    }

    pub fn with_target_fp(mut self, fp: Hash32) -> Self {
        self.target_fp = Some(fp);
        self
    }

    pub fn with_timestamp(mut self, secs: u64) -> Self {
        self.timestamp = Some(secs);
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.kind.is_empty() {
            return Err(LogError::EmptyKind);
        }
        Ok(())
    }
}

/// An op plus zero or more detached signatures.
///
/// Signatures are **not** part of the bytes that are signed or hashed: a
/// verifier strips them and re-encodes the unsigned form. That is what makes
/// `content_hash` stable as signatures are added by additional authors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOp {
    pub op: Op,
    pub signatures: Vec<Signature>,
}

impl SignedOp {
    pub fn new(op: Op, signatures: Vec<Signature>) -> Self { Self { op, signatures } }

    /// Is there at least one signature? An op with none is untrusted input.
    pub fn is_signed(&self) -> bool { !self.signatures.is_empty() }
}
