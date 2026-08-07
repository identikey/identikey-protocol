//! The op itself: a signed, actor-attributed, content-addressed, causally
//! ordered, DAG-linked record with an opaque typed body.

use bc_components::Signature;

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

/// An unsigned op.
///
/// The first five fields are the **subject** — the core map, the load-bearing
/// anchors that are always present. The last four become Gordian
/// **assertions**: optional, repeatable, individually digested, and therefore
/// individually elidable without invalidating a signature.
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
    /// Additional causal dependencies (assertion, repeatable).
    pub deps: Vec<Hash32>,
    /// Negative acknowledgements (assertion, repeatable).
    pub nacks: Vec<Hash32>,
    /// Optional target fingerprint (assertion).
    pub target_fp: Option<Hash32>,
    /// Optional wall-clock timestamp, seconds since the epoch, encoded as a
    /// CBOR `#6.1` tagged integer (assertion). Advisory only — `hlc` is the
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

/// An op plus zero or more signatures.
///
/// Signatures live on the **wrapper** around the unsigned envelope, so they
/// are not part of what they themselves cover, and `content_hash` — which is
/// taken over the unsigned form — is stable as signatures are added by
/// additional authors.
///
/// [`Signature`] is `bc_components::Signature`: a tagged, self-describing
/// object that names its own scheme. This crate no longer carries an algorithm
/// tag of its own; there is nothing left for one to disambiguate.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedOp {
    pub op: Op,
    /// The signatures on the wrapper, as a `Vec` for convenience but a **set**
    /// in fact: Gordian orders assertions by digest, so a decoded op returns
    /// its signatures in digest order and the author's insertion order is not
    /// recoverable from the bytes. Nothing should depend on the order.
    pub signatures: Vec<Signature>,
    /// How many assertions were **elided** in the envelope this was decoded
    /// from. Zero for anything this crate encoded.
    ///
    /// Elision is not an error: a partially-redacted op is still verifiable,
    /// which is the entire reason the format is Gordian Envelope. But it is
    /// also not invisible — a decoded op with `elided > 0` is missing
    /// assertions the author put there, and re-encoding it will not reproduce
    /// the bytes it came from.
    pub elided: usize,
}

impl SignedOp {
    pub fn new(op: Op, signatures: Vec<Signature>) -> Self {
        Self { op, signatures, elided: 0 }
    }

    /// Is there at least one signature? An op with none is untrusted input.
    pub fn is_signed(&self) -> bool { !self.signatures.is_empty() }

    /// Were any assertions redacted out of the envelope this came from?
    pub fn has_elisions(&self) -> bool { self.elided > 0 }
}
