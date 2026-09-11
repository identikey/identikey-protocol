//! Verdict vocabulary: deny / drop / reply-here / deliver.

use crate::error::AdmitError;

/// Evaluator output. The embedder maps this onto lifecycle (thaw, queue, skip).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Fail closed. Do not queue, restore, or deliver.
    Deny,
    /// Discard. Running-body mentions stay on the relay; host mailbox is unused.
    Drop,
    /// Handle at the facade without waking the body (cache, drain).
    ReplyHere,
    /// Trusted hop: `deliver_message` / queue.
    Deliver,
}

impl Verdict {
    pub const DENY: &'static str = "deny";
    pub const DROP: &'static str = "drop";
    pub const REPLY_HERE: &'static str = "reply-here";
    pub const DELIVER: &'static str = "deliver";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => Self::DENY,
            Self::Drop => Self::DROP,
            Self::ReplyHere => Self::REPLY_HERE,
            Self::Deliver => Self::DELIVER,
        }
    }

    pub fn parse(s: &str) -> Result<Self, AdmitError> {
        match s {
            Self::DENY => Ok(Self::Deny),
            Self::DROP => Ok(Self::Drop),
            Self::REPLY_HERE => Ok(Self::ReplyHere),
            Self::DELIVER => Ok(Self::Deliver),
            other => Err(AdmitError::UnknownVerdict(other.to_string())),
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Verdict {
    type Err = AdmitError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
