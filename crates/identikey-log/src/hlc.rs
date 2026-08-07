//! Hybrid Logical Clock — causal ordering without a shared global clock.
//!
//! Wire shape (PROTOCOL §17.1): a bare 2-element CBOR array `[l, c]` of dCBOR
//! shortest-form unsigned integers. **No CBOR tag.**
//!
//! * `l` — physical component: a millisecond wall-clock timestamp, advanced
//!   monotonically. It is *not* a trustworthy clock reading; it is a counter
//!   seeded from one.
//! * `c` — counter: disambiguates concurrent events from independent authors
//!   that arrived at the same `l`.

/// A hybrid logical clock reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Hlc {
    /// Physical component (milliseconds).
    pub l: u64,
    /// Counter component.
    pub c: u64,
}

impl Hlc {
    pub const fn new(l: u64, c: u64) -> Self { Self { l, c } }

    /// The advance rule from PROTOCOL §17.2:
    ///
    /// ```text
    /// new_l = max(local_wall_ms, last_l) + 1
    /// new_c = 0
    /// ```
    ///
    /// The `+1` is what makes `l` alone a strict total order for a single
    /// author: two events issued in the same millisecond still get distinct,
    /// increasing `l` values, so a reader never has to fall back on `c` to
    /// order one author's own history. `c` exists only for *independent*
    /// authors who happen to land on the same `l`; it therefore resets on
    /// every advance rather than accumulating.
    ///
    /// `last_l` is the `l` of the most recently issued *or observed* event
    /// (observing a peer's op pulls our clock forward — that is the "hybrid"
    /// part), or `0` on first use.
    pub fn advance(local_wall_ms: u64, last_l: u64) -> Self {
        Self { l: local_wall_ms.max(last_l).saturating_add(1), c: 0 }
    }

    /// Advance from this reading, given the current wall clock.
    pub fn next(self, local_wall_ms: u64) -> Self { Self::advance(local_wall_ms, self.l) }

    /// Merge an observed peer reading into our own, so the next [`Hlc::next`]
    /// is causally after everything we have seen.
    pub fn observe(self, other: Hlc) -> Self {
        if other.l > self.l { Self { l: other.l, c: self.c } } else { self }
    }

    /// `true` when the two readings are *concurrent* — equal in both
    /// components. The protocol imposes no merge rule for concurrency; that is
    /// the consumer's domain logic (PROTOCOL §17.3).
    pub fn concurrent_with(self, other: Hlc) -> bool { self == other }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_always_strictly_increases_l_and_resets_c() {
        // Wall clock ahead of the last event.
        assert_eq!(Hlc::advance(1_000, 500), Hlc::new(1_001, 0));
        // Last event ahead of the wall clock (clock skew / rapid issuance).
        assert_eq!(Hlc::advance(500, 1_000), Hlc::new(1_001, 0));
        // Equal.
        assert_eq!(Hlc::advance(700, 700), Hlc::new(701, 0));
        // c always resets.
        assert_eq!(Hlc::new(5, 9).next(1).c, 0);
    }

    #[test]
    fn sequential_events_from_one_author_are_ordered_by_l_alone() {
        let mut clock = Hlc::default();
        let mut prev = clock;
        for _ in 0..10 {
            // A frozen wall clock is the worst case: the +1 must carry it.
            clock = clock.next(1_700_000_000_000);
            assert!(clock.l > prev.l);
            prev = clock;
        }
    }

    #[test]
    fn total_order_is_lexicographic_on_l_then_c() {
        assert!(Hlc::new(1, 9) < Hlc::new(2, 0));
        assert!(Hlc::new(2, 0) < Hlc::new(2, 1));
        assert!(Hlc::new(2, 1).concurrent_with(Hlc::new(2, 1)));
    }

    #[test]
    fn observing_a_peer_pulls_our_clock_forward() {
        let ours = Hlc::new(10, 0);
        let merged = ours.observe(Hlc::new(50, 3));
        assert_eq!(merged.l, 50);
        assert!(merged.next(0) > Hlc::new(50, 3));
        // An older peer reading does not drag us backwards.
        assert_eq!(ours.observe(Hlc::new(1, 0)), ours);
    }
}
