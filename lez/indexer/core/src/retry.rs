//! Retry gate for possibly-transient block-apply failures.

/// Counts consecutive apply failures per block id so the ingest loop can
/// retry before parking.
///
/// A failure streak is keyed to one block id: a failure of a different block
/// starts a fresh streak. Reset only on a genuinely applied block — the
/// `AlreadyApplied` replay of the prefix after a retry cycle must not clear
/// the failing block's streak.
pub struct ApplyRetryGate {
    failing: Option<(u64, u32)>,
}

impl ApplyRetryGate {
    #[must_use]
    pub const fn new() -> Self {
        Self { failing: None }
    }

    /// Registers a failed apply of `block_id`; returns its consecutive
    /// attempt count.
    pub const fn register_failure(&mut self, block_id: u64) -> u32 {
        let attempts = match self.failing {
            Some((id, attempts)) if id == block_id => attempts.saturating_add(1),
            _ => 1,
        };
        self.failing = Some((block_id, attempts));
        attempts
    }

    /// Clears the streak; call when a block actually applies.
    pub const fn reset(&mut self) {
        self.failing = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_consecutive_failures_of_same_block() {
        let mut gate = ApplyRetryGate::new();
        assert_eq!(gate.register_failure(7), 1);
        assert_eq!(gate.register_failure(7), 2);
        assert_eq!(gate.register_failure(7), 3);
    }

    #[test]
    fn different_block_starts_fresh_streak() {
        let mut gate = ApplyRetryGate::new();
        gate.register_failure(7);
        gate.register_failure(7);
        assert_eq!(gate.register_failure(8), 1);
    }

    #[test]
    fn reset_clears_streak() {
        let mut gate = ApplyRetryGate::new();
        gate.register_failure(7);
        gate.reset();
        assert_eq!(gate.register_failure(7), 1);
    }
}
