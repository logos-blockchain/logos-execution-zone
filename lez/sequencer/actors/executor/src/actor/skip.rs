use std::collections::HashMap;

use chain_state::{Blocker, ChainState, ChannelEntry, stake_config};
use log::info;
use sequencer_bedrock_actor::protocol::Slot;
use sequencer_core::{MsgId, config::ChannelParams};
use tokio::time::{Duration, Instant};

use crate::actor::turn::Turn;

/// When our turn builds on the head tip past a block the head has not executed, skipping it.
#[derive(Default)]
pub struct SkipPolicy {
    /// When each view entry was first seen.
    first_seen: HashMap<MsgId, Instant>,
    /// The block first found past the head tip in our turn, and when.
    blocked: Option<(MsgId, Instant)>,
    /// The block this turn logged a hold for.
    logged: Option<MsgId>,
}

impl SkipPolicy {
    /// Keeps when each of `view`'s entries was first seen.
    pub fn observe(&mut self, view: &[ChannelEntry]) {
        let now = Instant::now();
        self.first_seen = view
            .iter()
            .map(|entry| {
                let seen = self.first_seen.get(&entry.msg).copied().unwrap_or(now);
                (entry.msg, seen)
            })
            .collect();
    }

    /// Logs holds afresh, for a new turn of ours.
    pub const fn start_turn(&mut self) {
        self.logged = None;
    }

    /// Whether this turn builds on `chain`'s head tip, which skips the block past it, if any.
    pub fn may_produce(&mut self, chain: &ChainState, own: [u8; 32], turn: &Turn) -> bool {
        self.observe(chain.view());
        let Some(blocker) = chain.blocker() else {
            return true;
        };
        let held = stake_config::channel_params(chain.head_state())
            .ok_or("the head state sets no channel params")
            .and_then(|params| self.hold(&blocker, chain.fold_stopped(), own, &params, turn));
        if let Err(reason) = held
            && self.logged != Some(blocker.msg)
        {
            self.logged = Some(blocker.msg);
            info!(
                "Holding production at channel entry {}: {reason}",
                blocker.msg
            );
        }
        held.is_ok()
    }

    /// Why this turn may not skip `blocker`.
    fn hold(
        &mut self,
        blocker: &Blocker,
        stopped: bool,
        own: [u8; 32],
        params: &ChannelParams,
        turn: &Turn,
    ) -> Result<(), &'static str> {
        let now = Instant::now();
        let blocked = self
            .blocked
            .filter(|&(msg, _)| msg == blocker.msg)
            .unwrap_or((blocker.msg, now));
        self.blocked = Some(blocked);
        // A failed block past its window leaves the branch before ours is placed.
        if blocker.dead
            && let (Some(slot), Some(current)) = (blocker.slot, turn.slot_at(now))
            && current
                > slot
                    .into_inner()
                    .saturating_add(u64::from(params.skip_window))
        {
            return Ok(());
        }
        if !blocker.private || !blocker.in_run {
            return Err("not a private block of the unconfirmed run");
        }
        if blocker.signer == Some(own) {
            return Err("our own block");
        }
        if stopped {
            return Err("the fold stopped behind it");
        }
        let (_, since) = blocked;
        let wait = Duration::from_secs(u64::from(
            params
                .posting_timeout
                .checked_div(2)
                .expect("the divisor is not zero"),
        ));
        if !blocker.dead && now.saturating_duration_since(since) < wait {
            return Err("waiting for its proofs");
        }
        let current = turn.slot_at(now).ok_or("the current slot is unknown")?;
        let start = blocker
            .slot
            .map(Slot::into_inner)
            .or_else(|| turn.slot_at(*self.first_seen.get(&blocker.msg)?))
            .ok_or("the current slot is unknown")?;
        if current.saturating_add(u64::from(params.posting_timeout))
            > start.saturating_add(u64::from(params.skip_window))
        {
            return Err("too late in its skip window");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::advance;

    use super::*;

    const OWN: [u8; 32] = [1; 32];
    const PEER: [u8; 32] = [2; 32];
    /// The slot the block past the head tip finalized in.
    const BLOCKER_SLOT: u64 = 5;
    /// Slots after a private block within which another writer may skip it.
    const SKIP_WINDOW: u32 = 10;
    /// Two slots, so a producer waits one second for a missing proof.
    const POSTING_TIMEOUT: u32 = 2;
    const WAIT: Duration = Duration::from_secs(1);
    const PARAMS: ChannelParams = ChannelParams {
        minimum_sequencer_stake: 0,
        posting_timeframe: 30,
        posting_timeout: POSTING_TIMEOUT,
        skip_window: SKIP_WINDOW,
        exit_delay: 0,
        max_block_size: 0,
    };

    /// A private block of the unconfirmed run, final at [`BLOCKER_SLOT`]: failed if `dead`, else
    /// missing its proofs.
    fn blocker(signer: [u8; 32], dead: bool) -> Blocker {
        Blocker {
            msg: MsgId::from([7; 32]),
            signer: Some(signer),
            private: true,
            slot: Some(Slot::from(BLOCKER_SLOT)),
            dead,
            in_run: true,
        }
    }

    /// Our turn, which Bedrock reports started at `slot` just now.
    fn turn_from(slot: u64) -> Turn {
        let mut turn = Turn::new(false);
        turn.update(true, Some(Slot::from(slot)));
        turn
    }

    #[tokio::test(start_paused = true)]
    async fn a_block_missing_its_proofs_holds_the_turn_until_the_wait_has_passed() {
        let mut policy = SkipPolicy::default();
        let missing = blocker(PEER, false);
        let turn = turn_from(BLOCKER_SLOT + 1);

        assert_eq!(
            policy.hold(&missing, false, OWN, &PARAMS, &turn),
            Err("waiting for its proofs")
        );
        advance(WAIT.saturating_sub(Duration::from_millis(1))).await;
        assert_eq!(
            policy.hold(&missing, false, OWN, &PARAMS, &turn),
            Err("waiting for its proofs")
        );
        advance(Duration::from_millis(1)).await;
        assert_eq!(policy.hold(&missing, false, OWN, &PARAMS, &turn), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_block_another_writer_built_on_holds_the_turn_past_the_wait() {
        let mut policy = SkipPolicy::default();
        let built_on = Blocker {
            in_run: false,
            ..blocker(PEER, false)
        };
        let turn = turn_from(BLOCKER_SLOT + 1);

        assert_eq!(
            policy.hold(&built_on, false, OWN, &PARAMS, &turn),
            Err("not a private block of the unconfirmed run")
        );
        advance(WAIT).await;
        assert_eq!(
            policy.hold(&built_on, false, OWN, &PARAMS, &turn),
            Err("not a private block of the unconfirmed run")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_block_missing_its_proofs_holds_the_turn_once_a_skip_could_land_past_its_window() {
        let mut policy = SkipPolicy::default();
        let missing = blocker(PEER, false);
        let last = BLOCKER_SLOT + u64::from(SKIP_WINDOW - POSTING_TIMEOUT);

        assert_eq!(
            policy.hold(&missing, false, OWN, &PARAMS, &turn_from(last)),
            Err("waiting for its proofs")
        );
        advance(WAIT).await;
        let (in_time, late) = (turn_from(last), turn_from(last.saturating_add(1)));
        assert_eq!(policy.hold(&missing, false, OWN, &PARAMS, &in_time), Ok(()));
        assert_eq!(
            policy.hold(&missing, false, OWN, &PARAMS, &late),
            Err("too late in its skip window")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_failed_block_stops_holding_the_turn_once_past_its_window() {
        let mut policy = SkipPolicy::default();
        let end = BLOCKER_SLOT + u64::from(SKIP_WINDOW);
        let past = turn_from(end.saturating_add(1));

        assert_eq!(
            policy.hold(&blocker(OWN, true), false, OWN, &PARAMS, &turn_from(end)),
            Err("our own block")
        );
        assert_eq!(
            policy.hold(&blocker(OWN, true), false, OWN, &PARAMS, &past),
            Ok(())
        );
        assert_eq!(
            policy.hold(&blocker(OWN, false), false, OWN, &PARAMS, &past),
            Err("our own block")
        );
    }
}
