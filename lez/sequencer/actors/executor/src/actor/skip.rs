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
