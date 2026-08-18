//! Discovery process for the `sequencer_stake` committee.

use std::collections::{BTreeMap, BTreeSet};

use log::warn;
use sequencer_stake_core::{PendingUnstake, SequencerKey, SequencerStakeConfig, StakeRecord};

/// The channel slot each leaving key was first seen gone from the live committee at.
///
/// In memory only: a restart re-stamps at the current tip and costs a pending
/// exit one more finality delay.
#[derive(Debug, Default)]
pub struct CommitteeAbsence {
    absent_since: BTreeMap<SequencerKey, u64>,
}

impl CommitteeAbsence {
    /// Records one look at the live committee, taken with the channel tip at
    /// `tip_slot`.
    pub fn observe(
        &mut self,
        live: &[SequencerKey],
        leaving: &BTreeSet<SequencerKey>,
        tip_slot: u64,
    ) {
        self.absent_since.retain(|key, _| leaving.contains(key));
        for key in leaving {
            if live.contains(key) {
                self.absent_since.remove(key);
            } else {
                self.absent_since.entry(*key).or_insert(tip_slot);
            }
        }
    }

    /// Whether the channel slot that first showed `key` gone is irreversible.
    #[must_use]
    pub fn removal_is_final(&self, key: SequencerKey, finalized_slot: Option<u64>) -> bool {
        self.absent_since
            .get(&key)
            .is_some_and(|absent_since| finalized_slot > Some(*absent_since))
    }
}

/// The accredited-keys list LEZ state says the channel should have, or `None`
/// if it already matches the live Bedrock committee.
///
/// Level-triggered: re-fires on every block where the two disagree, not just
/// the block a key crossed the minimum in, so a submission that never lands
/// on Bedrock gets retried instead of being asked for once and forgotten.
///
/// Doesn't cover channel administration params like `posting_timeframe` —
/// those are fixed constants supplied separately when building the
/// `ChannelConfigOp`.
#[must_use]
pub fn committee_update(
    state: &lee::V03State,
    live_accredited_keys: &[SequencerKey],
) -> Option<Vec<SequencerKey>> {
    let config = read_config(state)?;

    // Sorted by key bytes so the list is deterministic across calls: a
    // `ChannelConfigOp`'s `keys` field must reproduce the same order every
    // time given the same state, since Bedrock's accredited-key index is
    // positional.
    let mut desired: Vec<SequencerKey> = config
        .entries
        .iter()
        .filter(|(_, entry)| entry.net_stake() >= config.minimum_sequencer_stake)
        .map(|(key, _)| *key)
        .collect();
    desired.sort_unstable();

    if desired.is_empty() {
        warn!(
            "No staked sequencer key meets the minimum; leaving the live committee untouched \
             since a channel cannot have zero accredited keys"
        );
        return None;
    }

    let mut live = live_accredited_keys.to_vec();
    live.sort_unstable();

    (desired != live).then_some(desired)
}

/// Ownership-account id + pending-release details for every entry with a
/// pending unstake — candidates *worth attempting*, not necessarily valid yet.
///
/// Whether one is actually includable in a block is a separate check,
/// [`finalize_unstake_is_valid`], applied uniformly to every `FinalizeUnstake`
/// a block builder considers, regardless of whether it came from here (the
/// sequencer's own proactive construction) or from the mempool (anyone else
/// submitting it directly, per spec).
#[must_use]
pub fn finalize_unstake_candidates(state: &lee::V03State) -> Vec<(lee::AccountId, PendingUnstake)> {
    let Some(config) = read_config(state) else {
        return Vec::new();
    };

    config
        .entries
        .into_values()
        .filter_map(|entry| {
            let record = stake_record(state, entry.account_id)?;
            Some((entry.account_id, record.pending_unstake?))
        })
        .collect()
}

// TODO: Only checked on blocks we build, never re-checked on adoption.
/// Whether a `FinalizeUnstake` on `ownership_id` may go in a block: one that
/// removes the key waits until the removal can no longer be undone.
#[must_use]
pub fn finalize_unstake_is_valid(
    state: &lee::V03State,
    ownership_id: lee::AccountId,
    absence: &CommitteeAbsence,
    finalized_slot: Option<u64>,
) -> bool {
    let Some(record) = stake_record(state, ownership_id) else {
        return true;
    };
    if record.pending_unstake.is_none() {
        return true;
    }
    let Some(entry) =
        read_config(state).and_then(|config| config.entries.get(&record.sequencer_key).copied())
    else {
        return true;
    };

    let fully_drains = entry.net_stake() == 0;
    !fully_drains || absence.removal_is_final(record.sequencer_key, finalized_slot)
}

/// Keys whose pending release takes them out of the committee.
#[must_use]
pub fn keys_leaving_the_committee(state: &lee::V03State) -> BTreeSet<SequencerKey> {
    let Some(config) = read_config(state) else {
        return BTreeSet::new();
    };

    config
        .entries
        .into_iter()
        .filter(|(_, entry)| entry.net_stake() == 0)
        .map(|(key, _)| key)
        .collect()
}

/// Reads the `sequencer_stake` config account — a single account read, not a
/// scan, since every `Stake`/`UnstakeRequest`/`FinalizeUnstake` keeps its
/// `entries` map current as it executes. `None` only if the account is absent
/// or undecodable, which genesis rules out.
pub(crate) fn read_config(state: &lee::V03State) -> Option<SequencerStakeConfig> {
    let Some(account) =
        state.get_account_by_id_ref(system_accounts::sequencer_stake_config_account_id())
    else {
        warn!("sequencer_stake config account is absent");
        return None;
    };
    let config = SequencerStakeConfig::from_bytes(account.data.as_ref());
    if config.is_none() {
        warn!("sequencer_stake config account did not decode as SequencerStakeConfig");
    }
    config
}

/// The `StakeRecord` an ownership account carries: which key it backs, plus
/// whatever release is pending against it.
fn stake_record(state: &lee::V03State, ownership_id: lee::AccountId) -> Option<StakeRecord> {
    let account = state.get_account_by_id_ref(ownership_id)?;
    StakeRecord::from_bytes(account.data.as_ref())
}

#[must_use]
pub fn config_is_readable(state: &lee::V03State) -> bool {
    read_config(state).is_some()
}

#[cfg(test)]
mod tests {
    use lee_core::account::Account;
    use sequencer_stake_core::SequencerEntry;

    use super::*;

    const MINIMUM: u128 = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

    /// One staked key: the config entry plus the ownership account backing it.
    #[derive(Clone, Copy)]
    struct Staked {
        key: SequencerKey,
        account_id: lee::AccountId,
        /// The config entry's tracked stake.
        total: u128,
        pending: Option<PendingUnstake>,
        /// The ownership account's, which sits above `total_staked` once
        /// anyone donates to it.
        balance: u128,
    }

    impl Staked {
        fn new(tag: u8, total: u128) -> Self {
            Self {
                key: test_key(tag),
                account_id: lee::AccountId::new([tag.wrapping_add(100); 32]),
                total,
                pending: None,
                balance: total,
            }
        }

        fn pending(mut self, amount: u128) -> Self {
            self.pending = Some(PendingUnstake {
                amount,
                destination: lee::AccountId::new([200; 32]),
            });
            self
        }

        fn donated(mut self, amount: u128) -> Self {
            self.balance = self.balance.saturating_add(amount);
            self
        }
    }

    /// LEZ state holding the config account plus one ownership account per key.
    fn state_with(stakes: impl IntoIterator<Item = Staked>) -> lee::V03State {
        let stakes: Vec<Staked> = stakes.into_iter().collect();

        let ownership_accounts = stakes.iter().map(|staked| {
            (
                staked.account_id,
                Account {
                    program_owner: programs::sequencer_stake().id().into(),
                    balance: staked.balance,
                    data: StakeRecord {
                        sequencer_key: staked.key,
                        pending_unstake: staked.pending,
                    }
                    .to_bytes()
                    .try_into()
                    .expect("stake record fits"),
                    ..Account::default()
                },
            )
        });

        let config = Account {
            program_owner: programs::sequencer_stake().id().into(),
            data: SequencerStakeConfig {
                minimum_sequencer_stake: MINIMUM,
                entries: stakes
                    .iter()
                    .map(|staked| {
                        (
                            staked.key,
                            SequencerEntry {
                                account_id: staked.account_id,
                                total_staked: staked.total,
                                total_pending_unstake: staked
                                    .pending
                                    .map_or(0, |pending| pending.amount),
                            },
                        )
                    })
                    .collect(),
            }
            .to_bytes()
            .try_into()
            .expect("config fits"),
            ..Account::default()
        };

        lee::V03State::new()
            .with_public_accounts(ownership_accounts)
            .with_public_accounts([(system_accounts::sequencer_stake_config_account_id(), config)])
    }

    /// A distinct valid key per `tag`.
    fn test_key(tag: u8) -> SequencerKey {
        let bytes = crate::block_publisher::Ed25519Key::from_bytes(&[tag; 32])
            .public_key()
            .to_bytes();
        SequencerKey::new(bytes).expect("a derived public key is a curve point")
    }

    #[test]
    fn candidate_below_minimum_is_not_accredited() {
        let staked = Staked::new(1, MINIMUM - 1);

        assert!(committee_update(&state_with([staked]), &[]).is_none());
    }

    #[test]
    fn candidate_above_minimum_but_missing_live_is_added() {
        let staked = Staked::new(2, MINIMUM);

        assert_eq!(
            committee_update(&state_with([staked]), &[]),
            Some(vec![staked.key])
        );
    }

    #[test]
    fn already_matching_live_committee_is_not_re_submitted() {
        let staked = Staked::new(3, MINIMUM);

        assert!(committee_update(&state_with([staked]), &[staked.key]).is_none());
    }

    #[test]
    fn key_below_minimum_but_still_live_is_removed() {
        let exiting = Staked::new(4, MINIMUM).pending(MINIMUM);
        let staying = Staked::new(6, MINIMUM);

        assert_eq!(
            committee_update(&state_with([exiting, staying]), &[exiting.key, staying.key]),
            Some(vec![staying.key])
        );
    }

    #[test]
    fn a_pending_unstake_discounts_the_stake_backing_a_key() {
        let discounted = Staked::new(5, 2 * MINIMUM).pending(2 * MINIMUM);
        let staying = Staked::new(7, MINIMUM);

        assert_eq!(
            committee_update(
                &state_with([discounted, staying]),
                &[discounted.key, staying.key]
            ),
            Some(vec![staying.key])
        );
    }

    #[test]
    fn an_empty_committee_is_never_submitted() {
        let exiting = Staked::new(4, MINIMUM).pending(MINIMUM);

        assert_eq!(
            committee_update(&state_with([exiting]), &[exiting.key]),
            None
        );
    }

    #[test]
    fn mismatch_keeps_firing_until_live_matches() {
        // A submission that never landed on Bedrock must be retried, not
        // asked for once and forgotten.
        let state = state_with([Staked::new(8, MINIMUM)]);

        assert!(committee_update(&state, &[]).is_some());
        assert!(committee_update(&state, &[]).is_some());
    }

    #[test]
    fn accredited_keys_are_deterministically_sorted() {
        let high = Staked::new(9, MINIMUM);
        let low = Staked::new(1, MINIMUM);

        assert_eq!(
            committee_update(&state_with([high, low]), &[]),
            Some(vec![low.key, high.key])
        );
    }

    #[test]
    fn every_pending_unstake_is_a_candidate_regardless_of_validity() {
        // Even a not-yet-valid full drain is a candidate — validity is decided
        // separately, by `finalize_unstake_is_valid`, uniformly for every
        // FinalizeUnstake a block builder considers.
        let staked = Staked::new(5, MINIMUM).pending(MINIMUM);

        assert_eq!(
            finalize_unstake_candidates(&state_with([staked])),
            vec![(staked.account_id, staked.pending.unwrap())]
        );
    }

    #[test]
    fn an_entry_with_no_pending_unstake_is_not_a_candidate() {
        let staked = Staked::new(7, MINIMUM);

        assert!(finalize_unstake_candidates(&state_with([staked])).is_empty());
    }

    #[test]
    fn a_partial_release_is_always_valid() {
        let staked = Staked::new(5, MINIMUM + 10).pending(10);
        let state = state_with([staked]);

        // Neither still accredited nor anything finalized matters here.
        assert!(finalize_unstake_is_valid(
            &state,
            staked.account_id,
            &CommitteeAbsence::default(),
            None
        ));
    }

    #[test]
    fn a_full_drain_waits_for_the_removal_to_finalize() {
        let staked = Staked::new(6, MINIMUM).pending(MINIMUM);
        let state = state_with([staked]);
        let watched = BTreeSet::from([staked.key]);
        let valid = |absence: &CommitteeAbsence, finalized| {
            finalize_unstake_is_valid(&state, staked.account_id, absence, finalized)
        };

        // Never looked at, or looked at and still accredited.
        let mut absence = CommitteeAbsence::default();
        assert!(!valid(&absence, Some(100)));
        absence.observe(&[staked.key], &watched, 10);
        assert!(!valid(&absence, Some(100)));

        // Seen leaving at height 10: only a later block finalizing frees it.
        absence.observe(&[], &watched, 10);
        for finalized in [None, Some(9), Some(10)] {
            assert!(
                !valid(&absence, finalized),
                "not final yet at {finalized:?}"
            );
        }
        assert!(valid(&absence, Some(11)));
    }

    #[test]
    fn each_removal_only_frees_its_own_release() {
        let key = test_key(6);
        let watched = BTreeSet::from([key]);
        let mut absence = CommitteeAbsence::default();

        absence.observe(&[], &watched, 10);
        assert!(absence.removal_is_final(key, Some(11)));

        // Seen back in the committee: that removal no longer counts.
        absence.observe(&[key], &watched, 20);
        assert!(!absence.removal_is_final(key, Some(100)));
        absence.observe(&[], &watched, 30);
        assert!(!absence.removal_is_final(key, Some(30)));
        assert!(absence.removal_is_final(key, Some(31)));

        // FinalizeUnstake ran: nothing pending, so the note is dropped.
        absence.observe(&[], &BTreeSet::new(), 40);
        assert!(!absence.removal_is_final(key, Some(100)));
    }

    #[test]
    fn a_donated_balance_does_not_make_a_full_drain_look_partial() {
        // Measured against tracked stake, so a donation cannot hide the drain.
        let staked = Staked::new(7, MINIMUM).pending(MINIMUM).donated(1);

        assert!(!finalize_unstake_is_valid(
            &state_with([staked]),
            staked.account_id,
            &CommitteeAbsence::default(),
            Some(100)
        ));
    }

    #[test]
    fn only_keys_a_release_would_remove_are_watched() {
        // A key that stays in the committee has no removal to wait for.
        let exiting = Staked::new(4, MINIMUM).pending(MINIMUM);
        let staying = Staked::new(6, MINIMUM);
        let shrinking = Staked::new(8, 2 * MINIMUM).pending(MINIMUM);

        assert_eq!(
            keys_leaving_the_committee(&state_with([exiting, staying, shrinking])),
            BTreeSet::from([exiting.key])
        );
    }
}
