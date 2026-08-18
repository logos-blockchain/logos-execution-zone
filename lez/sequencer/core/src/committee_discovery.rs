//! Discovery process for the `sequencer_stake` committee.

use log::warn;
use sequencer_stake_core::{PendingUnstake, SequencerKey, SequencerStakeConfig, StakeRecord};

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

/// Block-validity rule for a `FinalizeUnstake` on `ownership_id`.
///
/// A partial release is always valid: `UnstakeRequest` already guarantees it
/// leaves the key at or above the minimum, so committee membership is
/// unaffected. A full drain — measured against tracked stake, not balance,
/// which anyone can inflate — is valid only once the key is no longer
/// accredited. An unknown account, no pending request, or no config entry
/// also counts as valid; the program itself rejects those cases anyway.
///
/// TODO: checks live Bedrock membership, not an ordered history walk like the
/// spec calls for. Fine for the sequencer building the next block, but a
/// follower re-checking an already-adopted block has no independent way to
/// verify it this way. Switch once zone-sdk exposes ordered `ChannelConfigOp`
/// data to LEZ.
#[must_use]
pub fn finalize_unstake_is_valid(
    state: &lee::V03State,
    ownership_id: lee::AccountId,
    live_accredited_keys: &[SequencerKey],
) -> bool {
    let Some(record) = stake_record(state, ownership_id) else {
        return true;
    };
    let Some(pending) = record.pending_unstake else {
        return true;
    };
    let Some(entry) =
        read_config(state).and_then(|config| config.entries.get(&record.sequencer_key).copied())
    else {
        return true;
    };

    let fully_drains = entry.total_staked == pending.amount;
    !fully_drains || !live_accredited_keys.contains(&record.sequencer_key)
}

/// Reads the `sequencer_stake` config account — a single account read, not a
/// scan, since every `Stake`/`UnstakeRequest`/`FinalizeUnstake` keeps its
/// `entries` map current as it executes. `None` only if the account is absent
/// or undecodable, which genesis rules out.
fn read_config(state: &lee::V03State) -> Option<SequencerStakeConfig> {
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

        assert!(finalize_unstake_is_valid(
            &state,
            staked.account_id,
            &[staked.key]
        ));
        assert!(finalize_unstake_is_valid(&state, staked.account_id, &[]));
    }

    #[test]
    fn a_full_drain_is_valid_only_once_absent_from_the_live_committee() {
        let staked = Staked::new(6, MINIMUM).pending(MINIMUM);
        let state = state_with([staked]);

        assert!(!finalize_unstake_is_valid(
            &state,
            staked.account_id,
            &[staked.key]
        ));
        assert!(finalize_unstake_is_valid(&state, staked.account_id, &[]));
    }

    #[test]
    fn a_donated_balance_does_not_make_a_full_drain_look_partial() {
        // The drain is measured against the tracked stake, so a donation
        // sitting on the ownership account does not reclassify it as partial.
        let staked = Staked::new(7, MINIMUM).pending(MINIMUM).donated(1);

        assert!(!finalize_unstake_is_valid(
            &state_with([staked]),
            staked.account_id,
            &[staked.key]
        ));
    }
}
