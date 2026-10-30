//! Full stake releases, which a block may hold only for keys whose removal config is final.

use std::collections::{BTreeMap, BTreeSet};

use common::{block::Block, transaction::LeeTransaction};
use lee::V03State;
use sequencer_stake_core::{Message, SequencerEntry, SequencerKey, SequencerStakeConfig};

/// The stake entries the config account holds in `state`, empty when it does not decode.
#[must_use]
pub fn stake_entries(state: &V03State) -> BTreeMap<SequencerKey, SequencerEntry> {
    state
        .get_account_by_id_ref(system_accounts::sequencer_stake_config_account_id())
        .and_then(|account| {
            SequencerStakeConfig::from_bytes(
                account
                    .data
                    .actor_state(programs::sequencer_stake_account_id()),
            )
        })
        .map(|config| config.entries)
        .unwrap_or_default()
}

/// Whether `tx` can release a stake: it names the stake config account, as every write to it
/// must, and is not a public `Slash`.
#[must_use]
pub fn can_release_stake(tx: &LeeTransaction) -> bool {
    tx.affected_public_account_ids()
        .contains(&system_accounts::sequencer_stake_config_account_id())
        && !matches!(stake_message(tx), Some(Message::Slash { .. }))
}

/// Keys whose whole stake was pending unstake in `before` and whose entry is gone from `after`.
#[must_use]
pub fn full_releases(
    before: &BTreeMap<SequencerKey, SequencerEntry>,
    after: &BTreeMap<SequencerKey, SequencerEntry>,
) -> Vec<SequencerKey> {
    before
        .iter()
        .filter(|(key, entry)| is_fully_pending(entry) && !after.contains_key(key))
        .map(|(key, _)| *key)
        .collect()
}

/// Keys the public `FinalizeUnstake` calls of `block` name, the only ones it can release in full.
#[must_use]
pub fn finalize_unstake_keys(block: &Block) -> BTreeSet<SequencerKey> {
    block
        .body
        .transactions
        .iter()
        .filter_map(finalize_unstake_key)
        .collect()
}

/// The key a public `FinalizeUnstake` call names.
#[must_use]
pub fn finalize_unstake_key(tx: &LeeTransaction) -> Option<SequencerKey> {
    if let Message::FinalizeUnstake { sequencer_key } = stake_message(tx)? {
        Some(sequencer_key)
    } else {
        None
    }
}

/// Keys whose whole stake is pending release in `entries`.
#[must_use]
pub fn fully_pending_keys(
    entries: &BTreeMap<SequencerKey, SequencerEntry>,
) -> BTreeSet<SequencerKey> {
    entries
        .iter()
        .filter(|(_, entry)| is_fully_pending(entry))
        .map(|(key, _)| *key)
        .collect()
}

fn is_fully_pending(entry: &SequencerEntry) -> bool {
    entry
        .pending_unstake
        .is_some_and(|pending| pending.amount == entry.total_staked)
}

/// The stake program message a public transaction's root call carries.
fn stake_message(tx: &LeeTransaction) -> Option<Message> {
    let (to, message) = tx.public_call()?;
    (to.program_account_id == programs::sequencer_stake_account_id())
        .then(|| borsh::from_slice(message).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use lee::AccountId;
    use sequencer_stake_core::PendingUnstake;

    use super::*;

    fn key(seed: u8) -> SequencerKey {
        let signing = sequencer_stake_core::ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        SequencerKey::new(signing.verifying_key().to_bytes()).expect("a derived key is valid")
    }

    fn entry(total_staked: u128, pending: Option<u128>) -> SequencerEntry {
        SequencerEntry {
            account_id: AccountId::new([1; 32]),
            total_staked,
            pending_unstake: pending.map(|amount| PendingUnstake {
                amount,
                destination: AccountId::new([2; 32]),
            }),
        }
    }

    fn entries(
        list: impl IntoIterator<Item = (SequencerKey, SequencerEntry)>,
    ) -> BTreeMap<SequencerKey, SequencerEntry> {
        list.into_iter().collect()
    }

    #[test]
    fn a_dropped_entry_whose_whole_stake_was_pending_is_a_full_release() {
        let before = entries([(key(1), entry(10, Some(10))), (key(2), entry(10, None))]);
        let after = entries([(key(2), entry(10, None))]);
        assert_eq!(full_releases(&before, &after), vec![key(1)]);
    }

    #[test]
    fn a_partial_release_is_not_a_full_one() {
        let before = entries([(key(1), entry(10, Some(4)))]);
        let after = entries([(key(1), entry(6, None))]);
        assert!(full_releases(&before, &after).is_empty());
    }

    #[test]
    fn a_fully_pending_entry_still_held_is_not_released() {
        let before = entries([(key(1), entry(10, Some(10)))]);
        assert!(full_releases(&before, &before).is_empty());
    }

    #[test]
    fn only_fully_pending_entries_are_candidates() {
        let held = entries([
            (key(1), entry(10, Some(10))),
            (key(2), entry(10, Some(3))),
            (key(3), entry(10, None)),
        ]);
        assert_eq!(fully_pending_keys(&held), [key(1)].into());
    }
}
