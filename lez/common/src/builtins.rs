//! System builtins `builtin_loader` can upgrade, and the block-level rule that a scheduled
//! upgrade is applied by its block.

use builtin_loader_core::{BUILTIN_LOADER_ACCOUNT_ID, ScheduledUpgrade};
use lee::{AccountId, V03State};
use lee_core::BlockId;

/// The system builtins `builtin_loader` upgrades.
///
/// `token`, `amm` and `ata` are not among them: they stay fixed until removed from the builtins.
/// The cross-zone ones exist only on cross-zone zones; elsewhere their accounts are empty and
/// never hold a schedule.
pub const UPGRADABLE_BUILTINS: [&[u8]; 10] = [
    &programs::CLOCK_NAME,
    &programs::FEE_NAME,
    &programs::BRIDGE_NAME,
    &programs::SEQUENCER_STAKE_NAME,
    &programs::CROSS_ZONE_INBOX_NAME,
    &programs::CROSS_ZONE_OUTBOX_NAME,
    &programs::BRIDGE_LOCK_NAME,
    &programs::WRAPPED_TOKEN_NAME,
    &programs::PING_SENDER_NAME,
    &programs::PING_RECEIVER_NAME,
];

/// The upgrade scheduled for the builtin `name`, if any.
#[must_use]
pub fn scheduled_upgrade(state: &V03State, name: &[u8]) -> Option<ScheduledUpgrade> {
    let account = state.get_account_by_id_ref(AccountId::from_builtin_program_name(name))?;
    ScheduledUpgrade::from_bytes(account.data.shard(BUILTIN_LOADER_ACCOUNT_ID))
}

/// The first upgradable builtin whose upgrade was due by `block_id` but is still scheduled.
///
/// A block that leaves one is invalid: `Apply` clears the schedule, so "upgraded by its block" is
/// a check on the state after the block.
#[must_use]
pub fn overdue_builtin_upgrade(state: &V03State, block_id: BlockId) -> Option<&'static [u8]> {
    UPGRADABLE_BUILTINS.into_iter().find(|name| {
        scheduled_upgrade(state, name).is_some_and(|upgrade| upgrade.from_height <= block_id)
    })
}

#[cfg(test)]
mod tests {
    use lee::Account;

    use super::*;

    fn state_with_clock_scheduled_from(from_height: BlockId) -> V03State {
        let upgrade = ScheduledUpgrade {
            first_segment: AccountId::new([7; 32]),
            from_height,
        };
        V03State::new().with_public_accounts([(
            AccountId::from_builtin_program_name(&programs::CLOCK_NAME),
            Account::default().with_shard(
                BUILTIN_LOADER_ACCOUNT_ID,
                upgrade.to_bytes().try_into().unwrap(),
            ),
        )])
    }

    #[test]
    fn a_schedule_is_overdue_from_its_height() {
        let state = state_with_clock_scheduled_from(5);

        assert_eq!(overdue_builtin_upgrade(&state, 4), None);
        assert_eq!(
            overdue_builtin_upgrade(&state, 5),
            Some(&programs::CLOCK_NAME[..])
        );
        assert_eq!(
            overdue_builtin_upgrade(&state, 6),
            Some(&programs::CLOCK_NAME[..])
        );
    }

    #[test]
    fn nothing_is_overdue_without_a_schedule() {
        assert_eq!(overdue_builtin_upgrade(&V03State::new(), 100), None);
    }
}
