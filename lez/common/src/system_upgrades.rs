//! `system_upgrader` transactions and the upgrade records they leave.

use lee::V03State;
use lee_core::BlockId;
use system_upgrader_core::{
    Registry, SYSTEM_UPGRADER_ACCOUNT_ID, ScheduledUpgrade, SystemProgramName, registry_account_id,
};

use crate::transaction::LeeTransaction;

/// `system_upgrader`'s registry: every upgradable system program and its pending upgrade.
#[must_use]
pub fn registry(state: &V03State) -> Registry {
    state
        .get_account_by_id_ref(registry_account_id())
        .and_then(|account| {
            Registry::from_bytes(account.data.actor_state(SYSTEM_UPGRADER_ACCOUNT_ID))
        })
        .unwrap_or_default()
}

/// The system program whose upgrade activates in block `block_id`, if any: that block must carry
/// its `Apply`.
#[must_use]
pub fn due_at(state: &V03State, block_id: BlockId) -> Option<SystemProgramName> {
    registry(state)
        .programs
        .into_iter()
        .find_map(|(name, upgrade)| {
            upgrade
                .filter(|upgrade| upgrade.activation_height == block_id)
                .map(|_| name)
        })
}

/// The upgrade scheduled for the system program `name`, if any.
#[must_use]
pub fn scheduled_upgrade(state: &V03State, name: &SystemProgramName) -> Option<ScheduledUpgrade> {
    registry(state).scheduled(name)
}

/// Whether `tx` invokes `system_upgrader`. Only the block producer includes one, at most one per
/// block, directly before its fee transaction.
#[must_use]
pub fn is_system_upgrader_tx(tx: &LeeTransaction) -> bool {
    tx.public_call()
        .is_some_and(|(to, _)| to.program_account_id == SYSTEM_UPGRADER_ACCOUNT_ID)
}
