use log::warn;
use sequencer_stake_core::{ChannelParams, SequencerStakeConfig};

/// Reads the `sequencer_stake` config account.
///
/// A single account read, not a scan, since every
/// `Stake`/`UnstakeRequest`/`FinalizeUnstake` keeps its `entries` map current
/// as it executes. `None` only if the account is absent or undecodable, which
/// genesis rules out.
#[must_use]
pub fn read_config(state: &lee::V03State) -> Option<SequencerStakeConfig> {
    let Some(account) =
        state.get_account_by_id_ref(system_accounts::sequencer_stake_config_account_id())
    else {
        warn!("sequencer_stake config account is absent");
        return None;
    };
    let sequencer_stake_program_id = sequencer_stake_core::sequencer_stake_account_id();
    let config = SequencerStakeConfig::from_bytes(
        account
            .data
            .actor_state(sequencer_stake_program_id)
            .as_ref(),
    );
    if config.is_none() {
        warn!("sequencer_stake config account did not decode as SequencerStakeConfig");
    }
    config
}

/// Channel posting params from the config account. `None` before genesis set
/// them, which a live chain rules out.
#[must_use]
pub fn channel_params(state: &lee::V03State) -> Option<ChannelParams> {
    read_config(state)?.channel_params
}
