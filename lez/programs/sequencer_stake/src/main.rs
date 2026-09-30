use std::collections::btree_map::Entry;

use lee_core::{
    BlockId,
    account::{AccountId, ProgramShardSelector},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID, custody_transfer},
    program::{AccountMeta, BlockValidityWindow, ChainedCall, Plan, PlanInput, run_program},
};
use sequencer_stake_core::{
    ChannelParams, Instruction, PendingUnstake, SequencerEntry, SequencerKey, SequencerStakeConfig,
    SlashApproval, StakeRecord, UNSTAKE_REQUEST_WINDOW,
    ed25519_dalek::{Signature, VerifyingKey},
    sequencer_stake_config_account_id, slash_approval_message, slash_approval_threshold,
    slash_sink_account_id, stake_funds_account_id, stake_funds_seed,
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    OpenStake {
        sequencer_key: SequencerKey,
        has_record: bool,
    },
    RecordStake {
        sequencer_key: SequencerKey,
        ownership_account_id: AccountId,
        amount: u128,
        has_record: bool,
    },
    RequestUnstake {
        sequencer_key: SequencerKey,
        amount: u128,
        destination: AccountId,
        requested_at: BlockId,
    },
    TrackUnstakeRequest {
        sequencer_key: SequencerKey,
        ownership_account_id: AccountId,
        amount: u128,
    },
    /// `FinalizeUnstake` carries no signature, so the ownership record is the only thing that
    /// says this release was ever requested, for this amount, to this destination.
    ReleaseUnstake {
        sequencer_key: SequencerKey,
        amount: u128,
        destination: AccountId,
        requested_at: BlockId,
    },
    SettleUnstake {
        sequencer_key: SequencerKey,
        ownership_account_id: AccountId,
        amount: u128,
        exit_delay: u64,
    },
    ClearForSlash {
        sequencer_key: SequencerKey,
    },
    ApplySlash {
        sequencer_key: SequencerKey,
        ownership_account_id: AccountId,
        inscription: [u8; 32],
        approvals: Vec<SlashApproval>,
        total_staked: u128,
    },
    InitChannelParams {
        channel_params: ChannelParams,
        channel_id: [u8; 32],
    },
}

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    Some(match effect {
        Effect::OpenStake {
            sequencer_key,
            has_record,
        } => {
            // The stake shard remains after a full exit, so presence is what distinguishes a
            // new stake from a top-up.
            assert_eq!(
                !pre_data.is_empty(),
                has_record,
                "stake claims an ownership record this account does not match"
            );
            if has_record {
                let record = StakeRecord::from_bytes(pre_data)
                    .expect("ownership record should decode as StakeRecord");
                assert_eq!(
                    record.sequencer_key, sequencer_key,
                    "ownership account backs a different sequencer key"
                );
                assert!(
                    record.pending_unstake.is_none(),
                    "cannot top up while an unstake request is pending"
                );
            }
            StakeRecord {
                sequencer_key,
                pending_unstake: None,
            }
            .to_bytes()
        }
        Effect::RecordStake {
            sequencer_key,
            ownership_account_id,
            amount,
            has_record,
        } => {
            let mut config = decode_config(pre_data);
            assert!(
                amount >= channel_params(&config).minimum_sequencer_stake,
                "a stake or top-up must add at least the minimum"
            );
            match config.entries.entry(sequencer_key) {
                Entry::Occupied(mut occupied) => {
                    assert!(
                        has_record,
                        "this sequencer key already has an ownership account"
                    );
                    let entry = occupied.get_mut();
                    assert_eq!(
                        entry.account_id, ownership_account_id,
                        "config entry points at a different ownership account"
                    );
                    entry.total_staked = entry
                        .total_staked
                        .checked_add(amount)
                        .expect("total staked overflow");
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(SequencerEntry {
                        account_id: ownership_account_id,
                        total_staked: amount,
                        total_pending_unstake: 0,
                    });
                }
            }
            config.to_bytes()
        }
        Effect::RequestUnstake {
            sequencer_key,
            amount,
            destination,
            requested_at,
        } => {
            let mut record = decode_record(pre_data);
            assert_eq!(
                record.sequencer_key, sequencer_key,
                "ownership account backs a different sequencer key"
            );
            assert!(
                record.pending_unstake.is_none(),
                "an unstake request is already pending"
            );
            record.pending_unstake = Some(PendingUnstake {
                amount,
                destination,
                requested_at,
            });
            record.to_bytes()
        }
        Effect::TrackUnstakeRequest {
            sequencer_key,
            ownership_account_id,
            amount,
        } => {
            let mut config = decode_config(pre_data);
            let minimum_sequencer_stake = channel_params(&config).minimum_sequencer_stake;
            let entry = entry_of(&mut config, sequencer_key, ownership_account_id);
            // Sized against the tracked stake, never the account balance: anyone can
            // credit any account, so balance can exceed `total_staked`.
            assert!(
                entry.allows_unstake_request(amount, minimum_sequencer_stake),
                "unstake request must be covered by the staked total and leave the key at zero or at/above the minimum"
            );
            entry.total_pending_unstake = entry
                .total_pending_unstake
                .checked_add(amount)
                .expect("total pending unstake overflow");
            config.to_bytes()
        }
        Effect::ReleaseUnstake {
            sequencer_key,
            amount,
            destination,
            requested_at,
        } => {
            let mut record = decode_record(pre_data);
            assert_eq!(
                record.sequencer_key, sequencer_key,
                "ownership account backs a different sequencer key"
            );
            let pending = record
                .pending_unstake
                .take()
                .expect("no unstake request pending on this account");
            assert_eq!(
                pending.amount, amount,
                "amount does not match the recorded unstake request"
            );
            assert_eq!(
                pending.destination, destination,
                "destination does not match the recorded unstake request"
            );
            assert_eq!(
                pending.requested_at, requested_at,
                "request date does not match the recorded unstake request"
            );
            record.to_bytes()
        }
        Effect::SettleUnstake {
            sequencer_key,
            ownership_account_id,
            amount,
            exit_delay,
        } => {
            let mut config = decode_config(pre_data);
            assert_eq!(
                channel_params(&config).exit_delay,
                exit_delay,
                "exit delay does not match the channel params"
            );
            let entry = entry_of(&mut config, sequencer_key, ownership_account_id);
            entry.total_staked = entry
                .total_staked
                .checked_sub(amount)
                .expect("total staked underflow");
            entry.total_pending_unstake = entry
                .total_pending_unstake
                .checked_sub(amount)
                .expect("total pending unstake underflow");
            if entry.total_staked == 0 {
                config.entries.remove(&sequencer_key);
            }
            config.to_bytes()
        }
        Effect::ClearForSlash { sequencer_key } => {
            let mut record = decode_record(pre_data);
            assert_eq!(
                record.sequencer_key, sequencer_key,
                "ownership account backs a different sequencer key"
            );
            // The whole tracked stake burns, including any pending unstake.
            record.pending_unstake = None;
            record.to_bytes()
        }
        Effect::ApplySlash {
            sequencer_key,
            ownership_account_id,
            inscription,
            approvals,
            total_staked,
        } => {
            let mut config = decode_config(pre_data);
            // The approvals are the whole authorization, and accreditation is this config's
            // own answer.
            verify_approvals(&config, sequencer_key, inscription, &approvals);
            let entry = config
                .entries
                .remove(&sequencer_key)
                .expect("slashed key must have a config entry");
            assert_eq!(
                entry.account_id, ownership_account_id,
                "config entry points at a different ownership account"
            );
            assert_eq!(
                entry.total_staked, total_staked,
                "slash must burn exactly the stake this config tracks"
            );
            config.to_bytes()
        }
        Effect::InitChannelParams {
            channel_params,
            channel_id,
        } => {
            let mut config = decode_config(pre_data);
            assert!(
                config.channel_params.is_none(),
                "channel params are already set and cannot be changed"
            );
            config.channel_params = Some(channel_params);
            config.channel_id = Some(channel_id);
            config.to_bytes()
        }
    })
}

fn decode_config(pre_data: &[u8]) -> SequencerStakeConfig {
    SequencerStakeConfig::from_bytes(pre_data)
        .expect("config account data should decode as SequencerStakeConfig")
}

fn decode_record(pre_data: &[u8]) -> StakeRecord {
    StakeRecord::from_bytes(pre_data).expect("ownership account should decode as StakeRecord")
}

fn entry_of(
    config: &mut SequencerStakeConfig,
    sequencer_key: SequencerKey,
    ownership_account_id: AccountId,
) -> &mut SequencerEntry {
    let entry = config
        .entries
        .get_mut(&sequencer_key)
        .expect("staked key must already have a config entry");
    assert_eq!(
        entry.account_id, ownership_account_id,
        "config entry points at a different ownership account"
    );
    entry
}

fn verify_approvals(
    config: &SequencerStakeConfig,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: &[SlashApproval],
) {
    let message = slash_approval_message(channel_id(config), sequencer_key, inscription);

    let mut approvers: Vec<SequencerKey> = Vec::with_capacity(approvals.len());
    for approval in approvals {
        assert!(
            config.is_accredited_committee_member(&approval.signer),
            "approval from a key this config does not accredit"
        );
        assert!(
            !approvers.contains(&approval.signer),
            "the same key approved twice"
        );

        let verifying_key = VerifyingKey::from_bytes(&approval.signer.to_bytes())
            .expect("a SequencerKey is a valid Ed25519 public key");
        let signature = Signature::from_slice(&approval.signature)
            .expect("approval signature should be 64 bytes");
        verifying_key
            .verify_strict(&message, &signature)
            .expect("approval signature should verify against its signer");

        approvers.push(approval.signer);
    }

    assert!(
        approvers.len() >= slash_approval_threshold(config.accredited_committee_members_count()),
        "slash carries fewer approvals than the threshold"
    );
}

const fn channel_params(config: &SequencerStakeConfig) -> ChannelParams {
    config
        .channel_params
        .expect("genesis sets the channel params before any stake exists")
}

/// The channel genesis fixed, on the same terms as [`channel_params`].
const fn channel_id(config: &SequencerStakeConfig) -> [u8; 32] {
    config
        .channel_id
        .expect("genesis sets the channel id before any stake exists")
}

/// Other accounts also hold this program's shards, so the config is pinned by address.
fn assert_config_account(config_account: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config_account.account_id,
        sequencer_stake_config_account_id(self_account_id),
        "not the sequencer_stake config account"
    );
}

fn assert_funds_account(self_account_id: AccountId, ownership: &AccountMeta, funds: &AccountMeta) {
    assert_eq!(
        funds.account_id,
        stake_funds_account_id(self_account_id, &ownership.account_id),
        "not the stake funds account of this ownership account"
    );
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    match instruction {
        Instruction::Stake {
            sequencer_key,
            amount,
            has_record,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "Stake is only invoked as a top-level user transaction"
            );
            stake(input, sequencer_key, amount, has_record)
        }
        Instruction::UnstakeRequest {
            sequencer_key,
            amount,
            destination,
            requested_at,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "UnstakeRequest is only invoked as a top-level user transaction"
            );
            unstake_request(input, sequencer_key, amount, destination, requested_at)
        }
        Instruction::FinalizeUnstake {
            sequencer_key,
            amount,
            requested_at,
            exit_delay,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "FinalizeUnstake is only invoked as a top-level user transaction"
            );
            finalize_unstake(input, sequencer_key, amount, requested_at, exit_delay)
        }
        Instruction::InitChannelParams { params, channel_id } => {
            assert!(
                input.caller_account_id.is_none(),
                "InitChannelParams is only invoked as a top-level user transaction"
            );
            init_channel_params(input, params, channel_id)
        }
        Instruction::Slash {
            sequencer_key,
            inscription,
            approvals,
            total_staked,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "Slash is only invoked as a top-level user transaction"
            );
            slash(input, sequencer_key, inscription, approvals, total_staked)
        }
    }
}

fn stake(input: &PlanInput, sequencer_key: SequencerKey, amount: u128, has_record: bool) -> Plan {
    let self_account_id = input.self_account_id;
    let [funding_account, ownership_account, funds_account, config_account] =
        <&[_; 4]>::try_from(input.accounts.as_slice()).expect(
            "Stake requires a funding account, an ownership account, the stake funds account, and the config account",
        );

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );
    assert_funds_account(self_account_id, ownership_account, funds_account);
    assert_config_account(config_account, self_account_id);

    let mut plan = Plan::new(input);
    plan.effect(
        ownership_account,
        &Effect::OpenStake {
            sequencer_key,
            has_record,
        },
    );
    plan.effect(
        config_account,
        &Effect::RecordStake {
            sequencer_key,
            ownership_account_id: ownership_account.account_id,
            amount,
            has_record,
        },
    );

    plan.call(ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::native_balance(funding_account.account_id),
            ProgramShardSelector::native_balance(funds_account.account_id),
        ],
        &native_token::Instruction::Transfer { amount },
    ));
    plan
}

/// The blocks an `UnstakeRequest` dated `requested_at` may land in, so the date is never
/// earlier than the block that records it.
fn request_window(requested_at: BlockId) -> BlockValidityWindow {
    (requested_at.saturating_sub(UNSTAKE_REQUEST_WINDOW)..requested_at.saturating_add(1))
        .try_into()
        .expect("a request window is never empty")
}

fn unstake_request(
    input: &PlanInput,
    sequencer_key: SequencerKey,
    amount: u128,
    destination: AccountId,
    requested_at: BlockId,
) -> Plan {
    let self_account_id = input.self_account_id;
    let [ownership_account, config_account] = <&[_; 2]>::try_from(input.accounts.as_slice())
        .expect("UnstakeRequest requires the ownership account and the config account");

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );
    assert_config_account(config_account, self_account_id);

    // Only data changes here; the transfer happens in FinalizeUnstake.
    let mut plan = Plan::new(input);
    plan.block_window(request_window(requested_at));
    plan.effect(
        ownership_account,
        &Effect::RequestUnstake {
            sequencer_key,
            amount,
            destination,
            requested_at,
        },
    );
    plan.effect(
        config_account,
        &Effect::TrackUnstakeRequest {
            sequencer_key,
            ownership_account_id: ownership_account.account_id,
            amount,
        },
    );
    plan
}

fn finalize_unstake(
    input: &PlanInput,
    sequencer_key: SequencerKey,
    amount: u128,
    requested_at: BlockId,
    exit_delay: u64,
) -> Plan {
    let self_account_id = input.self_account_id;
    let [ownership_account, funds_account, destination_account, config_account] =
        <&[_; 4]>::try_from(input.accounts.as_slice()).expect(
            "FinalizeUnstake requires the ownership account, the stake funds account, a destination account, and the config account",
        );

    assert_funds_account(self_account_id, ownership_account, funds_account);
    assert_config_account(config_account, self_account_id);
    let ownership_id = ownership_account.account_id;

    // No signature check: already authorized back in UnstakeRequest. That is exactly why the
    // release below may only be sized and addressed by what the record turns out to hold.
    let mut plan = Plan::new(input);
    plan.block_window(requested_at.saturating_add(exit_delay)..);
    plan.effect(
        ownership_account,
        &Effect::ReleaseUnstake {
            sequencer_key,
            amount,
            destination: destination_account.account_id,
            requested_at,
        },
    );
    plan.effect(
        config_account,
        &Effect::SettleUnstake {
            sequencer_key,
            ownership_account_id: ownership_id,
            amount,
            exit_delay,
        },
    );
    plan.call(custody_transfer(
        funds_account.account_id,
        stake_funds_seed(&ownership_id),
        destination_account.account_id,
        amount,
    ));
    plan
}

fn init_channel_params(
    input: &PlanInput,
    channel_params: ChannelParams,
    channel_id: [u8; 32],
) -> Plan {
    let [config_account] = <&[_; 1]>::try_from(input.accounts.as_slice())
        .expect("InitChannelParams requires the config account");
    assert_config_account(config_account, input.self_account_id);

    // A zero timeframe would leave round robin unable to move off index 0, and
    // a zero minimum would accredit every key that ever staked a nonzero amount.
    assert!(
        channel_params.posting_timeframe > 0,
        "posting_timeframe must be non-zero"
    );
    // A timeout above the timeframe never fires: the turn ends first.
    assert!(
        channel_params.posting_timeout > 0
            && channel_params.posting_timeout <= channel_params.posting_timeframe,
        "posting_timeout must be non-zero and no longer than posting_timeframe"
    );
    assert!(
        channel_params.minimum_sequencer_stake > 0,
        "minimum_sequencer_stake must be non-zero"
    );
    assert!(channel_params.exit_delay > 0, "exit_delay must be non-zero");

    let mut plan = Plan::new(input);
    plan.effect(
        config_account,
        &Effect::InitChannelParams {
            channel_params,
            channel_id,
        },
    );
    plan
}

fn slash(
    input: &PlanInput,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: Vec<SlashApproval>,
    total_staked: u128,
) -> Plan {
    let self_account_id = input.self_account_id;
    let [ownership_account, funds_account, sink_account, config_account] =
        <&[_; 4]>::try_from(input.accounts.as_slice()).expect(
            "Slash requires the ownership account, the stake funds account, the slash sink, and the config account",
        );

    assert_funds_account(self_account_id, ownership_account, funds_account);
    assert_eq!(
        sink_account.account_id,
        slash_sink_account_id(self_account_id),
        "third account must be the slash sink PDA"
    );
    assert_config_account(config_account, self_account_id);
    let ownership_id = ownership_account.account_id;

    let mut plan = Plan::new(input);
    plan.effect(ownership_account, &Effect::ClearForSlash { sequencer_key });
    plan.effect(
        config_account,
        &Effect::ApplySlash {
            sequencer_key,
            ownership_account_id: ownership_id,
            inscription,
            approvals,
            total_staked,
        },
    );
    plan.call(custody_transfer(
        funds_account.account_id,
        stake_funds_seed(&ownership_id),
        sink_account.account_id,
        total_staked,
    ));
    plan
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const OWNER: AccountId = AccountId::new([1; 32]);
    const OTHER_OWNER: AccountId = AccountId::new([2; 32]);
    const DESTINATION: AccountId = AccountId::new([3; 32]);
    const ATTACKER: AccountId = AccountId::new([4; 32]);
    const INSCRIPTION: [u8; 32] = [8; 32];
    const CHANNEL_ID: [u8; 32] = [9; 32];
    const MINIMUM: u128 = 1_000;
    const EXIT_DELAY: u64 = 10;
    const REQUESTED_AT: u64 = 7;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key(seed: u8) -> SequencerKey {
        SequencerKey::new(signing_key(seed).verifying_key().to_bytes())
            .expect("a derived public key is a curve point")
    }

    fn config_with(entries: &[(SequencerKey, SequencerEntry)]) -> Vec<u8> {
        SequencerStakeConfig {
            channel_params: Some(ChannelParams {
                minimum_sequencer_stake: MINIMUM,
                posting_timeframe: 300,
                posting_timeout: 25,
                exit_delay: EXIT_DELAY,
            }),
            channel_id: Some(CHANNEL_ID),
            entries: entries.iter().copied().collect::<BTreeMap<_, _>>(),
        }
        .to_bytes()
    }

    fn entry(
        account_id: AccountId,
        total_staked: u128,
        total_pending_unstake: u128,
    ) -> SequencerEntry {
        SequencerEntry {
            account_id,
            total_staked,
            total_pending_unstake,
        }
    }

    fn record(sequencer_key: SequencerKey, pending_unstake: Option<PendingUnstake>) -> Vec<u8> {
        StakeRecord {
            sequencer_key,
            pending_unstake,
        }
        .to_bytes()
    }

    fn decoded_config(written: Option<Vec<u8>>) -> SequencerStakeConfig {
        SequencerStakeConfig::from_bytes(&written.expect("apply writes the config"))
            .expect("the config decodes")
    }

    fn pending(amount: u128, destination: AccountId) -> PendingUnstake {
        PendingUnstake {
            amount,
            destination,
            requested_at: REQUESTED_AT,
        }
    }

    fn approval(seed: u8, sequencer_key: SequencerKey) -> SlashApproval {
        let signer = signing_key(seed);
        SlashApproval {
            signer: key(seed),
            signature: signer
                .sign(&slash_approval_message(
                    CHANNEL_ID,
                    sequencer_key,
                    INSCRIPTION,
                ))
                .to_bytes()
                .to_vec(),
        }
    }

    // --- FinalizeUnstake ---

    #[test]
    fn a_release_matching_the_pending_request_consumes_it() {
        let written = apply(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
        assert_eq!(written, Some(record(key(1), None)));
    }

    #[test]
    #[should_panic(expected = "no unstake request pending on this account")]
    fn a_release_with_no_request_behind_it_is_refused() {
        // FinalizeUnstake carries no signature, so without this any caller drains the funds
        // account of an account that never asked to unstake.
        apply(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: ATTACKER,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), None),
        );
    }

    #[test]
    #[should_panic(expected = "amount does not match the recorded unstake request")]
    fn a_release_larger_than_the_pending_request_is_refused() {
        apply(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 5_000,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "destination does not match the recorded unstake request")]
    fn a_release_to_another_address_is_refused() {
        // The whole drain: the chained transfer's recipient is this value.
        apply(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: ATTACKER,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_release_naming_another_key_is_refused() {
        // The key selects which config entry the release is charged to.
        apply(
            Effect::ReleaseUnstake {
                sequencer_key: key(2),
                amount: 500,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "request date does not match the recorded unstake request")]
    fn a_release_dated_differently_is_refused() {
        // The date sets the release's earliest block; an earlier one would skip the delay.
        apply(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
                requested_at: REQUESTED_AT - 1,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    fn settling_a_release_drops_a_fully_drained_entry() {
        let written = apply(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: 3_000,
                exit_delay: EXIT_DELAY,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 3_000))]),
        );
        assert!(decoded_config(written).entries.is_empty());
    }

    #[test]
    fn settling_a_partial_release_leaves_the_rest_staked() {
        let written = apply(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: 1_000,
                exit_delay: EXIT_DELAY,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 1_000))]),
        );
        assert_eq!(
            decoded_config(written).entries.get(&key(1)).copied(),
            Some(entry(OWNER, 2_000, 0))
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_release_cannot_be_charged_to_another_accounts_entry() {
        apply(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                amount: 500,
                exit_delay: EXIT_DELAY,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
        );
    }

    #[test]
    #[should_panic(expected = "exit delay does not match the channel params")]
    fn a_settlement_claiming_another_exit_delay_is_refused() {
        apply(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: 500,
                exit_delay: EXIT_DELAY - 1,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
        );
    }

    // --- UnstakeRequest ---

    #[test]
    fn a_request_records_the_amount_and_destination() {
        let written = apply(
            Effect::RequestUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), None),
        );
        assert_eq!(
            written,
            Some(record(key(1), Some(pending(500, DESTINATION))))
        );
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_request_cannot_name_a_key_this_account_does_not_back() {
        // Both halves read the proposed key; unchecked, it would point the config effect at a
        // victim's entry.
        apply(
            Effect::RequestUnstake {
                sequencer_key: key(2),
                amount: 500,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), None),
        );
    }

    #[test]
    #[should_panic(expected = "an unstake request is already pending")]
    fn a_second_request_is_refused() {
        apply(
            Effect::RequestUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            },
            &record(key(1), Some(pending(100, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "unstake request must be covered by the staked total")]
    fn a_request_beyond_the_tracked_stake_is_refused() {
        apply(
            Effect::TrackUnstakeRequest {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: 3_001,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_request_cannot_be_tracked_against_another_accounts_entry() {
        apply(
            Effect::TrackUnstakeRequest {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                amount: 500,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
        );
    }

    // --- Stake ---

    #[test]
    #[should_panic(expected = "stake claims an ownership record this account does not match")]
    fn a_stake_cannot_claim_a_record_an_empty_account_does_not_hold() {
        // `has_record` decides the config-side branch between a top-up and a first stake, and
        // a first stake is the only one the minimum applies to.
        apply(
            Effect::OpenStake {
                sequencer_key: key(1),
                has_record: true,
            },
            &[],
        );
    }

    #[test]
    #[should_panic(expected = "stake claims an ownership record this account does not match")]
    fn a_stake_cannot_deny_a_record_the_account_holds() {
        apply(
            Effect::OpenStake {
                sequencer_key: key(1),
                has_record: false,
            },
            &record(key(1), None),
        );
    }

    #[test]
    #[should_panic(expected = "cannot top up while an unstake request is pending")]
    fn a_top_up_during_a_pending_release_is_refused() {
        apply(
            Effect::OpenStake {
                sequencer_key: key(1),
                has_record: true,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "a stake or top-up must add at least the minimum")]
    fn a_first_stake_below_the_minimum_is_refused() {
        apply(
            Effect::RecordStake {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: MINIMUM - 1,
                has_record: false,
            },
            &config_with(&[]),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn another_account_cannot_top_up_an_existing_key() {
        apply(
            Effect::RecordStake {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                amount: MINIMUM,
                has_record: true,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
        );
    }

    #[test]
    #[should_panic(expected = "this sequencer key already has an ownership account")]
    fn a_first_stake_cannot_take_over_a_key_already_staked() {
        apply(
            Effect::RecordStake {
                sequencer_key: key(1),
                ownership_account_id: OTHER_OWNER,
                amount: MINIMUM,
                has_record: false,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
        );
    }

    // --- Slash ---

    #[test]
    fn an_approved_slash_removes_the_entry() {
        let written = apply(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                inscription: INSCRIPTION,
                approvals: vec![approval(2, key(1)), approval(3, key(1))],
                total_staked: 3_000,
            },
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 0)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
                (key(3), entry(OTHER_OWNER, 3_000, 0)),
            ]),
        );
        assert_eq!(decoded_config(written).entries.len(), 2);
    }

    #[test]
    #[should_panic(expected = "approval from a key this config does not accredit")]
    fn a_slash_approved_by_an_unaccredited_key_is_refused() {
        // Accreditation is the entire authorization for a slash, and only the real config
        // knows it.
        apply(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                inscription: INSCRIPTION,
                approvals: vec![approval(9, key(1))],
                total_staked: 3_000,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
        );
    }

    #[test]
    #[should_panic(expected = "slash carries fewer approvals than the threshold")]
    fn a_slash_approved_by_a_single_key_is_refused() {
        apply(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                inscription: INSCRIPTION,
                approvals: vec![approval(2, key(1))],
                total_staked: 3_000,
            },
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 0)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
                (key(3), entry(OTHER_OWNER, 3_000, 0)),
            ]),
        );
    }

    #[test]
    #[should_panic(expected = "slash must burn exactly the stake this config tracks")]
    fn a_slash_cannot_burn_more_than_the_tracked_stake() {
        apply(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                inscription: INSCRIPTION,
                approvals: vec![approval(2, key(1)), approval(3, key(1))],
                total_staked: 10_000,
            },
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 0)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
                (key(3), entry(OTHER_OWNER, 3_000, 0)),
            ]),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_slash_cannot_be_charged_to_another_accounts_funds() {
        apply(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                inscription: INSCRIPTION,
                approvals: vec![approval(2, key(1)), approval(3, key(1))],
                total_staked: 3_000,
            },
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 0)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
                (key(3), entry(OTHER_OWNER, 3_000, 0)),
            ]),
        );
    }

    // --- InitChannelParams ---

    #[test]
    #[should_panic(expected = "channel params are already set")]
    fn channel_params_cannot_be_set_twice() {
        apply(
            Effect::InitChannelParams {
                channel_params: ChannelParams {
                    minimum_sequencer_stake: 1,
                    posting_timeframe: 1,
                    posting_timeout: 1,
                    exit_delay: 1,
                },
                channel_id: CHANNEL_ID,
            },
            &config_with(&[]),
        );
    }
}
