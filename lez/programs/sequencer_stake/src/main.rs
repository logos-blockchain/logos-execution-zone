use std::collections::btree_map::Entry;

use lee_core::{
    account::{AccountId, ProgramShardSelector},
    native_token::{NATIVE_TOKEN_PROGRAM_ID, custody_transfer, decode_balance},
    program::{
        AccountMeta, ChainedCall, InstructionData, LeeCall, Plan, ProgramInput, Proposed,
        read_lee_call, resolve_keep, resolve_write,
    },
};
use sequencer_stake_core::{
    ChannelParams, Instruction, PendingUnstake, SLASH_APPROVAL_THRESHOLD, SequencerEntry,
    SequencerKey, SequencerStakeConfig, SlashApproval, StakeRecord,
    ed25519_dalek::{Signature, VerifyingKey},
    sequencer_stake_config_account_id, slash_approval_message, slash_sink_account_id,
    stake_funds_account_id, stake_funds_seed,
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// The balance shard belongs to the native token program, so this only inspects it.
    BalanceIs(u128),
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
    },
    SettleUnstake {
        sequencer_key: SequencerKey,
        ownership_account_id: AccountId,
        amount: u128,
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
    InitChannelParams(ChannelParams),
}

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect = borsh::from_slice(&input.effect_data)
                .expect("sequencer_stake wrote its own effect");
            match resolve_effect(effect, &input.pre_data) {
                None => resolve_keep(input),
                Some(data) => {
                    resolve_write(input, data.try_into().expect("data fits in account data"))
                }
            }
        }
    }
}

fn resolve_effect(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::BalanceIs(expected) => {
            let balance = decode_balance(pre_data)
                .expect("a stake funds account selects its native balance shard");
            assert_eq!(
                balance, expected,
                "stake funds account does not hold the balance the call was planned against"
            );
            None
        }
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
            Some(
                StakeRecord {
                    sequencer_key,
                    pending_unstake: None,
                }
                .to_bytes(),
            )
        }
        Effect::RecordStake {
            sequencer_key,
            ownership_account_id,
            amount,
            has_record,
        } => {
            let mut config = decode_config(pre_data);
            let minimum_sequencer_stake = channel_params(&config).minimum_sequencer_stake;
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
                    assert!(
                        amount >= minimum_sequencer_stake,
                        "an initial stake must already meet the minimum"
                    );
                    vacant.insert(SequencerEntry {
                        account_id: ownership_account_id,
                        total_staked: amount,
                        total_pending_unstake: 0,
                    });
                }
            }
            Some(config.to_bytes())
        }
        Effect::RequestUnstake {
            sequencer_key,
            amount,
            destination,
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
            });
            Some(record.to_bytes())
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
            Some(config.to_bytes())
        }
        Effect::ReleaseUnstake {
            sequencer_key,
            amount,
            destination,
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
            Some(record.to_bytes())
        }
        Effect::SettleUnstake {
            sequencer_key,
            ownership_account_id,
            amount,
        } => {
            let mut config = decode_config(pre_data);
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
            Some(config.to_bytes())
        }
        Effect::ClearForSlash { sequencer_key } => {
            let mut record = decode_record(pre_data);
            assert_eq!(
                record.sequencer_key, sequencer_key,
                "ownership account backs a different sequencer key"
            );
            // The whole tracked stake burns, including any pending unstake.
            record.pending_unstake = None;
            Some(record.to_bytes())
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
            Some(config.to_bytes())
        }
        Effect::InitChannelParams(channel_params) => {
            let mut config = decode_config(pre_data);
            assert!(
                config.channel_params.is_none(),
                "channel params are already set and cannot be changed"
            );
            config.channel_params = Some(channel_params);
            Some(config.to_bytes())
        }
    }
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
    let message = slash_approval_message(sequencer_key, inscription);

    let mut approvers: Vec<SequencerKey> = Vec::with_capacity(approvals.len());
    for approval in approvals {
        assert!(
            config.entries.contains_key(&approval.signer),
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
        approvers.len() >= SLASH_APPROVAL_THRESHOLD,
        "slash carries fewer approvals than the threshold"
    );
}

const fn channel_params(config: &SequencerStakeConfig) -> ChannelParams {
    config
        .channel_params
        .expect("genesis sets the channel params before any stake exists")
}

/// Other accounts also hold this program's shards, so the config is pinned by address, and by
/// the shard under it: the effects that only inspect it have nothing else to go on.
fn assert_config_account(config_account: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config_account.account_id,
        sequencer_stake_config_account_id(self_account_id),
        "not the sequencer_stake config account"
    );
    assert_own_shard(config_account, self_account_id);
}

fn assert_own_shard(account: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        account.program_account_id, self_account_id,
        "account must be named under this program's shard"
    );
}

/// The funds account's balance is what every guard here measures, so the handle has to select
/// the native shard that holds it.
fn assert_funds_account(self_account_id: AccountId, ownership: &AccountMeta, funds: &AccountMeta) {
    assert_eq!(
        funds.account_id,
        stake_funds_account_id(self_account_id, &ownership.account_id),
        "not the stake funds account of this ownership account"
    );
    assert_native_shard(funds);
}

fn assert_native_shard(account: &AccountMeta) {
    assert_eq!(
        account.program_account_id, NATIVE_TOKEN_PROGRAM_ID,
        "account must be named under its native balance shard"
    );
}

fn execute(input: &ProgramInput<Instruction>, instruction_data: Vec<u8>) -> ! {
    match &input.instruction {
        Instruction::Stake {
            sequencer_key,
            amount,
            mover_account_id,
            mover_instruction_data,
            balance_before,
            has_record,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "Stake is only invoked as a top-level user transaction"
            );
            stake(
                input,
                instruction_data,
                *sequencer_key,
                *amount,
                *mover_account_id,
                mover_instruction_data.clone(),
                *balance_before,
                *has_record,
            )
        }
        Instruction::ConfirmStake {
            expected_balance_after,
        } => {
            assert_eq!(
                input.caller_account_id,
                Some(input.self_account_id),
                "ConfirmStake can only be invoked as a self-chained call"
            );
            confirm_stake(input, instruction_data, *expected_balance_after)
        }
        Instruction::UnstakeRequest {
            sequencer_key,
            amount,
            destination,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "UnstakeRequest is only invoked as a top-level user transaction"
            );
            unstake_request(
                input,
                instruction_data,
                *sequencer_key,
                *amount,
                *destination,
            )
        }
        Instruction::FinalizeUnstake {
            sequencer_key,
            amount,
        } => {
            assert!(
                input.caller_account_id.is_none(),
                "FinalizeUnstake is only invoked as a top-level user transaction"
            );
            finalize_unstake(input, instruction_data, *sequencer_key, *amount)
        }
        Instruction::InitChannelParams(channel_params) => {
            assert!(
                input.caller_account_id.is_none(),
                "InitChannelParams is only invoked as a top-level user transaction"
            );
            init_channel_params(input, instruction_data, *channel_params)
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
            slash(
                input,
                instruction_data,
                *sequencer_key,
                *inscription,
                approvals.clone(),
                *total_staked,
            )
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the instruction's own fields are passed through verbatim"
)]
fn stake(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    sequencer_key: SequencerKey,
    amount: u128,
    mover_account_id: AccountId,
    mover_instruction_data: InstructionData,
    balance_before: u128,
    has_record: bool,
) -> ! {
    let self_account_id = input.self_account_id;
    // The funding account carries no effect: it is here to propagate its authorization into
    // the nested mover call.
    let [funding_account, ownership_account, funds_account, config_account] =
        <[_; 4]>::try_from(input.accounts.clone()).expect(
            "Stake requires a funding account, an ownership account, the stake funds account, and the config account",
        );

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );
    assert_own_shard(&ownership_account, self_account_id);
    assert_funds_account(self_account_id, &ownership_account, &funds_account);
    assert_config_account(&config_account, self_account_id);

    let mut plan = Plan::new(input, instruction_data);
    let balance_before = plan.require(
        &funds_account,
        &Effect::BalanceIs(balance_before),
        Proposed::new(balance_before),
    );
    let expected_balance_after = balance_before
        .get()
        .checked_add(amount)
        .expect("stake amount overflow");
    let has_record = plan.require(
        &ownership_account,
        &Effect::OpenStake {
            sequencer_key,
            has_record,
        },
        Proposed::new(has_record),
    );
    plan.update(
        &config_account,
        &Effect::RecordStake {
            sequencer_key,
            ownership_account_id: ownership_account.account_id,
            amount,
            has_record: has_record.get(),
        },
    );

    plan.call(ChainedCall {
        program_account_id: mover_account_id,
        shard_selectors: vec![
            ProgramShardSelector::balance(funding_account.account_id),
            ProgramShardSelector::balance(funds_account.account_id),
        ],
        instruction_data: mover_instruction_data,
        pda_seeds: Vec::new(),
    });
    plan.call(ChainedCall::new(
        self_account_id,
        vec![ProgramShardSelector::balance(funds_account.account_id)],
        &Instruction::ConfirmStake {
            expected_balance_after,
        },
    ));
    plan.write()
}

fn confirm_stake(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    expected_balance_after: u128,
) -> ! {
    let [funds_account] = <[_; 1]>::try_from(input.accounts.clone())
        .expect("ConfirmStake requires exactly the stake funds account");
    assert_native_shard(&funds_account);

    // After the mover, never before: checking only before the child would accept a mover that
    // never paid.
    let mut plan = Plan::new(input, instruction_data);
    plan.effect(&funds_account, &Effect::BalanceIs(expected_balance_after));
    plan.write()
}

fn unstake_request(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    sequencer_key: SequencerKey,
    amount: u128,
    destination: AccountId,
) -> ! {
    let self_account_id = input.self_account_id;
    let [ownership_account, config_account] = <[_; 2]>::try_from(input.accounts.clone())
        .expect("UnstakeRequest requires the ownership account and the config account");

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );
    assert_own_shard(&ownership_account, self_account_id);
    assert_config_account(&config_account, self_account_id);

    // Only data changes here; the transfer happens in FinalizeUnstake.
    let mut plan = Plan::new(input, instruction_data);
    let sequencer_key = plan.require(
        &ownership_account,
        &Effect::RequestUnstake {
            sequencer_key,
            amount,
            destination,
        },
        Proposed::new(sequencer_key),
    );
    plan.update(
        &config_account,
        &Effect::TrackUnstakeRequest {
            sequencer_key: sequencer_key.get(),
            ownership_account_id: ownership_account.account_id,
            amount,
        },
    );
    plan.write()
}

fn finalize_unstake(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    sequencer_key: SequencerKey,
    amount: u128,
) -> ! {
    let self_account_id = input.self_account_id;
    let [ownership_account, funds_account, destination_account, config_account] =
        <[_; 4]>::try_from(input.accounts.clone()).expect(
            "FinalizeUnstake requires the ownership account, the stake funds account, a destination account, and the config account",
        );

    assert_own_shard(&ownership_account, self_account_id);
    assert_funds_account(self_account_id, &ownership_account, &funds_account);
    assert_config_account(&config_account, self_account_id);
    let ownership_id = ownership_account.account_id;

    // No signature check: already authorized back in UnstakeRequest. That is exactly why the
    // release below may only be sized and addressed by what the record turns out to hold.
    let mut plan = Plan::new(input, instruction_data);
    let release = plan.require(
        &ownership_account,
        &Effect::ReleaseUnstake {
            sequencer_key,
            amount,
            destination: destination_account.account_id,
        },
        Proposed::new((sequencer_key, amount, destination_account.account_id)),
    );
    let (pending_key, pending_amount, pending_destination) = release.get();
    plan.update(
        &config_account,
        &Effect::SettleUnstake {
            sequencer_key: pending_key,
            ownership_account_id: ownership_id,
            amount: pending_amount,
        },
    );
    plan.call(custody_transfer(
        funds_account.account_id,
        stake_funds_seed(&ownership_id),
        pending_destination,
        pending_amount,
    ));
    plan.write()
}

fn init_channel_params(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    channel_params: ChannelParams,
) -> ! {
    let [config_account] = <[_; 1]>::try_from(input.accounts.clone())
        .expect("InitChannelParams requires the config account");
    assert_config_account(&config_account, input.self_account_id);

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

    let mut plan = Plan::new(input, instruction_data);
    plan.update(&config_account, &Effect::InitChannelParams(channel_params));
    plan.write()
}

fn slash(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: Vec<SlashApproval>,
    total_staked: u128,
) -> ! {
    let self_account_id = input.self_account_id;
    let [ownership_account, funds_account, sink_account, config_account] =
        <[_; 4]>::try_from(input.accounts.clone()).expect(
            "Slash requires the ownership account, the stake funds account, the slash sink, and the config account",
        );

    assert_own_shard(&ownership_account, self_account_id);
    assert_funds_account(self_account_id, &ownership_account, &funds_account);
    assert_eq!(
        sink_account.account_id,
        slash_sink_account_id(self_account_id),
        "third account must be the slash sink PDA"
    );
    assert_config_account(&config_account, self_account_id);
    let ownership_id = ownership_account.account_id;

    let mut plan = Plan::new(input, instruction_data);
    plan.update(&ownership_account, &Effect::ClearForSlash { sequencer_key });
    let total_staked = plan.require(
        &config_account,
        &Effect::ApplySlash {
            sequencer_key,
            ownership_account_id: ownership_id,
            inscription,
            approvals,
            total_staked,
        },
        Proposed::new(total_staked),
    );
    plan.call(custody_transfer(
        funds_account.account_id,
        stake_funds_seed(&ownership_id),
        sink_account.account_id,
        total_staked.get(),
    ));
    plan.write()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::native_token::encode_balance;
    use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const OWNER: AccountId = AccountId::new([1; 32]);
    const OTHER_OWNER: AccountId = AccountId::new([2; 32]);
    const DESTINATION: AccountId = AccountId::new([3; 32]);
    const ATTACKER: AccountId = AccountId::new([4; 32]);
    const INSCRIPTION: [u8; 32] = [8; 32];
    const MINIMUM: u128 = 1_000;

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
            }),
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

    fn decoded_config(bytes: &[u8]) -> SequencerStakeConfig {
        SequencerStakeConfig::from_bytes(bytes).expect("the config decodes")
    }

    fn pending(amount: u128, destination: AccountId) -> PendingUnstake {
        PendingUnstake {
            amount,
            destination,
        }
    }

    fn approval(seed: u8, sequencer_key: SequencerKey) -> SlashApproval {
        let signer = signing_key(seed);
        SlashApproval {
            signer: key(seed),
            signature: signer
                .sign(&slash_approval_message(sequencer_key, INSCRIPTION))
                .to_bytes()
                .to_vec(),
        }
    }

    // --- FinalizeUnstake ---

    #[test]
    fn a_release_matching_the_pending_request_consumes_it() {
        let written = resolve_effect(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        )
        .expect("the record is written");
        assert_eq!(written, record(key(1), None));
    }

    #[test]
    #[should_panic(expected = "no unstake request pending on this account")]
    fn a_release_with_no_request_behind_it_is_refused() {
        // FinalizeUnstake carries no signature, so without this any caller drains the funds
        // account of an account that never asked to unstake.
        resolve_effect(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: ATTACKER,
            },
            &record(key(1), None),
        );
    }

    #[test]
    #[should_panic(expected = "amount does not match the recorded unstake request")]
    fn a_release_larger_than_the_pending_request_is_refused() {
        resolve_effect(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 5_000,
                destination: DESTINATION,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "destination does not match the recorded unstake request")]
    fn a_release_to_another_address_is_refused() {
        // The whole drain: the chained transfer's recipient is this value.
        resolve_effect(
            Effect::ReleaseUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: ATTACKER,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_release_naming_another_key_is_refused() {
        // The key selects which config entry the release is charged to.
        resolve_effect(
            Effect::ReleaseUnstake {
                sequencer_key: key(2),
                amount: 500,
                destination: DESTINATION,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    fn settling_a_release_drops_a_fully_drained_entry() {
        let written = resolve_effect(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: 3_000,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 3_000))]),
        )
        .expect("the config is written");
        assert!(decoded_config(&written).entries.is_empty());
    }

    #[test]
    fn settling_a_partial_release_leaves_the_rest_staked() {
        let written = resolve_effect(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                amount: 1_000,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 1_000))]),
        )
        .expect("the config is written");
        assert_eq!(
            decoded_config(&written).entries.get(&key(1)).copied(),
            Some(entry(OWNER, 2_000, 0))
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_release_cannot_be_charged_to_another_accounts_entry() {
        resolve_effect(
            Effect::SettleUnstake {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                amount: 500,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
        );
    }

    // --- UnstakeRequest ---

    #[test]
    fn a_request_records_the_amount_and_destination() {
        let written = resolve_effect(
            Effect::RequestUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
            },
            &record(key(1), None),
        )
        .expect("the record is written");
        assert_eq!(written, record(key(1), Some(pending(500, DESTINATION))));
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_request_cannot_name_a_key_this_account_does_not_back() {
        // Both halves read the proposed key; unchecked, it would point the config effect at a
        // victim's entry.
        resolve_effect(
            Effect::RequestUnstake {
                sequencer_key: key(2),
                amount: 500,
                destination: DESTINATION,
            },
            &record(key(1), None),
        );
    }

    #[test]
    #[should_panic(expected = "an unstake request is already pending")]
    fn a_second_request_is_refused() {
        resolve_effect(
            Effect::RequestUnstake {
                sequencer_key: key(1),
                amount: 500,
                destination: DESTINATION,
            },
            &record(key(1), Some(pending(100, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "unstake request must be covered by the staked total")]
    fn a_request_beyond_the_tracked_stake_is_refused() {
        resolve_effect(
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
        resolve_effect(
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
    fn the_proposed_starting_balance_must_be_the_real_one() {
        assert_eq!(
            resolve_effect(Effect::BalanceIs(700), &encode_balance(700)),
            None
        );
    }

    #[test]
    #[should_panic(expected = "does not hold the balance the call was planned against")]
    fn a_wrong_starting_balance_is_refused() {
        resolve_effect(Effect::BalanceIs(700), &encode_balance(100));
    }

    #[test]
    #[should_panic(expected = "stake claims an ownership record this account does not match")]
    fn a_stake_cannot_claim_a_record_an_empty_account_does_not_hold() {
        // `has_record` decides the config-side branch between a top-up and a first stake, and
        // a first stake is the only one the minimum applies to.
        resolve_effect(
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
        resolve_effect(
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
        resolve_effect(
            Effect::OpenStake {
                sequencer_key: key(1),
                has_record: true,
            },
            &record(key(1), Some(pending(500, DESTINATION))),
        );
    }

    #[test]
    #[should_panic(expected = "an initial stake must already meet the minimum")]
    fn a_first_stake_below_the_minimum_is_refused() {
        resolve_effect(
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
        resolve_effect(
            Effect::RecordStake {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                amount: 10,
                has_record: true,
            },
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
        );
    }

    #[test]
    #[should_panic(expected = "this sequencer key already has an ownership account")]
    fn a_first_stake_cannot_take_over_a_key_already_staked() {
        resolve_effect(
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
        let written = resolve_effect(
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
            ]),
        )
        .expect("the config is written");
        assert_eq!(decoded_config(&written).entries.len(), 1);
    }

    #[test]
    #[should_panic(expected = "approval from a key this config does not accredit")]
    fn a_slash_approved_by_an_unaccredited_key_is_refused() {
        // Accreditation is the entire authorization for a slash, and only the real config
        // knows it.
        resolve_effect(
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
    #[should_panic(expected = "slash must burn exactly the stake this config tracks")]
    fn a_slash_cannot_burn_more_than_the_tracked_stake() {
        resolve_effect(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: OWNER,
                inscription: INSCRIPTION,
                approvals: vec![approval(2, key(1))],
                total_staked: 10_000,
            },
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 0)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
            ]),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_slash_cannot_be_charged_to_another_accounts_funds() {
        resolve_effect(
            Effect::ApplySlash {
                sequencer_key: key(1),
                ownership_account_id: ATTACKER,
                inscription: INSCRIPTION,
                approvals: vec![approval(2, key(1))],
                total_staked: 3_000,
            },
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 0)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
            ]),
        );
    }

    // --- InitChannelParams ---

    #[test]
    #[should_panic(expected = "channel params are already set")]
    fn channel_params_cannot_be_set_twice() {
        resolve_effect(
            Effect::InitChannelParams(ChannelParams {
                minimum_sequencer_stake: 1,
                posting_timeframe: 1,
                posting_timeout: 1,
            }),
            &config_with(&[]),
        );
    }
}
