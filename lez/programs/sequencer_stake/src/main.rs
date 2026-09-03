use std::collections::btree_map::Entry;

use authenticated_transfer_core::custody_transfer;
use lee_core::{
    account::{AccountId, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountStateDiff, ChainedCall, DEFAULT_PROGRAM_OWNER, InstructionData, ProgramCall,
        ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};
use sequencer_stake_core::{
    ChannelParams, Instruction, PendingUnstake, SLASH_APPROVAL_THRESHOLD, SequencerEntry,
    SequencerKey, SequencerStakeConfig, SlashApproval, StakeRecord,
    ed25519_dalek::{Signature, VerifyingKey},
    sequencer_stake_config_account_id, slash_approval_message, slash_sink_account_id,
    stake_funds_account_id, stake_funds_seed,
};

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let (post_diffs, chained_calls) = match instruction {
        Instruction::Stake {
            sequencer_key,
            amount,
            mover_account_id,
            mover_instruction_data,
        } => {
            assert!(
                caller_account_id.is_none(),
                "Stake is only invoked as a top-level user transaction"
            );
            stake(
                self_account_id,
                pre_states,
                sequencer_key,
                amount,
                mover_account_id,
                mover_instruction_data,
            )
        }
        Instruction::ConfirmStake {
            expected_balance_after,
        } => {
            assert_eq!(
                caller_account_id,
                Some(self_account_id),
                "ConfirmStake can only be invoked as a self-chained call"
            );
            let post = confirm_stake(pre_states, expected_balance_after);
            (post, Vec::new())
        }
        Instruction::UnstakeRequest {
            amount,
            destination,
        } => {
            assert!(
                caller_account_id.is_none(),
                "UnstakeRequest is only invoked as a top-level user transaction"
            );
            let post = unstake_request(self_account_id, pre_states, amount, destination);
            (post, Vec::new())
        }
        Instruction::FinalizeUnstake => {
            assert!(
                caller_account_id.is_none(),
                "FinalizeUnstake is only invoked as a top-level user transaction"
            );
            finalize_unstake(self_account_id, pre_states)
        }
        Instruction::InitChannelParams(channel_params) => {
            assert!(
                caller_account_id.is_none(),
                "InitChannelParams is only invoked as a top-level user transaction"
            );
            let post = init_channel_params(self_account_id, pre_states, channel_params);
            (post, Vec::new())
        }
        Instruction::Slash {
            sequencer_key,
            inscription,
            approvals,
        } => {
            assert!(
                caller_account_id.is_none(),
                "Slash is only invoked as a top-level user transaction"
            );
            slash(
                self_account_id,
                pre_states,
                sequencer_key,
                inscription,
                &approvals,
            )
        }
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}

fn decode_config(
    config_account: &AccountWithMetadata,
    self_account_id: lee_core::account::AccountId,
) -> SequencerStakeConfig {
    // By id, not just by owner: every ownership account is owned by this
    // program too, and its data is caller-influenced.
    assert_eq!(
        config_account.account_id,
        sequencer_stake_config_account_id(self_account_id),
        "not the sequencer_stake config account"
    );
    assert_eq!(
        config_account.account.program_owner, self_account_id,
        "config account is not owned by sequencer_stake"
    );
    SequencerStakeConfig::from_bytes(config_account.account.data.as_ref())
        .expect("config account data should decode as SequencerStakeConfig")
}

fn assert_funds_account(
    self_account_id: lee_core::account::AccountId,
    ownership: &AccountWithMetadata,
    funds: &AccountWithMetadata,
) {
    assert_eq!(
        funds.account_id,
        stake_funds_account_id(self_account_id, &ownership.account_id),
        "not the stake funds account of this ownership account"
    );
}

fn stake(
    self_account_id: lee_core::account::AccountId,
    pre_states: Vec<AccountWithMetadata>,
    sequencer_key: SequencerKey,
    amount: u128,
    mover_account_id: lee_core::account::AccountId,
    mover_instruction_data: InstructionData,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let [funding_account, ownership_account, funds_account, config_account] =
        <[AccountWithMetadata; 4]>::try_from(pre_states).expect(
            "Stake requires a funding account, an ownership account, the stake funds account, and the config account",
        );

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );

    assert_funds_account(self_account_id, &ownership_account, &funds_account);

    let mut config = decode_config(&config_account, self_account_id);
    let minimum_sequencer_stake = channel_params(&config).minimum_sequencer_stake;

    let balance_before = funds_account.account.balance;
    let expected_balance_after = balance_before
        .checked_add(amount)
        .expect("stake amount overflow");

    // An ownership account stays claimed after a full exit, so what a call is
    // doing follows from the config entry, not from the account's owner.
    let is_claimed = ownership_account.account.program_owner != DEFAULT_PROGRAM_OWNER;
    if is_claimed {
        assert_eq!(
            ownership_account.account.program_owner, self_account_id,
            "not a sequencer_stake ownership account"
        );
        let record = StakeRecord::from_bytes(ownership_account.account.data.as_ref())
            .expect("claimed ownership account should decode as StakeRecord");
        assert_eq!(
            record.sequencer_key, sequencer_key,
            "ownership account backs a different sequencer key"
        );
        assert!(
            record.pending_unstake.is_none(),
            "cannot top up while an unstake request is pending"
        );
    }

    match config.entries.entry(sequencer_key) {
        Entry::Occupied(mut occupied) => {
            // top up: same already-claimed account only
            assert!(
                is_claimed,
                "this sequencer key already has an ownership account"
            );
            let entry = occupied.get_mut();
            assert_eq!(
                entry.account_id, ownership_account.account_id,
                "config entry points at a different ownership account"
            );
            entry.total_staked = entry
                .total_staked
                .checked_add(amount)
                .expect("total staked overflow");
        }
        Entry::Vacant(vacant) => {
            // first stake for this key, or a new one after a full exit
            assert!(
                amount >= minimum_sequencer_stake,
                "an initial stake must already meet the minimum"
            );
            vacant.insert(SequencerEntry {
                account_id: ownership_account.account_id,
                total_staked: amount,
                total_pending_unstake: 0,
            });
        }
    }

    // pass-through: propagates authorization into the nested mover call
    let funding_account_post = AccountStateDiff::unchanged(funding_account.clone());

    // the first stake's write acquires the ownership account; a top-up is an ordinary owned write
    let new_stake_record_data: Data = StakeRecord {
        sequencer_key,
        pending_unstake: None,
    }
    .to_bytes()
    .try_into()
    .expect("StakeRecord should fit in account data");
    let ownership_account_post = AccountStateDiff::new(
        ownership_account,
        BalanceDiff::Add(0),
        new_stake_record_data,
    );

    let funds_account_post = AccountStateDiff::unchanged(funds_account.clone());

    let config_account_post = AccountStateDiff::new(
        config_account,
        BalanceDiff::Add(0),
        config
            .to_bytes()
            .try_into()
            .expect("SequencerStakeConfig should fit in account data"),
    );

    let mover_call = ChainedCall {
        program_account_id: mover_account_id,
        pre_state_ids: vec![funding_account.account_id, funds_account.account_id],
        instruction_data: mover_instruction_data,
        pda_seeds: Vec::new(),
    };

    let confirm_call = ChainedCall::new(
        self_account_id,
        vec![funds_account.account_id],
        &Instruction::ConfirmStake {
            expected_balance_after,
        },
    );

    (
        vec![
            funding_account_post,
            ownership_account_post,
            funds_account_post,
            config_account_post,
        ],
        vec![mover_call, confirm_call],
    )
}

fn confirm_stake(
    pre_states: Vec<AccountWithMetadata>,
    expected_balance_after: u128,
) -> Vec<AccountStateDiff> {
    let [funds_account] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("ConfirmStake requires exactly the stake funds account");

    assert_eq!(
        funds_account.account.balance, expected_balance_after,
        "mover call did not deposit the expected amount into the stake funds account"
    );

    vec![AccountStateDiff::unchanged(funds_account)]
}

fn unstake_request(
    self_account_id: lee_core::account::AccountId,
    pre_states: Vec<AccountWithMetadata>,
    amount: u128,
    destination: AccountId,
) -> Vec<AccountStateDiff> {
    let [ownership_account, config_account] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("UnstakeRequest requires the ownership account and the config account");

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );
    assert_eq!(
        ownership_account.account.program_owner, self_account_id,
        "not a sequencer_stake ownership account"
    );

    let mut record = StakeRecord::from_bytes(ownership_account.account.data.as_ref())
        .expect("ownership account should decode as StakeRecord");
    assert!(
        record.pending_unstake.is_none(),
        "an unstake request is already pending"
    );

    let mut config = decode_config(&config_account, self_account_id);
    let minimum_sequencer_stake = channel_params(&config).minimum_sequencer_stake;
    let entry = config
        .entries
        .get_mut(&record.sequencer_key)
        .expect("staked key must already have a config entry");
    assert_eq!(
        entry.account_id, ownership_account.account_id,
        "config entry points at a different ownership account"
    );

    // Sized against the tracked stake, never the account balance: anyone can
    // credit a program-owned account, so balance can exceed `total_staked`.
    // Covers both "not more than is staked" and "zero or at least the minimum".
    assert!(
        entry.allows_unstake_request(amount, minimum_sequencer_stake),
        "unstake request must be covered by the staked total and leave the key at zero or at/above the minimum"
    );

    record.pending_unstake = Some(PendingUnstake {
        amount,
        destination,
    });
    entry.total_pending_unstake = entry
        .total_pending_unstake
        .checked_add(amount)
        .expect("total pending unstake overflow");

    // only data changes here; transfer happens in FinalizeUnstake
    let ownership_post = AccountStateDiff::new(
        ownership_account,
        BalanceDiff::Add(0),
        record
            .to_bytes()
            .try_into()
            .expect("StakeRecord should fit in account data"),
    );

    let config_post = AccountStateDiff::new(
        config_account,
        BalanceDiff::Add(0),
        config
            .to_bytes()
            .try_into()
            .expect("SequencerStakeConfig should fit in account data"),
    );

    vec![ownership_post, config_post]
}

/// Checks for enough distinct approvals from accredited keys over this key and
/// inscription.
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

/// The params genesis fixed. Absent only before genesis has run, which no
/// transaction reaching this program can observe.
const fn channel_params(config: &SequencerStakeConfig) -> ChannelParams {
    config
        .channel_params
        .expect("genesis sets the channel params before any stake exists")
}

fn init_channel_params(
    self_account_id: AccountId,
    pre_states: Vec<AccountWithMetadata>,
    channel_params: ChannelParams,
) -> Vec<AccountStateDiff> {
    let [config_account] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitChannelParams requires the config account");

    let mut config = decode_config(&config_account, self_account_id);
    assert!(
        config.channel_params.is_none(),
        "channel params are already set and cannot be changed"
    );
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

    config.channel_params = Some(channel_params);

    let config_post = AccountStateDiff::new(
        config_account,
        BalanceDiff::Add(0),
        config
            .to_bytes()
            .try_into()
            .expect("SequencerStakeConfig should fit in account data"),
    );

    vec![config_post]
}

fn slash(
    self_account_id: lee_core::account::AccountId,
    pre_states: Vec<AccountWithMetadata>,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: &[SlashApproval],
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let [ownership_account, funds_account, sink_account, config_account] =
        <[AccountWithMetadata; 4]>::try_from(pre_states).expect(
            "Slash requires the ownership account, the stake funds account, the slash sink, and the config account",
        );

    assert_eq!(
        ownership_account.account.program_owner, self_account_id,
        "not a sequencer_stake ownership account"
    );
    assert_funds_account(self_account_id, &ownership_account, &funds_account);
    assert_eq!(
        sink_account.account_id,
        slash_sink_account_id(self_account_id),
        "third account must be the slash sink PDA"
    );

    let mut record = StakeRecord::from_bytes(ownership_account.account.data.as_ref())
        .expect("ownership account should decode as StakeRecord");
    assert_eq!(
        record.sequencer_key, sequencer_key,
        "ownership account backs a different sequencer key"
    );

    let mut config = decode_config(&config_account, self_account_id);
    // The approvals are the whole authorization.
    verify_approvals(&config, sequencer_key, inscription, approvals);

    let entry = config
        .entries
        .remove(&sequencer_key)
        .expect("slashed key must have a config entry");
    assert_eq!(
        entry.account_id, ownership_account.account_id,
        "config entry points at a different ownership account"
    );

    // The whole tracked stake burns, including any pending unstake.
    record.pending_unstake = None;
    let ownership_post = AccountStateDiff::new(
        ownership_account.clone(),
        BalanceDiff::Add(0),
        record
            .to_bytes()
            .try_into()
            .expect("StakeRecord should fit in account data"),
    );

    let config_post = AccountStateDiff::new(
        config_account,
        BalanceDiff::Add(0),
        config
            .to_bytes()
            .try_into()
            .expect("SequencerStakeConfig should fit in account data"),
    );

    // The burn happens in a chained authenticated_transfer call.
    let burn_call = custody_transfer(
        funds_account.account_id,
        stake_funds_seed(&ownership_account.account_id),
        sink_account.account_id,
        entry.total_staked,
    );

    (
        vec![
            ownership_post,
            AccountStateDiff::unchanged(funds_account),
            AccountStateDiff::unchanged(sink_account),
            config_post,
        ],
        vec![burn_call],
    )
}

fn finalize_unstake(
    self_account_id: lee_core::account::AccountId,
    pre_states: Vec<AccountWithMetadata>,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let [ownership_account, funds_account, destination_account, config_account] =
        <[AccountWithMetadata; 4]>::try_from(pre_states).expect(
            "FinalizeUnstake requires the ownership account, the stake funds account, a destination account, and the config account",
        );

    assert_eq!(
        ownership_account.account.program_owner, self_account_id,
        "not a sequencer_stake ownership account"
    );
    assert_funds_account(self_account_id, &ownership_account, &funds_account);

    let mut record = StakeRecord::from_bytes(ownership_account.account.data.as_ref())
        .expect("ownership account should decode as StakeRecord");
    let pending = record
        .pending_unstake
        .take()
        .expect("no unstake request pending on this account");
    assert_eq!(
        destination_account.account_id, pending.destination,
        "destination does not match the recorded unstake request"
    );

    // no signature check: already authorized back in UnstakeRequest
    let ownership_post = AccountStateDiff::new(
        ownership_account.clone(),
        BalanceDiff::Add(0),
        record
            .to_bytes()
            .try_into()
            .expect("StakeRecord should fit in account data"),
    );

    let mut config = decode_config(&config_account, self_account_id);
    let entry = config
        .entries
        .get_mut(&record.sequencer_key)
        .expect("staked key must already have a config entry");
    assert_eq!(
        entry.account_id, ownership_account.account_id,
        "config entry points at a different ownership account"
    );
    entry.total_staked = entry
        .total_staked
        .checked_sub(pending.amount)
        .expect("total staked underflow");
    entry.total_pending_unstake = entry
        .total_pending_unstake
        .checked_sub(pending.amount)
        .expect("total pending unstake underflow");
    // Full drain is defined on the tracked stake, not the balance.
    if entry.total_staked == 0 {
        config.entries.remove(&record.sequencer_key);
    }

    let config_post = AccountStateDiff::new(
        config_account,
        BalanceDiff::Add(0),
        config
            .to_bytes()
            .try_into()
            .expect("SequencerStakeConfig should fit in account data"),
    );

    let release_call = custody_transfer(
        funds_account.account_id,
        stake_funds_seed(&ownership_account.account_id),
        destination_account.account_id,
        pending.amount,
    );

    (
        vec![
            ownership_post,
            AccountStateDiff::unchanged(funds_account),
            AccountStateDiff::unchanged(destination_account),
            config_post,
        ],
        vec![release_call],
    )
}
