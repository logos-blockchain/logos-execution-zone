use std::collections::btree_map::Entry;

use lee_core::{
    account::{AccountDiff, AccountId, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, ChainedCall, Claim, DEFAULT_PROGRAM_OWNER, InstructionData, ProgramCall,
        ProgramId, ProgramInput, ProgramOutput, read_lee_call,
    },
};
use sequencer_stake_core::{
    Instruction, PendingUnstake, SequencerEntry, SequencerKey, SequencerStakeConfig, StakeRecord,
    sequencer_stake_config_account_id,
};

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let (post_states, chained_calls) = match instruction {
        Instruction::Stake {
            sequencer_key,
            amount,
            mover_program_id,
            mover_instruction_data,
        } => {
            assert!(
                caller_program_id.is_none(),
                "Stake is only invoked as a top-level user transaction"
            );
            stake(
                self_program_id,
                pre_states.clone(),
                sequencer_key,
                amount,
                mover_program_id,
                mover_instruction_data,
            )
        }
        Instruction::ConfirmStake {
            expected_balance_after,
        } => {
            assert_eq!(
                caller_program_id,
                Some(self_program_id),
                "ConfirmStake can only be invoked as a self-chained call"
            );
            let post = confirm_stake(pre_states.clone(), expected_balance_after);
            (post, Vec::new())
        }
        Instruction::UnstakeRequest {
            amount,
            destination,
        } => {
            assert!(
                caller_program_id.is_none(),
                "UnstakeRequest is only invoked as a top-level user transaction"
            );
            let post = unstake_request(self_program_id, pre_states.clone(), amount, destination);
            (post, Vec::new())
        }
        Instruction::FinalizeUnstake => {
            assert!(
                caller_program_id.is_none(),
                "FinalizeUnstake is only invoked as a top-level user transaction"
            );
            let post = finalize_unstake(self_program_id, pre_states.clone());
            (post, Vec::new())
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}

fn decode_config(
    config_account: &AccountWithMetadata,
    self_program_id: ProgramId,
) -> SequencerStakeConfig {
    // By id, not just by owner: every ownership account is owned by this
    // program too, and its data is caller-influenced.
    assert_eq!(
        config_account.account_id,
        sequencer_stake_config_account_id(self_program_id),
        "not the sequencer_stake config account"
    );
    assert_eq!(
        config_account.account.program_owner,
        self_program_id.into(),
        "config account is not owned by sequencer_stake"
    );
    SequencerStakeConfig::from_bytes(config_account.account.data.as_ref())
        .expect("config account data should decode as SequencerStakeConfig")
}

fn stake(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    sequencer_key: SequencerKey,
    amount: u128,
    mover_program_id: ProgramId,
    mover_instruction_data: InstructionData,
) -> (Vec<AccountDiffOutput>, Vec<ChainedCall>) {
    let [funding_account, ownership_account, config_account] =
        <[AccountWithMetadata; 3]>::try_from(pre_states).expect(
            "Stake requires a funding account, an ownership account, and the config account",
        );

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );

    let mut config = decode_config(&config_account, self_program_id);
    let minimum_sequencer_stake = config.minimum_sequencer_stake;

    let balance_before = ownership_account.account.balance;
    let expected_balance_after = balance_before
        .checked_add(amount)
        .expect("stake amount overflow");

    // An ownership account stays claimed after a full exit, so what a call is
    // doing follows from the config entry, not from the account's owner.
    let is_claimed = ownership_account.account.program_owner != DEFAULT_PROGRAM_OWNER;
    if is_claimed {
        assert_eq!(
            ownership_account.account.program_owner,
            self_program_id.into(),
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
    let funding_account_post =
        AccountDiffOutput::new(AccountDiff::unchanged(funding_account.account_id));

    // claim is a no-op on a top-up (already owned)
    let new_stake_record_data: Data = StakeRecord {
        sequencer_key,
        pending_unstake: None,
    }
    .to_bytes()
    .try_into()
    .expect("StakeRecord should fit in account data");
    let ownership_diff = AccountDiff {
        id: ownership_account.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(new_stake_record_data),
    };
    let ownership_account_post = AccountDiffOutput::new_claimed_if_default(
        ownership_diff,
        ownership_account.account.program_owner,
        Claim::Authorized,
    );

    let config_diff = AccountDiff {
        id: config_account.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config
                .to_bytes()
                .try_into()
                .expect("SequencerStakeConfig should fit in account data"),
        ),
    };
    let config_account_post = AccountDiffOutput::new(config_diff);

    let mover_call = ChainedCall {
        program_id: mover_program_id,
        accounts: vec![funding_account.account_id, ownership_account.account_id],
        instruction_data: mover_instruction_data,
        pda_seeds: Vec::new(),
    };

    let confirm_call = ChainedCall::new(
        self_program_id,
        vec![ownership_account.account_id],
        &Instruction::ConfirmStake {
            expected_balance_after,
        },
    );

    (
        vec![
            funding_account_post,
            ownership_account_post,
            config_account_post,
        ],
        vec![mover_call, confirm_call],
    )
}

fn confirm_stake(
    pre_states: Vec<AccountWithMetadata>,
    expected_balance_after: u128,
) -> Vec<AccountDiffOutput> {
    let [ownership_account] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("ConfirmStake requires exactly the ownership account");

    assert_eq!(
        ownership_account.account.balance, expected_balance_after,
        "mover call did not deposit the expected amount into the ownership account"
    );

    vec![AccountDiffOutput::new(AccountDiff::unchanged(
        ownership_account.account_id,
    ))]
}

fn unstake_request(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    amount: u128,
    destination: AccountId,
) -> Vec<AccountDiffOutput> {
    let [ownership_account, config_account] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("UnstakeRequest requires the ownership account and the config account");

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );
    assert_eq!(
        ownership_account.account.program_owner,
        self_program_id.into(),
        "not a sequencer_stake ownership account"
    );

    let mut record = StakeRecord::from_bytes(ownership_account.account.data.as_ref())
        .expect("ownership account should decode as StakeRecord");
    assert!(
        record.pending_unstake.is_none(),
        "an unstake request is already pending"
    );

    let mut config = decode_config(&config_account, self_program_id);
    let minimum_sequencer_stake = config.minimum_sequencer_stake;
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
    let ownership_diff = AccountDiff {
        id: ownership_account.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            record
                .to_bytes()
                .try_into()
                .expect("StakeRecord should fit in account data"),
        ),
    };

    let config_diff = AccountDiff {
        id: config_account.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config
                .to_bytes()
                .try_into()
                .expect("SequencerStakeConfig should fit in account data"),
        ),
    };

    vec![
        AccountDiffOutput::new(ownership_diff),
        AccountDiffOutput::new(config_diff),
    ]
}

fn finalize_unstake(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
) -> Vec<AccountDiffOutput> {
    let [ownership_account, destination_account, config_account] =
        <[AccountWithMetadata; 3]>::try_from(pre_states).expect(
            "FinalizeUnstake requires the ownership account, a destination account, and the config account",
        );

    assert_eq!(
        ownership_account.account.program_owner,
        self_program_id.into(),
        "not a sequencer_stake ownership account"
    );

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
    let ownership_diff = AccountDiff {
        id: ownership_account.account_id,
        diff_balance: BalanceDiff::Sub(pending.amount),
        diff_data: Some(
            record
                .to_bytes()
                .try_into()
                .expect("StakeRecord should fit in account data"),
        ),
    };

    let destination_diff = AccountDiff {
        id: destination_account.account_id,
        diff_balance: BalanceDiff::Add(pending.amount),
        diff_data: None,
    };

    let mut config = decode_config(&config_account, self_program_id);
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

    let config_diff = AccountDiff {
        id: config_account.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config
                .to_bytes()
                .try_into()
                .expect("SequencerStakeConfig should fit in account data"),
        ),
    };

    vec![
        AccountDiffOutput::new(ownership_diff),
        AccountDiffOutput::new(destination_diff),
        AccountDiffOutput::new(config_diff),
    ]
}
