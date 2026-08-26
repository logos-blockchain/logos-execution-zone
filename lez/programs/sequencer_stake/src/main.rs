use std::collections::btree_map::Entry;

use lee_core::{
    account::{AccountId, Input, Slot},
    program::{
        ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};
use sequencer_stake_core::{
    Instruction, PendingUnstake, SequencerEntry, SequencerKey, SequencerStakeConfig, StakeRecord,
    sequencer_stake_config_account_id,
};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

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
            let post = confirm_stake(self_program_id, pre_states.clone(), expected_balance_after);
            (post, Vec::new())
        }
        Instruction::UnstakeRequest {
            amount,
            destination,
            native_program,
        } => {
            assert!(
                caller_program_id.is_none(),
                "UnstakeRequest is only invoked as a top-level user transaction"
            );
            let post = unstake_request(
                self_program_id,
                pre_states.clone(),
                amount,
                destination,
                native_program,
            );
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

fn decode_config(config_account: &Input, self_program_id: ProgramId) -> SequencerStakeConfig {
    // By id: every ownership account carries a slot of this program too, and its data is
    // caller-influenced.
    assert_eq!(
        config_account.account_id,
        sequencer_stake_config_account_id(self_program_id),
        "not the sequencer_stake config account"
    );
    SequencerStakeConfig::from_bytes(config_account.data(self_program_id))
        .expect("config account data should decode as SequencerStakeConfig")
}

fn stake(
    self_program_id: ProgramId,
    pre_states: Vec<Input>,
    sequencer_key: SequencerKey,
    amount: u128,
    mover_program_id: ProgramId,
    mover_instruction_data: InstructionData,
) -> (Vec<Option<Slot>>, Vec<ChainedCall>) {
    let [funding_account, ownership_account, config_account] = <[Input; 3]>::try_from(pre_states)
        .expect("Stake requires a funding account, an ownership account, and the config account");

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );

    let mut config = decode_config(&config_account, self_program_id);
    let minimum_sequencer_stake = config.minimum_sequencer_stake;

    let expected_balance_after = ownership_account
        .balance(self_program_id)
        .checked_add(amount)
        .expect("stake amount overflow");

    // An ownership account keeps its record after a full exit, so what a call is
    // doing follows from the config entry, not from the record. Read against the
    // data, not the slot: anyone can credit the slot into existence.
    let stake_data = ownership_account.data(self_program_id);
    let is_staked = !stake_data.is_empty();
    if is_staked {
        let record = StakeRecord::from_bytes(stake_data)
            .expect("staked ownership account should decode as StakeRecord");
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
            // top up: same already-staked account only
            assert!(
                is_staked,
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
    let funding_account_post = funding_account.unchanged();

    let mut ownership_account_post = ownership_account.slot_of(self_program_id).clone();
    ownership_account_post.data = StakeRecord {
        sequencer_key,
        pending_unstake: None,
    }
    .to_bytes()
    .try_into()
    .expect("StakeRecord should fit in account data");

    let mut config_account_post = config_account.into_slot_of(self_program_id);
    config_account_post.data = config
        .to_bytes()
        .try_into()
        .expect("SequencerStakeConfig should fit in account data");

    // chained-call pre-states reflect state as of when each call runs
    let ownership_account_recorded =
        ownership_account.with_slot(self_program_id, ownership_account_post.clone());

    let mover_call = ChainedCall {
        program_id: mover_program_id,
        pre_states: vec![funding_account, ownership_account_recorded.clone()],
        instruction_data: mover_instruction_data,
        pda_seeds: vec![],
    };

    // expected balance after the mover call
    let mut after_mover_slot = ownership_account_post.clone();
    after_mover_slot.balance = expected_balance_after;
    let ownership_account_after_mover =
        ownership_account_recorded.with_slot(self_program_id, after_mover_slot);

    let confirm_call = ChainedCall::new(
        self_program_id,
        vec![ownership_account_after_mover],
        &Instruction::ConfirmStake {
            expected_balance_after,
        },
    );

    (
        vec![
            funding_account_post,
            Some(ownership_account_post),
            Some(config_account_post),
        ],
        vec![mover_call, confirm_call],
    )
}

fn confirm_stake(
    self_program_id: ProgramId,
    pre_states: Vec<Input>,
    expected_balance_after: u128,
) -> Vec<Option<Slot>> {
    let [ownership_account] = <[Input; 1]>::try_from(pre_states)
        .expect("ConfirmStake requires exactly the ownership account");

    assert_eq!(
        ownership_account.balance(self_program_id),
        expected_balance_after,
        "mover call did not deposit the expected amount into the ownership account"
    );

    vec![ownership_account.unchanged()]
}

fn unstake_request(
    self_program_id: ProgramId,
    pre_states: Vec<Input>,
    amount: u128,
    destination: AccountId,
    native_program: ProgramId,
) -> Vec<Option<Slot>> {
    let [ownership_account, config_account] = <[Input; 2]>::try_from(pre_states)
        .expect("UnstakeRequest requires the ownership account and the config account");

    assert!(
        ownership_account.is_authorized,
        "must sign for the ownership account"
    );

    let mut record = StakeRecord::from_bytes(ownership_account.data(self_program_id))
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

    // Sized against the tracked stake, never the slot balance: anyone can credit
    // any slot, so balance can exceed `total_staked`. Covers both "not more than
    // is staked" and "zero or at least the minimum".
    assert!(
        entry.allows_unstake_request(amount, minimum_sequencer_stake),
        "unstake request must be covered by the staked total and leave the key at zero or at/above the minimum"
    );

    record.pending_unstake = Some(PendingUnstake {
        amount,
        destination,
        native_program,
    });
    entry.total_pending_unstake = entry
        .total_pending_unstake
        .checked_add(amount)
        .expect("total pending unstake overflow");

    // only data changes here; transfer happens in FinalizeUnstake
    let mut ownership_account_post = ownership_account.into_slot_of(self_program_id);
    ownership_account_post.data = record
        .to_bytes()
        .try_into()
        .expect("StakeRecord should fit in account data");

    let mut config_account_post = config_account.into_slot_of(self_program_id);
    config_account_post.data = config
        .to_bytes()
        .try_into()
        .expect("SequencerStakeConfig should fit in account data");

    vec![Some(ownership_account_post), Some(config_account_post)]
}

fn finalize_unstake(self_program_id: ProgramId, pre_states: Vec<Input>) -> Vec<Option<Slot>> {
    let [ownership_account, destination_account, config_account] =
        <[Input; 3]>::try_from(pre_states).expect(
            "FinalizeUnstake requires the ownership account, a destination account, and the config account",
        );

    let mut record = StakeRecord::from_bytes(ownership_account.data(self_program_id))
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
    let mut ownership_account_post = ownership_account.slot_of(self_program_id).clone();
    let ownership_slot = &mut ownership_account_post;
    ownership_slot.balance = ownership_slot
        .balance
        .checked_sub(pending.amount)
        .expect("insufficient staked balance");
    ownership_slot.data = record
        .to_bytes()
        .try_into()
        .expect("StakeRecord should fit in account data");

    // The staker chose this namespace under signature at UnstakeRequest; `FinalizeUnstake`
    // carries none, so a caller-named slot could route the release into one no program can
    // ever debit.
    let mut destination_post = destination_account.into_slot_of(pending.native_program);
    destination_post.balance = destination_post
        .balance
        .checked_add(pending.amount)
        .expect("finalize unstake amount overflow");

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

    let mut config_account_post = config_account.into_slot_of(self_program_id);
    config_account_post.data = config
        .to_bytes()
        .try_into()
        .expect("SequencerStakeConfig should fit in account data");

    vec![
        Some(ownership_account_post),
        Some(destination_post),
        Some(config_account_post),
    ]
}
