use std::convert::Infallible;

use cross_zone_outbox_core::{Instruction, OutboxRecord, outbox_pda, outbox_pda_seed};
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
};

/// The record is fully computed before being written, so `diff_data` already *is* the new data
/// verbatim — materializing it is a passthrough.
fn update_from_diff(_pre_state: Account, diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(diff_data
        .try_into()
        .expect("diff_data was already validated to fit under DATA_MAX_LENGTH when constructed"))
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&pre_state, &diff_data, &data);
            return;
        }
    };

    // The emitter, and the only identity here the state machine verifies: it
    // checks a guest's claimed caller against the real one. Note this is the
    // immediate chained caller, not the top-level program that cross-zone
    // discovery names; the two coincide only while every emitter refuses to be
    // called by another program, which both do today.
    let Some(emitter) = caller_program_id else {
        panic!("Outbox is only callable through a chain call from a user program");
    };

    let (target_zone, target_program_id, target_accounts, payload, ordinal) = match instruction {
        Instruction::Emit {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        } => (
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        ),
    };

    let [outbox] =
        <[AccountWithMetadata; 1]>::try_from(pre_states).expect("Emit requires exactly 1 account");

    assert_eq!(
        outbox.account_id,
        outbox_pda(self_program_id, emitter, &target_zone, ordinal),
        "Account must be the outbox PDA for (emitter, target_zone, ordinal)"
    );

    // A slot holds one message for ever. Identity first, so a wrong account that
    // happens to be free is reported as the wrong account rather than as a used
    // slot.
    //
    // This is the same predicate the state machine already requires of a first
    // write, so guest and host agree by construction rather than by coincidence.
    //
    // It also means a slot can be denied to its intended writer: the ordinal is
    // caller-chosen in a namespace every user of an emitter shares, and an
    // emission needs no signature, so anyone can occupy one. A client must pick
    // an ordinal the chain does not already hold rather than counting from zero.
    assert_eq!(
        outbox.account,
        Account::default(),
        "Outbox slot already written: one Emit per (emitter, target_zone, ordinal)"
    );

    let new_data = OutboxRecord {
        emitter,
        target_zone,
        ordinal,
        target_program_id,
        target_accounts,
        payload,
    }
    .to_bytes();

    // Unconditional, since the pre-state is provably default by the assert above.
    let post = AccountDiffOutput::new_claimed(
        AccountDiff {
            id: outbox.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(new_data),
        },
        Claim::Pda(outbox_pda_seed(emitter, &target_zone, ordinal)),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![outbox],
        vec![post],
    )
    .write();
}
