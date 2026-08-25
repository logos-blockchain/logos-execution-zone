use cross_zone_outbox_core::{Instruction, OutboxRecord, outbox_pda};
use lee_core::{
    account::AccountWithMetadata,
    program::{ProgramInput, ProgramOutput, read_lee_inputs},
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
    // No other program can occupy a record: this program's slot is writable only
    // by itself. What remains is a race between users of one emitter, which the
    // address already narrows to the same ordinal: the ordinal is caller-chosen
    // in a namespace they share and an emission needs no signature, so a client
    // must pick an ordinal the chain does not already hold rather than counting
    // from zero.
    assert!(
        outbox.account.slot(self_program_id).is_none(),
        "Outbox slot already written: one Emit per (emitter, target_zone, ordinal)"
    );

    let mut post = outbox.account.clone();
    post.slot_mut(self_program_id).data = OutboxRecord {
        emitter,
        target_zone,
        ordinal,
        target_program_id,
        target_accounts,
        payload,
    }
    .to_bytes()
    .try_into()
    .expect("OutboxRecord fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![outbox],
        vec![post],
    )
    .write();
}
