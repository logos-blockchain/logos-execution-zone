use cross_zone_outbox_core::{Instruction, OutboxRecord, outbox_pda};
use lee_core::{
    account::{AccountInput, BalanceDiff},
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
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

    // The emitter, and the only identity here the state machine verifies: it
    // checks a guest's claimed caller against the real one. Note this is the
    // immediate chained caller, not the top-level program that cross-zone
    // discovery names; the two coincide only while every emitter refuses to be
    // called by another program, which both do today.
    let Some(emitter) = caller_account_id else {
        panic!("Outbox is only callable through a chain call from a user program");
    };

    let (target_zone, target_account_id, target_accounts, payload, ordinal) = match instruction {
        Instruction::Emit {
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => (
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        ),
    };

    let [outbox] =
        <[AccountInput; 1]>::try_from(pre_states).expect("Emit requires exactly 1 account");

    assert_eq!(
        outbox.account_id,
        outbox_pda(self_account_id, emitter, &target_zone, ordinal),
        "Account must be the outbox PDA for (emitter, target_zone, ordinal)"
    );

    // A slot holds one message for ever. Identity first, so a wrong account that
    // happens to be free is reported as the wrong account rather than as a used
    // slot.
    //
    // A slot can still be denied to its intended writer by a real emission: the
    // ordinal is caller-chosen in a shard every user of an emitter shares,
    // and an emission needs no signature, so anyone can occupy one. A client must
    // pick an ordinal the chain does not already hold rather than counting from
    // zero.
    assert!(
        outbox.shard_of(self_account_id).is_empty(),
        "Outbox slot already written: one Emit per (emitter, target_zone, ordinal)"
    );

    let new_data = OutboxRecord {
        emitter,
        target_zone,
        ordinal,
        target_account_id,
        target_accounts,
        payload,
    }
    .to_bytes()
    .try_into()
    .expect("OutboxRecord fits in account data");

    let post = AccountStateDiff::new(outbox, BalanceDiff::Add(0), new_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![post],
    )
    .write();
}
