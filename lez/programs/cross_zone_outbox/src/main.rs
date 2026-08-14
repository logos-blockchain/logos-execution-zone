use cross_zone_outbox_core::{Instruction, OutboxRecord, outbox_pda, outbox_pda_seed};
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{AccountPostState, Claim, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
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
    let Some(emitter) = caller_account_id.map(ProgramId::from) else {
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
        outbox_pda(
            ProgramId::from(self_account_id),
            emitter,
            &target_zone,
            ordinal
        ),
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

    let mut post_account = outbox.account.clone();
    post_account.data = OutboxRecord {
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

    // Unconditional, since the pre-state is provably default by the assert above.
    let post = AccountPostState::new_claimed(
        post_account,
        Claim::Pda(outbox_pda_seed(emitter, &target_zone, ordinal)),
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![outbox],
        vec![post],
    )
    .write();
}
