use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs},
};
use ping_core::SenderInstruction;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<SenderInstruction>();

    assert!(
        caller_program_id.is_none(),
        "ping_sender is only invoked as a top-level user transaction"
    );

    let SenderInstruction::Send {
        outbox_program_id,
        target_zone,
        target_program_id,
        target_accounts,
        payload,
        ordinal,
    } = instruction;

    // The single account is the outbox PDA the chained call writes into; the
    // outbox claims it, so ping_sender forwards it unchanged.
    let [outbox] =
        <[AccountWithMetadata; 1]>::try_from(pre_states).expect("Send requires exactly 1 account");

    let call = ChainedCall::new(
        outbox_program_id,
        vec![outbox.clone()],
        &OutboxInstruction::Emit {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        },
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![outbox.clone()],
        vec![AccountPostState::new(outbox.account)],
    )
    .with_chained_calls(vec![call])
    .write();
}
