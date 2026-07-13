use cross_zone_outbox_core::{Instruction, OutboxRecord, outbox_pda, outbox_pda_seed};
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_some(),
        "Outbox is only callable through a chain call from a user program"
    );

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
        outbox_pda(self_program_id, &target_zone, ordinal),
        "Account must be the outbox PDA for (target_zone, ordinal)"
    );

    let mut post_account = outbox.account.clone();
    post_account.data = OutboxRecord {
        target_zone,
        target_program_id,
        target_accounts,
        payload,
    }
    .to_bytes()
    .try_into()
    .expect("OutboxRecord fits in account data");

    let post = AccountPostState::new_claimed_if_default(
        post_account,
        Claim::Pda(outbox_pda_seed(&target_zone, ordinal)),
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
