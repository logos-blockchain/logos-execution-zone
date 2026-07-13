use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};
use ping_core::{ReceiverInstruction, ping_record_pda, ping_record_seed};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<ReceiverInstruction>();

    assert!(
        caller_program_id.is_some(),
        "ping_receiver is only callable through a chained call"
    );

    let payload = match instruction {
        ReceiverInstruction::Record { payload } => payload,
    };

    let [record] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("Record requires exactly 1 account");
    assert_eq!(
        record.account_id,
        ping_record_pda(self_program_id),
        "Account must be the ping record PDA"
    );

    let mut post_account = record.account.clone();
    post_account.data = payload.try_into().expect("payload fits in account data");
    let post =
        AccountPostState::new_claimed_if_default(post_account, Claim::Pda(ping_record_seed()));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![record],
        vec![post],
    )
    .write();
}
