use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData, Instruction,
};
use nssa_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs},
};

fn update_if_multiple(
    pre: AccountWithMetadata,
    divisor: u64,
    current_block_id: u64,
    updated_data: [u8; 16],
) -> (AccountWithMetadata, AccountPostState) {
    if current_block_id.is_multiple_of(divisor) {
        let mut post_account = pre.account.clone();
        post_account.data = updated_data
            .to_vec()
            .try_into()
            .expect("16 bytes should fit in account data");
        (pre, AccountPostState::new(post_account))
    } else {
        let post = AccountPostState::new(pre.account.clone());
        (pre, post)
    }
}

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: timestamp,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre_01, pre_10, pre_50]) = <[_; 3]>::try_from(pre_states) else {
        panic!("Invalid number of input accounts");
    };

    // Verify pre-states correspond to the expected clock account IDs.
    if pre_01.account_id != CLOCK_01_PROGRAM_ACCOUNT_ID
        || pre_10.account_id != CLOCK_10_PROGRAM_ACCOUNT_ID
        || pre_50.account_id != CLOCK_50_PROGRAM_ACCOUNT_ID
    {
        panic!("Invalid input accounts");
    }

    let prev_data = ClockAccountData::from_bytes(
        pre_01.account.data.clone().into_inner()[..16]
            .try_into()
            .expect("Clock account data should be 16 bytes"),
    );
    let current_block_id = prev_data
        .block_id
        .checked_add(1)
        .expect("Next block id should be within u64 boundaries");

    let updated_data = ClockAccountData {
        block_id: current_block_id,
        timestamp,
    }
    .to_bytes();

    let (pre_01, post_01) = update_if_multiple(pre_01, 1, current_block_id, updated_data);
    let (pre_10, post_10) = update_if_multiple(pre_10, 10, current_block_id, updated_data);
    let (pre_50, post_50) = update_if_multiple(pre_50, 50, current_block_id, updated_data);

    ProgramOutput::new(
        instruction_words,
        vec![pre_01, pre_10, pre_50],
        vec![post_01, post_10, post_50],
    )
    .write();
}
