use nssa_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs},
};

type Instruction = nssa_core::Timestamp;

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
        return;
    };

    let prev_block_id = u64::from_le_bytes(
        pre_01.account.data.clone().into_inner()[..8]
            .try_into()
            .expect("Clock account data should contain a LE-encoded block_id u64"),
    );
    let current_block_id = prev_block_id
        .checked_add(1)
        .expect("Next block id should be within u64 boundaries");

    let updated_data = {
        let mut data = [0_u8; 16];
        data[..8].copy_from_slice(&current_block_id.to_le_bytes());
        data[8..].copy_from_slice(&timestamp.to_le_bytes());
        data
    };

    let (pre_01, post_01) = update_if_multiple(pre_01, 1, current_block_id, updated_data);
    let (pre_10, post_10) = update_if_multiple(pre_10, 10, current_block_id, updated_data);
    let (pre_50, post_50) = update_if_multiple(pre_50, 50, current_block_id, updated_data);

    write_nssa_outputs(
        instruction_words,
        vec![pre_01, pre_10, pre_50],
        vec![post_01, post_10, post_50],
    );
}
