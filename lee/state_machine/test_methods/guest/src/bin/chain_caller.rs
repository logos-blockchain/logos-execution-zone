use borsh::to_vec;
use lee_core::program::{
    AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

type Instruction = (u128, ProgramId, u32, Option<PdaSeed>);

/// A program that calls another program `num_chain_calls` times.
/// It permutes the order of the input accounts on the subsequent call
/// The `ProgramId` in the instruction must be the `program_id` of the transfers
/// program.
fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (balance, simple_transfer_id, num_chain_calls, pda_seed),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let call_instruction_data = to_vec(&balance).unwrap();

    let mut running_recipient_pre = recipient_pre.clone();
    let mut running_sender_pre = sender_pre.clone();

    if pda_seed.is_some() {
        running_sender_pre.is_authorized = true;
    }

    let mut chained_calls = Vec::new();
    for _i in 0..num_chain_calls {
        let new_chained_call = ChainedCall {
            program_account_id: simple_transfer_id.into(),
            instruction_data: call_instruction_data.clone(),
            pre_states: vec![running_sender_pre.clone(), running_recipient_pre.clone()], /* <- Account order permutation here */
            pda_seeds: pda_seed.iter().copied().collect(),
        };
        chained_calls.push(new_chained_call);

        running_sender_pre.account.balance =
            match running_sender_pre.account.balance.checked_sub(balance) {
                Some(new_balance) => new_balance,
                None => return,
            };
        running_recipient_pre.account.balance =
            match running_recipient_pre.account.balance.checked_add(balance) {
                Some(new_balance) => new_balance,
                None => return,
            };
    }

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![sender_pre.clone(), recipient_pre.clone()],
        vec![
            AccountPostState::new(sender_pre.account),
            AccountPostState::new(recipient_pre.account),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
