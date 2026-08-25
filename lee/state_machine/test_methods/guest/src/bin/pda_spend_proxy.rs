use borsh::to_vec;
use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};

/// Proxy for spending from a private PDA via `simple_transfer`.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `simple_transfer`.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, amount, simple_transfer_id),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let first_post = AccountDiffOutput::new(AccountDiff::unchanged(first.account_id));
    let second_post = AccountDiffOutput::new(AccountDiff::unchanged(second.account_id));

    let mut first_for_callee = first.clone();
    first_for_callee.is_authorized = true;

    let chained_call = ChainedCall {
        program_id: simple_transfer_id,
        instruction_data: to_vec(&amount).unwrap(),
        pre_states: vec![first_for_callee, second.clone()],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![first, second],
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
