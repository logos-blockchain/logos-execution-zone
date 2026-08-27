use borsh::to_vec;
use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramId, read_lee_call},
};

/// Proxy for spending from a private PDA via `simple_transfer`.
///
/// `pre_states = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `simple_transfer`.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (seed, amount, simple_transfer_id),
    } = read_lee_call::<Instruction>();

    let [first, second] = input.pre_states.as_slice() else {
        return;
    };

    let first_post = AccountDiffOutput::new(AccountDiff::unchanged(first.account_id));
    let second_post = AccountDiffOutput::new(AccountDiff::unchanged(second.account_id));

    let chained_call = ChainedCall {
        program_id: simple_transfer_id,
        instruction_data: to_vec(&amount).unwrap(),
        accounts: vec![first.account_id, second.account_id],
        pda_seeds: vec![seed],
    };

    input
        .into_output(vec![first_post, second_post])
        .with_chained_calls(vec![chained_call])
        .write();
}
