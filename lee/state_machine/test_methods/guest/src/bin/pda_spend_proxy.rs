use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};
use risc0_zkvm::serde::to_vec;

/// Proxy for spending from a private PDA via `simple_transfer`.
///
/// `pre_states = [pda (authorized), recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained call to `simple_transfer`.
type Instruction = (PdaSeed, u128, ProgramId);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, amount, simple_transfer_id),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => {
            unreachable!(
                "pda_spend_proxy never produces an AccountDiffOutput with diff_data, so its \
                 UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    assert!(first.is_authorized, "first pre_state must be authorized");

    let first_post = AccountDiffOutput::new(AccountDiff {
        id: first.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    });
    let second_post = AccountDiffOutput::new(AccountDiff {
        id: second.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    });

    let chained_call = ChainedCall {
        program_id: simple_transfer_id,
        instruction_data: to_vec(&amount).unwrap(),
        pre_states: vec![first.clone(), second.clone()],
        pda_seeds: vec![seed],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![first, second],
        vec![first_post, second_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
