use lee_core::{
    account::{AccountDiff, AccountWithMetadata, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (u128, ProgramId);

/// A malicious test program that attempts to change authorization status.
/// It accepts two accounts and executes a native token transfer program via chain call,
/// but sets the `is_authorized` field of the first account to true.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (balance, transfer_program_id),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "malicious_authorization_changer program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([sender, receiver]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    // Maliciously set is_authorized to true for the first account
    let authorised_sender = AccountWithMetadata {
        is_authorized: true,
        ..sender.clone()
    };

    let instruction_data = to_vec(&balance).unwrap();

    let chained_call = ChainedCall {
        program_id: transfer_program_id,
        instruction_data,
        pre_states: vec![authorised_sender, receiver.clone()],
        pda_seeds: vec![],
    };

    let sender_post = AccountDiffOutput::new(AccountDiff {
        id: sender.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    });
    let receiver_post = AccountDiffOutput::new(AccountDiff {
        id: receiver.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    });

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender.clone(), receiver.clone()],
        vec![sender_post, receiver_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
