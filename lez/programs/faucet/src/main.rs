use authenticated_transfer_core::custody_transfer;
use faucet_core::Instruction;
use lee_core::program::{
    AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
};

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: Instruction::GenesisTransfer { amount },
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    assert!(
        caller_account_id.is_none(),
        "Faucet cannot be invoked through chain calls"
    );

    let post_diffs = pre_states
        .iter()
        .map(|pre_state| AccountStateDiff::unchanged(pre_state.clone()))
        .collect();
    let [faucet, recipient] =
        <[_; 2]>::try_from(pre_states).expect("GenesisTransfer requires exactly 2 accounts");

    assert_eq!(
        faucet.account_id,
        faucet_core::compute_faucet_account_id(self_account_id),
        "First account must be faucet PDA"
    );

    let transfer = custody_transfer(
        faucet.account_id,
        faucet_core::compute_faucet_seed(),
        recipient.account_id,
        amount,
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_diffs,
    )
    .with_chained_calls(vec![transfer])
    .write();
}
