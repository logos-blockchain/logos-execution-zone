use lee_core::{
    account::AccountId,
    program::{
        AccountStateDiff, ChainedCall, InstructionData, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call, respond_unsupported_call,
    },
};

/// A program whose only job is to originate a chained call: it forwards a
/// caller-supplied instruction to a caller-supplied program account, passing
/// its own input accounts straight through. Used to reach the
/// `caller_account_id` guards in programs that reject being invoked as a
/// chained call — e.g. `sequencer_stake`'s `Stake` (top-level only) and
/// `ConfirmStake` (self-chained only).
type Instruction = (AccountId, InstructionData);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (target_program_account_id, forwarded_instruction_data),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    // Forward the same accounts, in the same order, into the chained call. The
    // callee sees this program as its `caller_account_id`.
    let chained_call = ChainedCall {
        program_account_id: target_program_account_id,
        pre_state_ids: pre_states.iter().map(|pre| pre.account_id).collect(),
        instruction_data: forwarded_instruction_data,
        pda_seeds: Vec::new(),
    };

    // Leave every input account untouched; this program exists only to be the
    // caller of `target_program_account_id`, never to mutate state itself.
    let post_states = pre_states
        .into_iter()
        .map(AccountStateDiff::unchanged)
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
