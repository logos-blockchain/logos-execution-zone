use lee_core::{
    account::AccountId,
    program::{
        AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call, respond_unsupported_call,
    },
};

// Tail Call with PDA example program.
//
// Demonstrates how to chain execution to another program using `ChainedCall`
// while authorizing program-derived accounts.
//
// Expects a single input account whose Account ID is derived from this program's deployed
// address and the fixed PDA seed below (`AccountId::for_public_pda`).
//
// Emits this account unchanged, then performs a tail call to the callee program named in this
// program's own instruction data, with a fixed greeting, delegating the PDA seed so the protocol
// authorizes the account for the callee.
//
// The callee's `AccountId` is caller-supplied: a deployed program's address isn't known until
// deploy time, so it can't be a compile-time constant.

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

type Instruction = AccountId;

fn main() {
    // Read inputs
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: callee_account_id,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    // Unpack the input account pre state
    let [pre_state] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));

    // Create the (unchanged) post state
    let post_state = AccountStateDiff::unchanged(pre_state.clone());

    // Create the chained call
    let chained_call_greeting: Vec<u8> =
        b"Hello from tail call with Program Derived Account ID".to_vec();
    let chained_call_instruction_data = borsh::to_vec(&chained_call_greeting).unwrap();

    let chained_call = ChainedCall {
        program_account_id: callee_account_id,
        instruction_data: chained_call_instruction_data,
        pre_state_ids: vec![pre_state.account_id],
        pda_seeds: vec![PDA_SEED],
    };

    // Write the outputs.
    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![post_state],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
