use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

// Calls Hello World with Authorization on this program's PDA,
// passing `PDA_SEED` to authorize the account for the callee.

const HELLO_WORLD_WITH_AUTHORIZATION_PROGRAM_ID_HEX: &str =
    "1d95c761168a7fa62eb15a3cc74d3f075e6ec98e6c1ac25bd5bcc7e0a9426398";
const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

fn hello_world_program_id() -> ProgramId {
    let hello_world_program_id_bytes: [u8; 32] =
        hex::decode(HELLO_WORLD_WITH_AUTHORIZATION_PROGRAM_ID_HEX)
            .unwrap()
            .try_into()
            .unwrap();
    bytemuck::cast(hello_world_program_id_bytes)
}

fn main() {
    // Read inputs
    let call = read_lee_call::<()>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (),
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
    let hello_world_id = hello_world_program_id().into();

    let chained_call = ChainedCall {
        program_account_id: hello_world_id,
        instruction_data: chained_call_instruction_data,
        shard_selectors: vec![ProgramShardSelector::new(
            pre_state.account_id,
            hello_world_id,
        )],
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
