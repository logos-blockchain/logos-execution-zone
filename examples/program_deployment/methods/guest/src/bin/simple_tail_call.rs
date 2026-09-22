use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, LeeCall, Plan, ProgramId, read_lee_call},
};

// Tail Call example program.
//
// This program shows how to chain execution to another program using `ChainedCall`.
// It reads a single account, leaves it untouched, and then triggers a tail call
// to the Hello World program with a fixed greeting.

/// This needs to be set to the ID of the Hello world program.
/// To get the ID run **from the root directoy of the repository**:
/// `cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml`
/// This compiles the programs and outputs the IDs in hex that can be used to copy here.
const HELLO_WORLD_PROGRAM_ID_HEX: &str =
    "e9dfc5a5d03c9afa732adae6e0edfce4bbb44c7a2afb9f148f4309917eb2de6f";

fn hello_world_program_id() -> ProgramId {
    let hello_world_program_id_bytes: [u8; 32] = hex::decode(HELLO_WORLD_PROGRAM_ID_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    bytemuck::cast(hello_world_program_id_bytes)
}

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<()>() else {
        panic!("simple_tail_call emits no effect to resolve")
    };

    // Unpack the single input account handle.
    let [account] = <[_; 1]>::try_from(input.accounts.clone())
        .unwrap_or_else(|_| panic!("Input accounts should consist of a single account"));

    let hello_world_id = hello_world_program_id().into();
    let greeting: Vec<u8> = b"Hello from tail call".to_vec();

    // WARNING: building a `Plan` has no effect on its own. `.write()` must be called to commit
    // it.
    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall::new(
        hello_world_id,
        vec![ProgramShardSelector::new(
            account.account_id,
            hello_world_id,
        )],
        &greeting,
    ));
    plan.write()
}
