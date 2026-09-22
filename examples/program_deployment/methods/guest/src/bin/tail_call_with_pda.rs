use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, LeeCall, PdaSeed, Plan, ProgramId, read_lee_call},
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
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<()>() else {
        panic!("tail_call_with_pda emits no effect to resolve")
    };

    // Unpack the single input account handle.
    let [account] = <[_; 1]>::try_from(input.accounts.clone())
        .unwrap_or_else(|_| panic!("Input accounts should consist of a single account"));

    let hello_world_id = hello_world_program_id().into();
    let greeting: Vec<u8> = b"Hello from tail call with Program Derived Account ID".to_vec();

    // WARNING: building a `Plan` has no effect on its own. `.write()` must be called to commit
    // it.
    let mut plan = Plan::new(&input, instruction_data);
    plan.call(
        ChainedCall::new(
            hello_world_id,
            vec![ProgramShardSelector::new(
                account.account_id,
                hello_world_id,
            )],
            &greeting,
        )
        .with_pda_seeds(vec![PDA_SEED]),
    );
    plan.write()
}
