use lee_core::program::{LeeCall, Plan, read_lee_call, resolve_write};

// Hello-world with authorization example program.
//
// This program reads an arbitrary sequence of bytes as its instruction
// and appends those bytes to this program's own shard on the single input account.
//
// Execution succeeds only if the input account **is authorized**.

type Instruction = Vec<u8>;

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            // Unpack the single input account handle.
            let [account] = <[_; 1]>::try_from(input.accounts.clone())
                .unwrap_or_else(|_| panic!("Input accounts should consist of a single account"));

            // #### Difference with `hello_world` example here:
            // Fail if the input account is not authorized
            // The `is_authorized` field will be correctly populated or verified by the system if
            // authorization is provided.
            assert!(account.is_authorized, "Missing required authorization");
            // ####

            // WARNING: building a `Plan` has no effect on its own. `.write()` must be called to
            // commit it.
            let mut plan = Plan::new(&input, instruction_data);
            plan.update(&account, &input.instruction);
            plan.write()
        }
        LeeCall::Resolve(input) => {
            let greeting: Vec<u8> = borsh::from_slice(&input.effect_data)
                .expect("hello_world_with_authorization wrote its own effect");
            let mut bytes = input.pre_data.clone().into_inner();
            bytes.extend_from_slice(&greeting);
            resolve_write(
                input,
                bytes
                    .try_into()
                    .expect("ShardData should fit within the allowed limits"),
            )
        }
    }
}
