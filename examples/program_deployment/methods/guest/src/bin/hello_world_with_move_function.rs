use lee_core::program::{LeeCall, Plan, read_lee_call, resolve_write};

// Hello-world with write + move_data example program.
//
// This program reads an instruction of the form `(function_id, data)` and
// dispatches to either:
//
// - `write`: appends `data` to this program's own shard on a single input account.
// - `move_data`: moves bytes out of one account's shard into another's. The source shard is cleared
//   and the destination shard receives the appended bytes.
//
// `Execute` never sees account contents, so `move_data` cannot read what it is about to move.
// The caller states the source's contents in `data`; the source's own effect resolves first and
// refuses unless the shard really holds exactly those bytes, which is what makes the value the
// destination appends a pinned one rather than a caller's claim.

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    Append(Vec<u8>),
    MoveOut(Vec<u8>),
}

fn resolve_effect(effect: &Effect, pre_data: &[u8]) -> Vec<u8> {
    match effect {
        Effect::Append(data) => {
            let mut bytes = pre_data.to_vec();
            bytes.extend_from_slice(data);
            bytes
        }
        Effect::MoveOut(data) => {
            assert_eq!(
                pre_data, data,
                "the source account does not hold the bytes the instruction moves out of it"
            );
            Vec::new()
        }
    }
}

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let (function_id, data) = input.instruction.clone();
            let mut plan = Plan::new(&input, instruction_data);

            match (input.accounts.as_slice(), function_id) {
                ([account], WRITE_FUNCTION_ID) => plan.update(account, &Effect::Append(data)),
                ([from, to], MOVE_DATA_FUNCTION_ID) => {
                    plan.update(from, &Effect::MoveOut(data.clone()));
                    plan.update(to, &Effect::Append(data));
                }
                _ => panic!("invalid params"),
            }

            // WARNING: building a `Plan` has no effect on its own. `.write()` must be called to
            // commit it.
            plan.write()
        }
        LeeCall::Resolve(input) => {
            let effect = borsh::from_slice(&input.effect_data)
                .expect("hello_world_with_move_function wrote its own effect");
            let data = resolve_effect(&effect, &input.pre_data)
                .try_into()
                .expect("ShardData should fit within the allowed limits");
            resolve_write(input, data)
        }
    }
}
