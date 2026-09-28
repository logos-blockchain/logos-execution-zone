use lee_core::program::{Plan, PlanInput, run_program};

// Hello-world with write + move_data example program.
//
// This program reads an instruction of the form `(function_id, data)` and
// dispatches to either:
//
// - `write`: appends `data` to this program's own shard on a single input account.
// - `move_data`: moves bytes out of one account's shard into another's. The source shard is cleared
//   and the destination shard receives the appended bytes.
//
// `plan` never sees account contents, so `move_data` cannot read what it is about to move.
// The caller states the source's contents in `data`; the source's own effect applies first and
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

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    Some(match effect {
        Effect::Append(data) => {
            let mut bytes = pre_data.to_vec();
            bytes.extend_from_slice(&data);
            bytes
        }
        Effect::MoveOut(data) => {
            assert_eq!(
                pre_data, data,
                "the source account does not hold the bytes the instruction moves out of it"
            );
            Vec::new()
        }
    })
}

fn main() {
    run_program(plan, apply)
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    let (function_id, data) = instruction;

    match (input.accounts.as_slice(), function_id) {
        ([account], WRITE_FUNCTION_ID) => plan.effect(account, &Effect::Append(data)),
        ([from, to], MOVE_DATA_FUNCTION_ID) => {
            plan.effect(from, &Effect::MoveOut(data.clone()));
            plan.effect(to, &Effect::Append(data));
        }
        _ => panic!("invalid params"),
    }
    plan
}
