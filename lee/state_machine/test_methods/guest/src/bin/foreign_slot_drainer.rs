use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

/// Drains a slot that is not its own into one that is, both at the same account. Conservation
/// still holds, so rule 4 is the only thing that can reject it.
///
/// Positions: `[the foreign slot, this program's own slot]`.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([foreign_pre, own_pre]) = <[_; 2]>::try_from(pre_states.clone()) else {
        return;
    };

    let mut foreign_post = foreign_pre.into_caller_named_slot();
    let drained = foreign_post.balance;
    foreign_post.balance = 0;

    let mut own_post = own_pre.into_slot_of(self_program_id);
    own_post.balance = own_post
        .balance
        .checked_add(drained)
        .expect("balance overflow");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        vec![Some(foreign_post), Some(own_post)],
    )
    .write();
}
