use lee_core::program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ProgramId;

/// Moves the whole balance of another program's slot into its own, inside one account.
/// Conservation still holds, so rule 4 is the only thing that can reject it.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: foreign_program_id,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut account_post = pre.account.clone();
    let drained = account_post.balance(foreign_program_id);
    account_post.slot_mut(foreign_program_id).balance = 0;
    let own = account_post.slot_mut(self_program_id);
    own.balance = own.balance.checked_add(drained).expect("balance overflow");
    account_post.prune();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![account_post],
    )
    .write();
}
