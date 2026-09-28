use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{ApplyInput, ApplyOutput},
};

use crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;

fn apply_with(post_data: Option<&[u8]>) -> (ApplyInput, ApplyOutput) {
    let program = crate::test_methods::scripted_applier();
    let self_account_id = AccountId::from_builtin_program(program.id());
    let input = ApplyInput {
        self_account_id,
        selector: ProgramShardSelector::new(AccountId::new([7; 32]), self_account_id),
        pre_data: ShardData::try_from(b"before".to_vec()).unwrap(),
        effect_data: borsh::to_vec(&post_data).unwrap(),
    };
    let (output, _cycles) = program.apply(&input, DEFAULT_PUBLIC_CYCLE_BUDGET).unwrap();
    (input, output)
}

#[test]
fn the_runner_echoes_its_input_and_keeps_clears_or_writes_as_apply_returns() {
    for (returned, post_data) in [
        (None, None),
        (Some(Vec::new()), Some(ShardData::empty())),
        (
            Some(b"after".to_vec()),
            Some(ShardData::try_from(b"after".to_vec()).unwrap()),
        ),
    ] {
        let (input, output) = apply_with(returned.as_deref());

        assert_eq!(output, ApplyOutput { input, post_data });
    }
}
