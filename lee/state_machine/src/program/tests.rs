use lee_core::account::{Account, AccountId, AccountWithMetadata};
use risc0_zkvm::{ExecutorEnv, default_executor};

use crate::program::Program;

#[test]
fn program_execution() {
    let program = crate::test_methods::simple_balance_transfer();
    let balance_to_move: u128 = 11_223_344_556_677;
    let instruction_data = Program::serialize_instruction(balance_to_move).unwrap();
    let sender = AccountWithMetadata::new(
        Account {
            balance: 77_665_544_332_211,
            ..Account::default()
        },
        true,
        AccountId::new([0; 32]),
    );
    let recipient = AccountWithMetadata::new(Account::default(), false, AccountId::new([1; 32]));

    let expected_sender_post = Account {
        balance: 77_665_544_332_211 - balance_to_move,
        ..Account::default()
    };
    let expected_recipient_post = Account {
        balance: balance_to_move,
        ..Account::default()
    };
    let program_output = program
        .execute(
            AccountId::from(program.id()),
            None,
            &[sender, recipient],
            &instruction_data,
        )
        .unwrap();

    let [sender_post, recipient_post] = program_output.post_states.try_into().unwrap();

    assert_eq!(sender_post.account(), &expected_sender_post);
    assert_eq!(recipient_post.account(), &expected_recipient_post);
}

#[test]
fn journal_is_the_borsh_frame_of_the_output_and_echoes_instruction_data() {
    let program = crate::test_methods::simple_balance_transfer();
    let instruction_data = Program::serialize_instruction(7_u128).unwrap();
    let pre_states = [
        AccountWithMetadata::new(
            Account {
                balance: 10,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        ),
        AccountWithMetadata::new(Account::default(), false, AccountId::new([1; 32])),
    ];

    let mut env_builder = ExecutorEnv::builder();
    Program::write_inputs(
        AccountId::from(program.id()),
        None,
        &pre_states,
        &instruction_data,
        &mut env_builder,
    )
    .unwrap();
    let session_info = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .unwrap();

    let payload = lee_core::from_frame(&session_info.journal.bytes).unwrap();
    let output: lee_core::program::ProgramOutput = borsh::from_slice(payload).unwrap();

    // The journal must be byte-identical to `to_frame(borsh(output))`: the privacy circuit
    // reconstructs exactly these bytes for `env::verify`, so any drift breaks recursion.
    assert_eq!(
        session_info.journal.bytes,
        lee_core::to_frame(&borsh::to_vec(&output).unwrap())
    );
    // The guest must echo the instruction bytes verbatim: chained-call binding compares them.
    assert_eq!(output.instruction_data, instruction_data);
}

#[test]
fn malformed_journal_frame_is_an_error_not_a_panic() {
    let program = crate::test_methods::malformed_journal();
    let err = program
        .execute(AccountId::from(program.id()), None, &[], &Vec::new())
        .unwrap_err();
    assert!(
        matches!(
            &err,
            crate::error::LeeError::ProgramExecutionFailed(msg)
                if msg.contains("malformed program journal frame")
        ),
        "expected malformed-frame ProgramExecutionFailed, got: {err:?}"
    );
}
