use lee_core::account::{Account, AccountId, AccountWithMetadata};

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
        .execute(None, &[sender, recipient], &instruction_data)
        .unwrap();

    let [sender_post, recipient_post] = program_output.post_states.try_into().unwrap();

    assert_eq!(sender_post.account(), &expected_sender_post);
    assert_eq!(recipient_post.account(), &expected_recipient_post);
}
