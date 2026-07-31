use lee_core::account::{Account, AccountDiff, AccountId, AccountWithMetadata, BalanceDiff};

use crate::program::Program;

#[test]
fn program_execution() {
    let program = crate::test_methods::simple_balance_transfer();
    let balance_to_move: u128 = 11_223_344_556_677;
    let instruction_data = Program::serialize_instruction(balance_to_move).unwrap();
    let sender_id = AccountId::new([0; 32]);
    let recipient_id = AccountId::new([1; 32]);
    let sender = AccountWithMetadata::new(
        Account {
            balance: 77_665_544_332_211,
            ..Account::default()
        },
        true,
        sender_id,
    );
    let recipient = AccountWithMetadata::new(Account::default(), false, recipient_id);

    let expected_sender_diff = AccountDiff {
        id: sender_id,
        diff_balance: BalanceDiff::Sub(balance_to_move),
        raw_diff: None,
    };
    let expected_recipient_diff = AccountDiff {
        id: recipient_id,
        diff_balance: BalanceDiff::Add(balance_to_move),
        raw_diff: None,
    };
    let program_output = program
        .execute(None, &[sender, recipient], &instruction_data)
        .unwrap();

    let [sender_post, recipient_post] = program_output.post_states.try_into().unwrap();

    assert_eq!(sender_post.diff(), &expected_sender_diff);
    assert_eq!(recipient_post.diff(), &expected_recipient_diff);
}
