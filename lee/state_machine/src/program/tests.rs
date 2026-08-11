use fee_core::params::MAX_GAS_EXEC;
use lee_core::account::{Account, AccountId, AccountWithMetadata};

use crate::{error::LeeError, program::Program};

/// User cycles metered by `simple_balance_transfer` on the inputs of
/// [`simple_balance_transfer_inputs`].
///
/// Pinned on purpose: metered cycles are a consensus input for fees, so if this number moves (a
/// risc0 upgrade, a guest change, a change to the inputs) every node's gas accounting moves with
/// it. This test is the regression alarm for that — it must fail loudly, not be re-pinned casually.
const SIMPLE_BALANCE_TRANSFER_CYCLES: u64 = 57_239;

const SENDER_BALANCE: u128 = 77_665_544_332_211;
const BALANCE_TO_MOVE: u128 = 11_223_344_556_677;

fn simple_balance_transfer_inputs() -> [AccountWithMetadata; 2] {
    let sender = AccountWithMetadata::new(
        Account {
            balance: SENDER_BALANCE,
            ..Account::default()
        },
        true,
        AccountId::new([0; 32]),
    );
    let recipient = AccountWithMetadata::new(Account::default(), false, AccountId::new([1; 32]));
    [sender, recipient]
}

#[test]
fn program_execution() {
    let program = crate::test_methods::simple_balance_transfer();
    let instruction_data = Program::serialize_instruction(BALANCE_TO_MOVE).unwrap();

    let expected_sender_post = Account {
        balance: SENDER_BALANCE - BALANCE_TO_MOVE,
        ..Account::default()
    };
    let expected_recipient_post = Account {
        balance: BALANCE_TO_MOVE,
        ..Account::default()
    };
    let (program_output, cycles) = program
        .execute(
            None,
            &simple_balance_transfer_inputs(),
            &instruction_data,
            MAX_GAS_EXEC,
        )
        .unwrap();

    let [sender_post, recipient_post] = program_output.post_states.try_into().unwrap();

    assert_eq!(sender_post.account(), &expected_sender_post);
    assert_eq!(recipient_post.account(), &expected_recipient_post);
    assert_eq!(
        cycles, SIMPLE_BALANCE_TRANSFER_CYCLES,
        "metered user cycles changed: gas accounting is consensus-critical, see the constant's docs"
    );
}

#[test]
fn execution_over_the_cycle_budget_is_out_of_gas() {
    // A budget below what the program needs must surface as the typed `OutOfGas`, so callers can
    // charge for it instead of parsing an opaque failure string.
    //
    // The executor tests the limit between instructions, so a session can overshoot it by the
    // cycles of its final instruction (here: 1); `- 2` is the tightest budget that still bails.
    let program = crate::test_methods::simple_balance_transfer();
    let instruction_data = Program::serialize_instruction(BALANCE_TO_MOVE).unwrap();
    let budget = SIMPLE_BALANCE_TRANSFER_CYCLES - 2;

    let result = program.execute(
        None,
        &simple_balance_transfer_inputs(),
        &instruction_data,
        budget,
    );

    assert!(
        matches!(result, Err(LeeError::OutOfGas { budget: reported }) if reported == budget),
        "expected OutOfGas for a budget below the program's cycle cost",
    );
}
