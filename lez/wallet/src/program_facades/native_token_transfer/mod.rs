use lee::{AccountInput, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program};
use lee_core::program::InstructionData;

use crate::{ExecutionFailureKind, WalletCore};

pub mod deshielded;
pub mod private;
pub mod public;
pub mod shielded;

#[expect(
    clippy::multiple_inherent_impl,
    reason = "impl blocks split across multiple files for organization"
)]
pub struct NativeTokenTransfer<'wallet>(pub &'wallet WalletCore);

/// Builds `authenticated_transfer`'s instruction data, its `ProgramWithDependencies` at its
/// real, name-derived address (not [`Program`]'s bijection-address `.into()`, which no longer
/// matches its genesis address), and a pre-check closure.
fn auth_transfer_preparation(
    balance_to_move: u128,
) -> (
    InstructionData,
    ProgramWithDependencies,
    impl FnOnce(&[AccountInput]) -> Result<(), ExecutionFailureKind>,
) {
    let instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        })
        .unwrap();

    // TODO: handle large Err-variant properly
    let tx_pre_check = move |accounts: &[AccountInput]| {
        let from = &accounts[0];
        if from.balance >= balance_to_move {
            Ok(())
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    };

    let program = ProgramWithDependencies::new(
        programs::authenticated_transfer(),
        programs::authenticated_transfer_account_id(),
        std::collections::HashMap::new(),
    );

    (instruction_data, program, tx_pre_check)
}
