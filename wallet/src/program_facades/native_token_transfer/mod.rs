use nssa::{Account, program::Program};
use nssa_core::program::InstructionData;

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

fn auth_transfer_preparation(
    balance_to_move: u128,
) -> (
    InstructionData,
    Program,
    impl FnOnce(&[&Account]) -> Result<(), ExecutionFailureKind>,
) {
    let instruction_data = Program::serialize_instruction(balance_to_move).unwrap();
    let program = Program::authenticated_transfer_program();

    // TODO: handle large Err-variant properly
    let tx_pre_check = move |accounts: &[&Account]| {
        let from = accounts[0];
        if from.balance >= balance_to_move {
            Ok(())
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    };

    (instruction_data, program, tx_pre_check)
}
