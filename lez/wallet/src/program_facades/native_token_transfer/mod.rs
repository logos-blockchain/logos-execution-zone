use lee::program::Program;
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

fn auth_transfer_preparation(
    balance_to_move: u128,
) -> (
    InstructionData,
    Program,
    impl FnOnce(&[lee::Input]) -> Result<(), ExecutionFailureKind>,
) {
    let instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        })
        .unwrap();

    // TODO: handle large Err-variant properly
    let tx_pre_check = move |accounts: &[lee::Input]| {
        let from = &accounts[0];
        if from.balance(programs::authenticated_transfer().id()) >= balance_to_move {
            Ok(())
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    };

    (
        instruction_data,
        programs::authenticated_transfer(),
        tx_pre_check,
    )
}
