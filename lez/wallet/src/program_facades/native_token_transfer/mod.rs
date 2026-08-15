use lee::{
    Account, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
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

pub(super) fn auth_transfer_program_with_deps() -> ProgramWithDependencies {
    ProgramWithDependencies::from(programs::authenticated_transfer()).with_program_account_id(
        program_loader_core::immutable_deploy_account_id(programs::authenticated_transfer().id()),
    )
}

fn auth_transfer_preparation(
    balance_to_move: u128,
) -> (
    InstructionData,
    Program,
    impl FnOnce(&[&Account]) -> Result<(), ExecutionFailureKind>,
) {
    let instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        })
        .unwrap();

    // TODO: handle large Err-variant properly
    let tx_pre_check = move |accounts: &[&Account]| {
        let from = accounts[0];
        if from.balance >= balance_to_move {
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
