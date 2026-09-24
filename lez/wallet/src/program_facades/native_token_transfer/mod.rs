use lee::{AccountInput, program::Program};
use lee_core::{
    native_token::{NATIVE_TOKEN_PROGRAM_ID, decode_balance},
    program::InstructionData,
};

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

fn native_transfer_preparation(
    balance_to_move: u128,
) -> (
    InstructionData,
    impl FnOnce(&[AccountInput]) -> Result<(), ExecutionFailureKind>,
) {
    let instruction_data =
        Program::serialize_instruction(lee_core::native_token::Instruction::Transfer {
            amount: balance_to_move,
        })
        .unwrap();

    // TODO: handle large Err-variant properly
    let tx_pre_check = move |accounts: &[AccountInput]| {
        let from = &accounts[0];
        let balance = decode_balance(from.shard_of(NATIVE_TOKEN_PROGRAM_ID))
            .map_err(|_error| ExecutionFailureKind::AccountDataError(from.account_id))?;
        if balance >= balance_to_move {
            Ok(())
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    };

    (instruction_data, tx_pre_check)
}
