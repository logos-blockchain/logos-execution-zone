use lee::program::Program;
use lee_core::{
    native_token::{Message, NATIVE_TOKEN_PROGRAM_ID, decode_balance},
    program::MessageData,
};

use crate::{AccountMention, ExecutionFailureKind, SelectedShard, WalletCore};

pub mod deshielded;
pub mod private;
pub mod public;
pub mod shielded;

#[expect(
    clippy::multiple_inherent_impl,
    reason = "impl blocks split across multiple files for organization"
)]
pub struct NativeTokenTransfer<'wallet>(pub &'wallet WalletCore);

// `accounts` is `[sender, recipient]`; the sender's native actor is the root.
fn native_transfer_preparation(
    accounts: &[AccountMention; 2],
    balance_to_move: u128,
) -> (
    MessageData,
    impl FnOnce(&[SelectedShard]) -> Result<(), ExecutionFailureKind> + use<>,
) {
    let message = Program::serialize_message(Message::Transfer {
        to: accounts[1].identity.account_id(),
        amount: balance_to_move,
    })
    .unwrap();

    // TODO: handle large Err-variant properly
    let tx_pre_check = move |accounts: &[SelectedShard]| {
        let from = &accounts[0];
        let balance = decode_balance(from.shard_of(NATIVE_TOKEN_PROGRAM_ID))
            .map_err(|_error| ExecutionFailureKind::AccountDataError(from.selector.account_id))?;
        if balance >= balance_to_move {
            Ok(())
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    };

    (message, tx_pre_check)
}
