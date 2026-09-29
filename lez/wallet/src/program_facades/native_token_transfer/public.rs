use common::HashType;

use super::NativeTokenTransfer;
use crate::{
    AccountIdentity, ExecutionFailureKind,
    program_facades::native_token_transfer::native_transfer_preparation,
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountIdentity,
        to: AccountIdentity,
        balance_to_move: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let accounts = [from.balance(), to.balance()];
        let (message, tx_pre_check) = native_transfer_preparation(&accounts, balance_to_move);

        self.0
            .send_pub_tx_with_pre_check(accounts.into(), 0, message, None, tx_pre_check)
            .await
    }
}
