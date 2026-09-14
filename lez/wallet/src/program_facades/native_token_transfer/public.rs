use common::HashType;
use lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID;

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
        let (instruction_data, tx_pre_check) = native_transfer_preparation(balance_to_move);

        self.0
            .send_pub_tx_with_pre_check(
                vec![from.balance(), to.balance()],
                instruction_data,
                NATIVE_TOKEN_PROGRAM_ID,
                tx_pre_check,
            )
            .await
    }
}
