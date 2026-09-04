use common::HashType;

use super::NativeTokenTransfer;
use crate::{
    AccountIdentity, ExecutionFailureKind,
    program_facades::native_token_transfer::auth_transfer_preparation,
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountIdentity,
        to: AccountIdentity,
        balance_to_move: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_pub_tx_with_pre_check(
                vec![from, to],
                instruction_data,
                program.id(),
                tx_pre_check,
            )
            .await
    }
}
