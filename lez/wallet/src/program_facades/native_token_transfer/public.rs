use common::HashType;

use super::NativeTokenTransfer;
use crate::{
    ExecutionFailureKind, Identity,
    program_facades::native_token_transfer::auth_transfer_preparation,
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: Identity,
        to: Identity,
        balance_to_move: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_pub_tx_with_pre_check(
                // Both positions name the native namespace: debited at the sender,
                // credited at the recipient.
                vec![
                    from.in_namespace(program.id()),
                    to.in_namespace(program.id()),
                ],
                instruction_data,
                program.id(),
                tx_pre_check,
            )
            .await
    }
}
