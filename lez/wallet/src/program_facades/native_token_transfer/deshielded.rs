use common::HashType;
use lee::AccountId;

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{ExecutionFailureKind, Identity};

impl NativeTokenTransfer<'_> {
    pub async fn send_deshielded_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<(HashType, lee_core::SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    self.0
                        .resolve_private_account(from)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                        .in_namespace(programs::authenticated_transfer().id()),
                    Identity::PublicNoSign(to)
                        .in_namespace(programs::authenticated_transfer().id()),
                ],
                instruction_data,
                &program.into(),
                tx_pre_check,
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected sender's secret");
                (resp, first)
            })
    }
}
