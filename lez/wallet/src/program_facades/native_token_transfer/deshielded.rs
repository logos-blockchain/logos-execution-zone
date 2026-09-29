use common::HashType;
use lee::{AccountId, privacy_preserving_transaction::circuit::ProgramCatalog};

use super::{NativeTokenTransfer, native_transfer_preparation};
use crate::{AccountIdentity, ExecutionFailureKind};

impl NativeTokenTransfer<'_> {
    pub async fn send_deshielded_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<(HashType, lee_core::SharedSecretKey), ExecutionFailureKind> {
        let accounts = [
            self.0
                .resolve_private_account(from)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance(),
            AccountIdentity::PublicNoSign(to).balance(),
        ];
        let (message, tx_pre_check) = native_transfer_preparation(&accounts, balance_to_move);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                accounts.into(),
                0,
                message,
                &ProgramCatalog::default(),
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
