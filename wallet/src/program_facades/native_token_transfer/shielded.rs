use common::HashType;
use nssa::AccountId;
use nssa_core::{NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{ExecutionFailureKind, PrivacyPreservingAccount};

impl NativeTokenTransfer<'_> {
    pub async fn send_shielded_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    PrivacyPreservingAccount::Public(from),
                    PrivacyPreservingAccount::PrivateOwned(to),
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

    pub async fn send_shielded_transfer_to_outer_account(
        &self,
        from: AccountId,
        to_npk: NullifierPublicKey,
        to_vpk: ViewingPublicKey,
        balance_to_move: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    PrivacyPreservingAccount::Public(from),
                    PrivacyPreservingAccount::PrivateForeign {
                        npk: to_npk,
                        vpk: to_vpk,
                    },
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
