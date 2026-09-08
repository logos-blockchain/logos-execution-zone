use common::HashType;
use lee::AccountId;
use lee_core::{
    Identifier, NullifierPublicKey, PrivateAccountKind, SharedSecretKey,
    encryption::ViewingPublicKey,
};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{AccountIdentity, ExecutionFailureKind};

impl NativeTokenTransfer<'_> {
    pub async fn send_shielded_transfer(
        &self,
        from: AccountIdentity,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from.balance_only(),
                    self.0
                        .resolve_private_account(to)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                        .balance_only(),
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
        from: AccountIdentity,
        to_npk: NullifierPublicKey,
        to_vpk: ViewingPublicKey,
        to_identifier: Identifier,
        balance_to_move: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from.balance_only(),
                    AccountIdentity::PrivateForeign {
                        npk: to_npk,
                        vpk: to_vpk,
                        kind: PrivateAccountKind::Regular(to_identifier),
                    }
                    .balance_only(),
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
