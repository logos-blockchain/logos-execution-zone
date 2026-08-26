use common::HashType;
use lee::AccountId;
use lee_core::{Identifier, NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{ExecutionFailureKind, Identity};

impl NativeTokenTransfer<'_> {
    pub async fn send_shielded_transfer(
        &self,
        from: Identity,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from.in_namespace(program.id()),
                    self.0
                        .resolve_private_account(to)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                        .in_namespace(program.id()),
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
        from: Identity,
        to_npk: NullifierPublicKey,
        to_vpk: ViewingPublicKey,
        to_identifier: Identifier,
        balance_to_move: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from.in_namespace(program.id()),
                    Identity::PrivateForeign {
                        npk: to_npk,
                        vpk: to_vpk,
                        identifier: to_identifier,
                    }
                    .in_namespace(program.id()),
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
