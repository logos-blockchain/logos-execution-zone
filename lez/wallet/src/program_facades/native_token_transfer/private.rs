use std::vec;

use common::HashType;
use lee::AccountId;
use lee_core::{Identifier, NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{ExecutionFailureKind, Identity};

impl NativeTokenTransfer<'_> {
    pub async fn send_private_transfer_to_outer_account(
        &self,
        from: AccountId,
        to_npk: NullifierPublicKey,
        to_vpk: ViewingPublicKey,
        to_identifier: Identifier,
        balance_to_move: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    self.0
                        .resolve_private_account(from)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                        .in_namespace(programs::authenticated_transfer().id()),
                    Identity::PrivateForeign {
                        npk: to_npk,
                        vpk: to_vpk,
                        identifier: to_identifier,
                    }
                    .in_namespace(programs::authenticated_transfer().id()),
                ],
                instruction_data,
                &program.into(),
                tx_pre_check,
            )
            .await
            .map(|(resp, secrets)| {
                let mut secrets_iter = secrets.into_iter();
                let first = secrets_iter.next().expect("expected sender's secret");
                let second = secrets_iter.next().expect("expected receiver's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_private_transfer_to_owned_account(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        let from_account = self
            .0
            .resolve_private_account(from)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let to_account = self
            .0
            .resolve_private_account(to)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from_account.in_namespace(programs::authenticated_transfer().id()),
                    to_account.in_namespace(programs::authenticated_transfer().id()),
                ],
                instruction_data,
                &program.into(),
                tx_pre_check,
            )
            .await
            .map(|(resp, secrets)| {
                let mut secrets_iter = secrets.into_iter();
                let first = secrets_iter.next().expect("expected sender's secret");
                let second = secrets_iter.next().expect("expected receiver's secret");
                (resp, [first, second])
            })
    }
}
