use std::vec;

use common::HashType;
use nssa::{AccountId, program::Program};
use nssa_core::{NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{ExecutionFailureKind, PrivacyPreservingAccount};

impl NativeTokenTransfer<'_> {
    pub async fn register_account_private(
        &self,
        from: AccountId,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction: u128 = 0;

        self.0
            .send_privacy_preserving_tx(
                vec![PrivacyPreservingAccount::PrivateOwned(from)],
                Program::serialize_instruction(instruction).unwrap(),
                &Program::authenticated_transfer_program().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut secrets_iter = secrets.into_iter();
                let first = secrets_iter.next().expect("expected sender's secret");
                (resp, first)
            })
    }

    pub async fn send_private_transfer_to_outer_account(
        &self,
        from: AccountId,
        to_npk: NullifierPublicKey,
        to_vpk: ViewingPublicKey,
        balance_to_move: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    PrivacyPreservingAccount::PrivateOwned(from),
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

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    PrivacyPreservingAccount::PrivateOwned(from),
                    PrivacyPreservingAccount::PrivateOwned(to),
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
