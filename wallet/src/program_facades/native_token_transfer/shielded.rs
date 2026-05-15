use common::HashType;
use nssa::AccountId;
use nssa_core::{Identifier, NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{ExecutionFailureKind, PrivacyPreservingAccount, cli::CliAccountMention};

impl NativeTokenTransfer<'_> {
    pub async fn send_shielded_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
        from_mention: &CliAccountMention,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        let key_path = from_mention.key_path().map(str::to_owned);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    PrivacyPreservingAccount::Public(from),
                    self.0
                        .resolve_private_account(to)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &program.into(),
                tx_pre_check,
                &key_path,
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
        to_identifier: Identifier,
        balance_to_move: u128,
        from_mention: &CliAccountMention,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        let key_path = from_mention.key_path().map(str::to_owned);

        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    PrivacyPreservingAccount::Public(from),
                    PrivacyPreservingAccount::PrivateForeign {
                        npk: to_npk,
                        vpk: to_vpk,
                        identifier: to_identifier,
                    },
                ],
                instruction_data,
                &program.into(),
                tx_pre_check,
                &key_path,
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
