use common::HashType;
use nssa::AccountId;
use nssa_core::{Identifier, NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};

use super::{NativeTokenTransfer, auth_transfer_preparation};
use crate::{AccountIdentity, ExecutionFailureKind, cli::CliAccountMention};

impl NativeTokenTransfer<'_> {
    pub async fn send_shielded_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
        from_mention: &CliAccountMention,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let from_identity =
            from_mention
                .key_path()
                .map_or(AccountIdentity::Public(from), |key_path| {
                    AccountIdentity::PublicKeycard {
                        account_id: from,
                        key_path: key_path.to_owned(),
                    }
                });

        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from_identity,
                    self.0
                        .resolve_private_account(to)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
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
        to_identifier: Identifier,
        balance_to_move: u128,
        from_mention: &CliAccountMention,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let from_identity =
            from_mention
                .key_path()
                .map_or(AccountIdentity::Public(from), |key_path| {
                    AccountIdentity::PublicKeycard {
                        account_id: from,
                        key_path: key_path.to_owned(),
                    }
                });

        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);
        self.0
            .send_privacy_preserving_tx_with_pre_check(
                vec![
                    from_identity,
                    AccountIdentity::PrivateForeign {
                        npk: to_npk,
                        vpk: to_vpk,
                        identifier: to_identifier,
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
