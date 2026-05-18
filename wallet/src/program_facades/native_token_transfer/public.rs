use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::HashType;
use nssa::{AccountId, program::Program};

use super::NativeTokenTransfer;
use crate::{
    ExecutionFailureKind, cli::CliAccountMention, signing::SigningGroups,
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
        from_mention: &CliAccountMention,
        to_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let mut groups = SigningGroups::new();
        groups
            .add_sender(from_mention, from, self.0)
            .and_then(|()| groups.add_recipient(to_mention, to, self.0))
            .map_err(ExecutionFailureKind::from_anyhow)?;

        self.0
            .send_public_tx(
                &Program::authenticated_transfer_program(),
                vec![from, to],
                AuthTransferInstruction::Transfer {
                    amount: balance_to_move,
                },
                groups,
            )
            .await
    }

    pub async fn register_account(
        &self,
        from: AccountId,
        account_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let mut groups = SigningGroups::new();
        groups
            .add_sender(account_mention, from, self.0)
            .map_err(ExecutionFailureKind::from_anyhow)?;

        self.0
            .send_public_tx(
                &Program::authenticated_transfer_program(),
                vec![from],
                AuthTransferInstruction::Initialize,
                groups,
            )
            .await
    }
}
