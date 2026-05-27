use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::HashType;
use nssa::{AccountId, program::Program};

use super::NativeTokenTransfer;
use crate::{
    AccountIdentity, ExecutionFailureKind, cli::CliAccountMention,
    program_facades::native_token_transfer::auth_transfer_preparation,
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
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        let from_identity =
            from_mention
                .key_path()
                .map_or(AccountIdentity::Public(from), |key_path| {
                    AccountIdentity::PublicKeycard {
                        account_id: from,
                        key_path: key_path.to_owned(),
                    }
                });

        let to_identity = to_mention
            .key_path()
            .map_or(AccountIdentity::Public(to), |key_path| {
                AccountIdentity::PublicKeycard {
                    account_id: to,
                    key_path: key_path.to_owned(),
                }
            });

        self.0
            .send_pub_tx_with_pre_check(
                vec![from_identity, to_identity],
                instruction_data,
                &program.into(),
                tx_pre_check,
            )
            .await
    }

    pub async fn register_account(
        &self,
        from: AccountId,
        account_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let from_identity =
            account_mention
                .key_path()
                .map_or(AccountIdentity::Public(from), |key_path| {
                    AccountIdentity::PublicKeycard {
                        account_id: from,
                        key_path: key_path.to_owned(),
                    }
                });

        let program = Program::authenticated_transfer_program();
        let instruction_data = Program::serialize_instruction(AuthTransferInstruction::Initialize)?;

        self.0
            .send_pub_tx(vec![from_identity], instruction_data, &program.into())
            .await
    }
}
