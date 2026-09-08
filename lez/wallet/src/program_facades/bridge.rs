use common::HashType;
use lee::{AccountId, program::Program};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct Bridge<'wallet>(pub &'wallet WalletCore);

impl Bridge<'_> {
    pub async fn send_withdraw(
        &self,
        sender_account_id: AccountId,
        amount: u64,
        bedrock_account_pk: [u8; 32],
    ) -> Result<HashType, ExecutionFailureKind> {
        let bridge_account_id = system_accounts::bridge_account_id();
        let instruction = bridge_core::Instruction::Withdraw {
            amount,
            bedrock_account_pk,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(sender_account_id).balance_only(),
                    AccountIdentity::PublicNoSign(bridge_account_id).balance_only(),
                ],
                instruction_data,
                programs::bridge().id().into(),
            )
            .await
    }
}
