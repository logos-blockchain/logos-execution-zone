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
        let message = bridge_core::Message::Withdraw {
            amount,
            bedrock_account_pk,
        };
        let message = Program::serialize_message(message).expect("Message should serialize");
        // The sender's signature authorizes the sender's own actor under the bridge program.
        let root = AccountIdentity::Public(sender_account_id)
            .select_program_actor_state(programs::bridge_account_id());

        self.0
            .send_pub_tx(
                vec![
                    root,
                    AccountIdentity::Public(sender_account_id).balance(),
                    AccountIdentity::PublicNoSign(bridge_account_id).balance(),
                ],
                0,
                message,
            )
            .await
    }
}
