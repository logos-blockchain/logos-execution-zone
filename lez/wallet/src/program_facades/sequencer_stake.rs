use common::HashType;
use lee::{privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::SharedSecretKey;
use sequencer_stake_core::{Message, SequencerKey};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct SequencerStake<'wallet>(pub &'wallet WalletCore);

impl SequencerStake<'_> {
    // The signing ownership account's stake actor is the root, and `funding`'s native balance pays,
    // publicly or privately: the ownership turn requests exactly that transfer into the funds.
    pub async fn send_stake(
        &self,
        ownership: AccountIdentity,
        funding: AccountIdentity,
        sequencer_key: SequencerKey,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let program = programs::sequencer_stake_account_id();
        let has_record = !super::shard(self.0, &ownership, program).await?.is_empty();
        let funds = system_accounts::stake_funds_account_id(&ownership.account_id());
        let message = Program::serialize_message(Message::Stake {
            sequencer_key,
            amount,
            has_record,
            funding: funding.account_id(),
        })
        .expect("Message should serialize");
        let accounts = vec![
            ownership.select_program_shard(program),
            AccountIdentity::PublicNoSign(funds).balance(),
            funding.balance(),
            AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id())
                .select_program_shard(program),
        ];
        self.0
            .send_tx(
                accounts,
                0,
                message,
                &ProgramCatalog::from([(program, programs::sequencer_stake())]),
            )
            .await
    }
}
