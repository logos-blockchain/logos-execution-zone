use common::HashType;
use lee::{
    AccountId, error::LeeError, privacy_preserving_transaction::circuit::ProgramCatalog,
    program::Program,
};
use lee_core::SharedSecretKey;
use sequencer_stake_core::{
    Message, SequencerKey, StakeRecord, UNSTAKE_REQUEST_WINDOW, stake_funds_seed,
};

use crate::{AccountIdentity, CastDelivery, ExecutionFailureKind, WalletCore};

pub struct SequencerStake<'wallet>(pub &'wallet WalletCore);

impl SequencerStake<'_> {
    // The signing ownership account's stake actor is the root, and `funding`'s native balance pays,
    // publicly or privately: the ownership transition requests exactly that transfer into the
    // funds.
    pub async fn send_stake(
        &self,
        ownership: AccountIdentity,
        funding: AccountIdentity,
        sequencer_key: SequencerKey,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let program = programs::sequencer_stake_account_id();
        let has_record = !super::actor_state(self.0, &ownership, program)
            .await?
            .is_empty();
        let funds = AccountIdentity::PublicPda {
            program,
            seed: stake_funds_seed(&ownership.account_id()),
        };
        let message = Program::serialize_message(Message::Stake {
            sequencer_key,
            amount,
            has_record,
            funding: funding.account_id(),
        })
        .expect("Message should serialize");
        // A private owner's fee payouts are published under its recovery binding.
        let casts = if ownership.is_private() {
            self.0.cast_destination(ownership.clone().balance())?.1
        } else {
            CastDelivery::default()
        };
        let accounts = vec![
            ownership.select_program_actor_state(program),
            funds.balance(),
            funding.balance(),
            AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id())
                .select_program_actor_state(program),
        ];
        self.0
            .send_tx(
                accounts,
                0,
                message,
                &ProgramCatalog::from([(program, programs::sequencer_stake())]),
                None,
                casts,
            )
            .await
    }

    pub async fn send_unstake_request(
        &self,
        ownership: AccountId,
        amount: u128,
        destination: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let payable = self
            .0
            .get_account_public(destination)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
            .is_some()
            || self
                .0
                .get_recovery_binding(destination)
                .await
                .map_err(ExecutionFailureKind::SequencerError)?
                .is_some();
        if !payable {
            return Err(ExecutionFailureKind::TransactionBuildError(
                LeeError::InvalidInput(format!(
                    "FinalizeUnstake cannot pay {destination}: it is neither a public account nor \
                     a bound private address"
                )),
            ));
        }
        let program = programs::sequencer_stake_account_id();
        let owner = AccountIdentity::Public(ownership);
        let record = StakeRecord::from_bytes(&super::actor_state(self.0, &owner, program).await?)
            .ok_or(ExecutionFailureKind::AccountDataError(ownership))?;
        let requested_at = self
            .0
            .get_last_block_id()
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
            .saturating_add(UNSTAKE_REQUEST_WINDOW);
        let message = Program::serialize_message(Message::UnstakeRequest {
            sequencer_key: record.sequencer_key,
            amount,
            destination,
            requested_at,
        })
        .expect("Message should serialize");
        let accounts = vec![
            owner.select_program_actor_state(program),
            AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id())
                .select_program_actor_state(program),
        ];
        self.0.send_pub_tx(accounts, 0, message).await
    }
}
