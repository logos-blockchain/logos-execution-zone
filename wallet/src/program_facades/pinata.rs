use common::{HashType, transaction::NSSATransaction};
use nssa::AccountId;
use nssa_core::{MembershipProof, SharedSecretKey};
use sequencer_service_rpc::RpcClient as _;

use crate::{ExecutionFailureKind, PrivacyPreservingAccount, WalletCore};

pub struct Pinata<'wallet>(pub &'wallet WalletCore);

impl Pinata<'_> {
    pub async fn claim(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let account_ids = vec![pinata_account_id, winner_account_id];
        let program_id = nssa::program::Program::pinata().id();
        let message =
            nssa::public_transaction::Message::try_new(program_id, account_ids, vec![], solution)
                .unwrap();

        let witness_set = nssa::public_transaction::WitnessSet::for_message(&message, &[]);
        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    /// Claim a pinata reward using a privacy-preserving transaction for an already-initialized
    /// owned private account.
    ///
    /// The `winner_proof` parameter is accepted for API completeness; the wallet currently fetches
    /// the membership proof automatically from the chain.
    pub async fn claim_private_owned_account_already_initialized(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
        _winner_proof: MembershipProof,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.claim_private_owned_account(pinata_account_id, winner_account_id, solution)
            .await
    }

    pub async fn claim_private_owned_account(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.0
            .send_privacy_preserving_tx(
                vec![
                    PrivacyPreservingAccount::Public(pinata_account_id),
                    PrivacyPreservingAccount::PrivateOwned(winner_account_id),
                ],
                nssa::program::Program::serialize_instruction(solution).unwrap(),
                &nssa::program::Program::pinata().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected recipient's secret");
                (resp, first)
            })
    }
}
