use common::{HashType, transaction::NSSATransaction};
use sequencer_service_rpc::RpcClient as _;
use key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder;
use nssa::{AccountId, privacy_preserving_transaction::circuit};
use nssa_core::{MembershipProof, SharedSecretKey, account::AccountWithMetadata};

use crate::{
    ExecutionFailureKind, WalletCore, helperfunctions::produce_random_nonces,
    transaction_utils::AccountPreparedData,
};

impl WalletCore {
    pub async fn claim_pinata(
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

        Ok(self.sequencer_client.send_transaction(NSSATransaction::Public(tx).into()).await?)
    }

    pub async fn claim_pinata_private_owned_account_already_initialized(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
        winner_proof: MembershipProof,
    ) -> Result<(HashType, [SharedSecretKey; 1]), ExecutionFailureKind> {
        let AccountPreparedData {
            nsk: winner_nsk,
            npk: winner_npk,
            vpk: winner_vpk,
            auth_acc: winner_pre,
            proof: _,
        } = self
            .private_acc_preparation(winner_account_id, true, false)
            .await?;

        let pinata_acc = self.get_account_public(pinata_account_id).await.unwrap();

        let program = nssa::program::Program::pinata();

        let pinata_pre = AccountWithMetadata::new(pinata_acc.clone(), false, pinata_account_id);

        let eph_holder_winner = EphemeralKeyHolder::new(&winner_npk);
        let shared_secret_winner = eph_holder_winner.calculate_shared_secret_sender(&winner_vpk);

        let (output, proof) = circuit::execute_and_prove(
            &[pinata_pre, winner_pre],
            &nssa::program::Program::serialize_instruction(solution).unwrap(),
            &[0, 1],
            &produce_random_nonces(1),
            &[(winner_npk.clone(), shared_secret_winner.clone())],
            &[(winner_nsk.unwrap())],
            &[winner_proof],
            &program.into(),
        )
        .unwrap();

        let message =
            nssa::privacy_preserving_transaction::message::Message::try_from_circuit_output(
                vec![pinata_account_id],
                vec![],
                vec![(
                    winner_npk.clone(),
                    winner_vpk.clone(),
                    eph_holder_winner.generate_ephemeral_public_key(),
                )],
                output,
            )
            .unwrap();

        let witness_set =
            nssa::privacy_preserving_transaction::witness_set::WitnessSet::for_message(
                &message,
                proof,
                &[],
            );
        let tx = nssa::privacy_preserving_transaction::PrivacyPreservingTransaction::new(
            message,
            witness_set,
        );

        Ok((
            self.sequencer_client.send_transaction(NSSATransaction::PrivacyPreserving(tx).into()).await?,
            [shared_secret_winner],
        ))
    }

    pub async fn claim_pinata_private_owned_account_not_initialized(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
    ) -> Result<(HashType, [SharedSecretKey; 1]), ExecutionFailureKind> {
        let AccountPreparedData {
            nsk: _,
            npk: winner_npk,
            vpk: winner_vpk,
            auth_acc: winner_pre,
            proof: _,
        } = self
            .private_acc_preparation(winner_account_id, false, false)
            .await?;

        let pinata_acc = self.get_account_public(pinata_account_id).await.unwrap();

        let program = nssa::program::Program::pinata();

        let pinata_pre = AccountWithMetadata::new(pinata_acc.clone(), false, pinata_account_id);

        let eph_holder_winner = EphemeralKeyHolder::new(&winner_npk);
        let shared_secret_winner = eph_holder_winner.calculate_shared_secret_sender(&winner_vpk);

        let (output, proof) = circuit::execute_and_prove(
            &[pinata_pre, winner_pre],
            &nssa::program::Program::serialize_instruction(solution).unwrap(),
            &[0, 2],
            &produce_random_nonces(1),
            &[(winner_npk.clone(), shared_secret_winner.clone())],
            &[],
            &[],
            &program.into(),
        )
        .unwrap();

        let message =
            nssa::privacy_preserving_transaction::message::Message::try_from_circuit_output(
                vec![pinata_account_id],
                vec![],
                vec![(
                    winner_npk.clone(),
                    winner_vpk.clone(),
                    eph_holder_winner.generate_ephemeral_public_key(),
                )],
                output,
            )
            .unwrap();

        let witness_set =
            nssa::privacy_preserving_transaction::witness_set::WitnessSet::for_message(
                &message,
                proof,
                &[],
            );
        let tx = nssa::privacy_preserving_transaction::PrivacyPreservingTransaction::new(
            message,
            witness_set,
        );

        Ok((
            self.sequencer_client.send_transaction(NSSATransaction::PrivacyPreserving(tx).into()).await?,
            [shared_secret_winner],
        ))
    }
}
