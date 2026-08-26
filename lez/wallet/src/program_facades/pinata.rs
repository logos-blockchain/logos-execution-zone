use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::{MembershipProof, SharedSecretKey};

use crate::{ExecutionFailureKind, Identity, WalletCore};

pub struct Pinata<'wallet>(pub &'wallet WalletCore);

impl Pinata<'_> {
    pub async fn claim(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction_data =
            Program::serialize_instruction(solution).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    Identity::PublicNoSign(pinata_account_id).in_namespace(programs::pinata().id()),
                    Identity::PublicNoSign(winner_account_id)
                        .in_namespace(programs::authenticated_transfer().id()),
                ],
                instruction_data,
                programs::pinata().id(),
            )
            .await
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
                    Identity::Public(pinata_account_id).in_namespace(programs::pinata().id()),
                    self.0
                        .resolve_private_account(winner_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                        .in_namespace(programs::authenticated_transfer().id()),
                ],
                lee::program::Program::serialize_instruction(solution).unwrap(),
                &programs::pinata().into(),
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
