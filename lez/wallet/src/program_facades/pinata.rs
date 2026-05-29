use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::{MembershipProof, SharedSecretKey};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct Pinata<'wallet>(pub &'wallet WalletCore);

impl Pinata<'_> {
    pub async fn claim(
        &self,
        pinata_account_id: AccountId,
        winner_account_id: AccountId,
        solution: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::pinata();
        let instruction = solution;
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(pinata_account_id),
                    AccountIdentity::PublicNoSign(winner_account_id),
                ],
                instruction_data,
                &program.into(),
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
                    AccountIdentity::Public(pinata_account_id),
                    self.0
                        .resolve_private_account(winner_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                lee::program::Program::serialize_instruction(solution).unwrap(),
                &lee::program::Program::pinata().into(),
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
