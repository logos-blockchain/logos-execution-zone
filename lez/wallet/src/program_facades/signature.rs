//! Manual key rotation: the signature program's guest, run privately, replaces the keys of owned
//! public accounts without their signatures.

use anyhow::Context as _;
use common::HashType;
use lee::{
    AccountId, Actor, error::LeeError, privacy_preserving_transaction::circuit::ProgramCatalog,
    signature::key_state_with_counter,
};
use lee_core::{
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader},
    signing_key::{KeyType, signature_program_id},
};
use program_loader_core::LoaderActorState as _;
use signature_core::{AccountRotation, Message};

use crate::{
    AccountIdentity, AsyncDelivery, ExecutionFailureKind, WalletCore, WalletSequencerClient,
    rotation,
};

pub struct Signature<'wallet, C: WalletSequencerClient>(pub &'wallet WalletCore<C>);

impl<C: WalletSequencerClient> Signature<'_, C> {
    /// Rotates the keys of `accounts`, public accounts this wallet holds, in one privacy
    /// transaction. `fee_payer`, a private account this wallet holds,
    /// pays the fee and runs the guest, so the accounts' secrets stay in the proof.
    pub async fn manual_rotation(
        &self,
        accounts: &[AccountId],
        fee_payer: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        if accounts.is_empty() {
            return Err(invalid_input(
                "A manual rotation names at least one account",
            ));
        }
        if self
            .0
            .storage()
            .key_chain()
            .managed_private_account(fee_payer)
            .is_none()
        {
            return Err(invalid_input(&format!(
                "The fee payer {fee_payer} must be a private account this wallet holds"
            )));
        }
        self.ensure_current_guest().await?;

        let mut rotations = Vec::with_capacity(accounts.len());
        for &account in accounts {
            let secret = self
                .0
                .storage()
                .key_chain()
                .pub_account_secret(account)
                .cloned()
                .ok_or_else(|| {
                    invalid_input(&format!(
                        "This wallet holds no secret for {account}: it cannot rotate its key \
                         manually"
                    ))
                })?;
            let (nonce, stored) = self
                .0
                .stored_key(account)
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            let counter = rotation::next_counter(&secret, stored, nonce)
                .map_err(|error| invalid_input(&format!("{account}: {error}")))?;
            rotations.push(AccountRotation {
                secret: *secret.value(),
                account,
                next: key_state_with_counter(&secret, KeyType::Schnorr, nonce, counter),
            });
        }

        let signature = signature_program_id();
        let message = borsh::to_vec(&Message::ManualRotation { rotations })
            .expect("a manual rotation serializes");
        let mentions = std::iter::once(
            AccountIdentity::PrivateOwned(fee_payer).select_program_actor_state(signature),
        )
        .chain(accounts.iter().map(|&account| {
            AccountIdentity::PublicNoSign(account).select_program_actor_state(signature)
        }))
        .collect();
        let (tx_hash, _) = self
            .0
            .send_tx_with_pre_check(
                mentions,
                0,
                message,
                &ProgramCatalog::from([(signature, programs::signature_program())]),
                None,
                AsyncDelivery::default(),
                Some(fee_payer),
                |_| Ok(()),
            )
            .await?;
        Ok(tx_hash)
    }

    /// Refuses before proving when the guest this wallet carries is not the one deployed: the
    /// sequencer would refuse its proof.
    async fn ensure_current_guest(&self) -> Result<(), ExecutionFailureKind> {
        let header = self
            .0
            .get_account_view(Actor::new(
                signature_program_id(),
                PROGRAM_LOADER_ACCOUNT_ID,
            ))
            .await
            .context("Failed to read the signature program's header")
            .map_err(ExecutionFailureKind::SequencerError)?
            .and_then(|account| {
                ProgramHeader::from_loader_actor_state(
                    account.data.actor_state(PROGRAM_LOADER_ACCOUNT_ID),
                )
            })
            .ok_or_else(|| invalid_input("No signature program is deployed on this chain"))?;
        let carried = programs::signature_program().id();
        if header.image_id != carried {
            return Err(invalid_input(
                "This wallet's signature guest is out of date: the chain runs another version, \
                 so its proof would be refused. Update the wallet.",
            ));
        }
        Ok(())
    }
}

fn invalid_input(message: &str) -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(LeeError::InvalidInput(message.to_owned()))
}
