use std::collections::BTreeSet;

use anyhow::Context as _;
use common::transaction::LeeTransaction;
use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message},
};
use lee::{AccountId, PublicTransaction, public_transaction::Message as LeeMessage};
use log::{error, warn};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_stake_core::{SequencerKey, SlashApproval};
use sequencer_storage_actor::{
    StorageActor, StorageActorTrait,
    protocol::{GetSlashRecordBytes, PutSlashRecordBytes},
};

use crate::{
    Result,
    error::Error,
    protocol::{Offence, Propose, Report, ReportedOffence},
};

/// On-disk form. The tag lets a later build migrate rather than fail to decode.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum PersistedRecord {
    V1 { found: BTreeSet<Offence> },
}

pub struct SlasherActor<S: StorageActorTrait = StorageActor> {
    storage_ref: ActorRef<S>,
    /// Signs this node's approval of a slash.
    approver: Ed25519Key,
    own_key: SequencerKey,
    /// Approvals a `Slash` must carry.
    threshold: usize,
    /// Never pruned: an offending key stays liable for good.
    found: BTreeSet<Offence>,
}

impl<S: StorageActorTrait> SlasherActor<S> {
    /// Restores the persisted record, empty if none was written.
    pub async fn load(storage_ref: ActorRef<S>, approver: Ed25519Key, threshold: usize) -> Self {
        let found = storage_ref
            .ask(GetSlashRecordBytes)
            .await
            .expect("Failed to read the slash record from store")
            .map_or_else(BTreeSet::new, |bytes| {
                let record = borsh::from_slice(&bytes)
                    .expect("persisted slash record should decode with this build");
                match record {
                    PersistedRecord::V1 { found } => found,
                }
            });
        let own_key = SequencerKey::new(approver.public_key().to_bytes())
            .expect("a Bedrock public key is a valid Ed25519 public key");

        Self {
            storage_ref,
            approver,
            own_key,
            threshold,
            found,
        }
    }

    /// Fatal on failure: the checkpoint is about to move past the offence.
    async fn persist(&self) -> Result<()> {
        let bytes = borsh::to_vec(&PersistedRecord::V1 {
            found: self.found.clone(),
        })
        .expect("slash record should serialize");
        self.storage_ref.ask(PutSlashRecordBytes { bytes }).await?;

        Ok(())
    }

    /// This node's approval of an offence, plus any collected from peers.
    fn approvals_for(&self, offence: &Offence) -> Vec<SlashApproval> {
        let message =
            sequencer_stake_core::slash_approval_message(offence.offender, offence.inscription);

        vec![SlashApproval {
            signer: self.own_key,
            signature: self.approver.sign_payload(&message).to_bytes().to_vec(),
        }]
    }
}

impl<S: StorageActorTrait> Actor for SlasherActor<S> {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }
}

impl<S: StorageActorTrait> Message<Report> for SlasherActor<S> {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Report { offences }: Report,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let mut added = false;
        for ReportedOffence {
            signer,
            inscription,
        } in offences
        {
            let Some(offender) = SequencerKey::new(signer) else {
                warn!(
                    "Undecodable inscription {} signed by an invalid key",
                    hex::encode(inscription)
                );
                continue;
            };
            error!(
                "Undecodable inscription {} written by {}",
                hex::encode(inscription),
                hex::encode(offender)
            );
            added |= self.found.insert(Offence {
                offender,
                inscription,
            });
        }

        if added {
            self.persist().await?;
        }

        Ok(())
    }
}

impl<S: StorageActorTrait> Message<Propose> for SlasherActor<S> {
    type Reply = Vec<LeeTransaction>;

    async fn handle(
        &mut self,
        Propose { config }: Propose,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Only an accredited key's approval counts.
        if !config.entries.contains_key(&self.own_key) {
            return Vec::new();
        }

        let mut proposed = Vec::new();
        // One burn takes the whole stake, so keep one offence per offender.
        let mut proposed_for = None;
        for offence in &self.found {
            if proposed_for == Some(offence.offender) {
                continue;
            }
            let Some(entry) = config.entries.get(&offence.offender) else {
                continue;
            };
            let approvals = self.approvals_for(offence);
            if approvals.len() < self.threshold {
                continue;
            }
            match build_slash_tx(entry.account_id, offence, approvals) {
                Ok(tx) => {
                    proposed.push(tx);
                    proposed_for = Some(offence.offender);
                }
                Err(err) => warn!("Failed to build a Slash tx: {err:#}"),
            }
        }

        proposed
    }
}

// No witness set: the approvals are the authorization.
pub fn build_slash_tx(
    ownership_id: AccountId,
    offence: &Offence,
    approvals: Vec<SlashApproval>,
) -> anyhow::Result<LeeTransaction> {
    let program_id: AccountId = programs::sequencer_stake().id().into();
    let message = LeeMessage::try_new(
        program_id,
        vec![
            ownership_id,
            system_accounts::stake_funds_account_id(&ownership_id),
            sequencer_stake_core::slash_sink_account_id(program_id),
            system_accounts::sequencer_stake_config_account_id(),
        ],
        vec![],
        sequencer_stake_core::Instruction::Slash {
            sequencer_key: offence.offender,
            inscription: offence.inscription,
            approvals,
        },
    )
    .context("Failed to build a Slash message")?;

    Ok(LeeTransaction::Public(PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )))
}

#[cfg(test)]
mod tests {
    use kameo::actor::Spawn as _;
    use sequencer_stake_core::{SequencerEntry, SequencerStakeConfig};
    use sequencer_storage_actor::mock::MockStorageActor;

    use super::*;

    const INSCRIPTION: [u8; 32] = [7; 32];

    type Slasher = ActorRef<SlasherActor<MockStorageActor>>;

    /// A storage actor that holds no record and accepts every write.
    fn storage() -> ActorRef<MockStorageActor> {
        let mut mock = MockStorageActor::new();
        mock.expect_handle_get_slash_record_bytes()
            .returning(|_, _| Ok(None));
        mock.expect_handle_put_slash_record_bytes()
            .returning(|_, _| Ok(()));
        MockStorageActor::spawn(mock)
    }

    fn offender_signing_key() -> Ed25519Key {
        Ed25519Key::from_bytes(&[3; 32])
    }

    fn offender() -> SequencerKey {
        SequencerKey::new(offender_signing_key().public_key().to_bytes()).expect("valid key")
    }

    fn approver_signing_key() -> Ed25519Key {
        Ed25519Key::from_bytes(&[5; 32])
    }

    fn approver() -> SequencerKey {
        SequencerKey::new(approver_signing_key().public_key().to_bytes()).expect("valid key")
    }

    async fn slasher(approver: Ed25519Key) -> Slasher {
        SlasherActor::spawn(
            SlasherActor::load(
                storage(),
                approver,
                sequencer_stake_core::SLASH_APPROVAL_THRESHOLD,
            )
            .await,
        )
    }

    fn signed_by_offender(inscription: [u8; 32]) -> ReportedOffence {
        ReportedOffence {
            signer: offender_signing_key().public_key().to_bytes(),
            inscription,
        }
    }

    async fn report(slasher: &Slasher, offences: Vec<ReportedOffence>) {
        slasher
            .ask(Report { offences })
            .await
            .expect("the report should persist");
    }

    /// A config accrediting every key with a stake to burn.
    fn config_staking(keys: &[SequencerKey]) -> SequencerStakeConfig {
        SequencerStakeConfig {
            minimum_sequencer_stake: 1,
            entries: keys
                .iter()
                .map(|key| {
                    (
                        *key,
                        SequencerEntry {
                            account_id: AccountId::new([8; 32]),
                            total_staked: 1,
                            total_pending_unstake: 0,
                        },
                    )
                })
                .collect(),
        }
    }

    async fn propose(slasher: &Slasher, config: SequencerStakeConfig) -> Vec<LeeTransaction> {
        slasher
            .ask(Propose { config })
            .await
            .expect("the proposal should reply")
    }

    #[tokio::test]
    async fn a_reported_offence_becomes_a_slash_candidate() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        assert_eq!(
            propose(&slasher, config_staking(&[approver(), offender()]))
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn nothing_is_proposed_for_an_empty_report() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, Vec::new()).await;

        assert!(
            propose(&slasher, config_staking(&[approver(), offender()]))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn one_offender_yields_one_slash_however_many_offences() {
        let slasher = slasher(approver_signing_key()).await;
        report(
            &slasher,
            vec![signed_by_offender(INSCRIPTION), signed_by_offender([9; 32])],
        )
        .await;

        // The first burn takes everything, so the second would only abort.
        assert_eq!(
            propose(&slasher, config_staking(&[approver(), offender()]))
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_unaccredited_approver_proposes_nothing() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        assert!(
            propose(&slasher, config_staking(&[offender()]))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_offender_with_nothing_left_to_burn_is_no_candidate() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        assert!(
            propose(&slasher, config_staking(&[approver()]))
                .await
                .is_empty()
        );
    }
}
