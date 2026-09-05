use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context as _;
use common::transaction::LeeTransaction;
use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message},
};
use lee::{AccountId, PublicTransaction, public_transaction::Message as LeeMessage};
use log::{debug, error, warn};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_stake_core::{
    SequencerKey, SequencerStakeConfig, SlashApproval, slash_approval_threshold,
};
use sequencer_storage_actor::{
    StorageActor, StorageActorTrait,
    protocol::{GetSlashRecordBytes, PutSlashRecordBytes},
};
use tokio::sync::mpsc;

use crate::{
    Result,
    error::Error,
    protocol::{Approval, Offence, Propose, Report, ReportedOffence, SetApprovalPublisher},
};

/// Cap on signatures kept per offence, the only bound before a config arrives.
const MAX_APPROVERS_PER_OFFENCE: usize = 64;

/// On-disk form, tagged so a later build can migrate instead of failing to decode.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum PersistedRecord {
    V2 {
        found: BTreeSet<Offence>,
        approvals: Approvals,
    },
}

/// Peers' signatures, by offence and then by signer.
type Approvals = BTreeMap<Offence, BTreeMap<SequencerKey, [u8; 64]>>;

pub struct SlasherActor<S: StorageActorTrait = StorageActor> {
    storage_ref: ActorRef<S>,
    /// Signs this node's approval of a slash.
    approver: Ed25519Key,
    own_key: SequencerKey,
    /// Never pruned: an offending key stays liable for good.
    found: BTreeSet<Offence>,
    /// Peer approvals, for offences in `found` only.
    approvals: Approvals,
    /// The last config `Propose` saw, used to screen inbound approvals.
    config: Option<SequencerStakeConfig>,
    /// Where own approvals go. `None` until gossip is up, or when it is off.
    publisher: Option<mpsc::Sender<Approval>>,
}

impl<S: StorageActorTrait> SlasherActor<S> {
    /// Restores the persisted record, empty if none was written.
    pub async fn load(storage_ref: ActorRef<S>, approver: Ed25519Key) -> Self {
        let (found, approvals) = storage_ref
            .ask(GetSlashRecordBytes)
            .await
            .expect("Failed to read the slash record from store")
            .map_or_else(Default::default, |bytes| {
                let PersistedRecord::V2 { found, approvals } = borsh::from_slice(&bytes)
                    .expect("persisted slash record should decode with this build");
                (found, approvals)
            });
        let own_key = SequencerKey::new(approver.public_key().to_bytes())
            .expect("a Bedrock public key is a valid Ed25519 public key");

        Self {
            storage_ref,
            approver,
            own_key,
            found,
            approvals,
            config: None,
            publisher: None,
        }
    }

    /// Fatal on failure: the checkpoint is about to move past the offence.
    async fn persist(&self) -> Result<()> {
        let bytes = borsh::to_vec(&PersistedRecord::V2 {
            found: self.found.clone(),
            approvals: self.approvals.clone(),
        })
        .expect("slash record should serialize");
        self.storage_ref.ask(PutSlashRecordBytes { bytes }).await?;

        Ok(())
    }

    fn own_approval(&self, offence: Offence) -> Approval {
        let message =
            sequencer_stake_core::slash_approval_message(offence.offender, offence.inscription);

        Approval {
            offence,
            signer: self.own_key,
            signature: self.approver.sign_payload(&message).to_bytes(),
        }
    }

    /// This node's approval plus the accredited peer ones. Signers are
    /// distinct: own key never enters `approvals`.
    fn approvals_for(
        &self,
        offence: &Offence,
        config: &SequencerStakeConfig,
    ) -> Vec<SlashApproval> {
        let approval = |signer, signature: &[u8; 64]| SlashApproval {
            signer,
            signature: signature.to_vec(),
        };
        let own = self.own_approval(*offence);
        let collected = self
            .approvals
            .get(offence)
            .into_iter()
            .flatten()
            .filter(|(signer, _)| config.is_accredited_committee_member(signer))
            .map(|(signer, signature)| approval(*signer, signature));

        std::iter::once(approval(own.signer, &own.signature))
            .chain(collected)
            .collect()
    }

    /// Best effort: without gossip this node only ever has its own approval.
    fn publish(&self, approval: Approval) {
        if let Some(publisher) = &self.publisher
            && publisher.try_send(approval).is_err()
        {
            debug!("Dropped an outbound slash approval");
        }
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
        let mut added = Vec::new();
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
            let offence = Offence {
                offender,
                inscription,
            };
            if self.found.insert(offence) {
                added.push(offence);
            }
        }

        if added.is_empty() {
            return Ok(());
        }
        self.persist().await?;
        for offence in added {
            self.publish(self.own_approval(offence));
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
        // Kept so the next inbound approval can be screened on arrival.
        self.config = Some(config.clone());

        // Only an accredited key's approval counts.
        if !config.is_accredited_committee_member(&self.own_key) {
            return Vec::new();
        }

        let threshold = slash_approval_threshold(config.accredited_committee_members_count());
        let mut proposed = Vec::new();
        // One burn takes the whole stake, so keep one offence per offender.
        let mut proposed_for = BTreeSet::new();
        for offence in &self.found {
            if proposed_for.contains(&offence.offender) {
                continue;
            }
            let Some(entry) = config.entries.get(&offence.offender) else {
                continue;
            };
            let approvals = self.approvals_for(offence, &config);
            if approvals.len() < threshold {
                continue;
            }
            match build_slash_tx(entry.account_id, offence, approvals) {
                Ok(tx) => {
                    proposed.push(tx);
                    proposed_for.insert(offence.offender);
                }
                Err(err) => warn!("Failed to build a Slash tx: {err:#}"),
            }
        }

        proposed
    }
}

impl<S: StorageActorTrait> Message<Approval> for SlasherActor<S> {
    type Reply = ();

    async fn handle(&mut self, msg: Approval, _ctx: &mut Context<Self, Self::Reply>) {
        if msg.signer == self.own_key {
            return;
        }
        // A peer is trusted for its signature, never for the offence itself.
        if !self.found.contains(&msg.offence) || !msg.verify() {
            return;
        }
        // Screened against the last config seen, so junk keys take no slot.
        if let Some(config) = &self.config
            && !config.is_accredited_committee_member(&msg.signer)
        {
            return;
        }
        let Approval {
            offence,
            signer,
            signature,
        } = msg;

        let signers = self.approvals.entry(offence).or_default();
        if signers.len() >= MAX_APPROVERS_PER_OFFENCE && !signers.contains_key(&signer) {
            return;
        }
        if signers.insert(signer, signature).is_some() {
            return;
        }

        if let Err(err) = self.persist().await {
            warn!("Failed to persist a peer's slash approval: {err}");
        }
        // The peer may have dropped our earlier approval, so send a fresh one.
        self.publish(self.own_approval(offence));
    }
}

impl<S: StorageActorTrait> Message<SetApprovalPublisher> for SlasherActor<S> {
    type Reply = ();

    async fn handle(
        &mut self,
        SetApprovalPublisher(publisher): SetApprovalPublisher,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        self.publisher = Some(publisher);
        // Gossip comes up late, so restored offences were never announced.
        for offence in &self.found {
            self.publish(self.own_approval(*offence));
        }
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
    const PEER_SECRET: [u8; 32] = [6; 32];
    const SECOND_PEER_SECRET: [u8; 32] = [2; 32];

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

    fn second_offender_signing_key() -> Ed25519Key {
        Ed25519Key::from_bytes(&[4; 32])
    }

    fn second_offender() -> SequencerKey {
        SequencerKey::new(second_offender_signing_key().public_key().to_bytes()).expect("valid key")
    }

    fn approver_signing_key() -> Ed25519Key {
        Ed25519Key::from_bytes(&[5; 32])
    }

    fn peer() -> SequencerKey {
        SequencerKey::new(Ed25519Key::from_bytes(&PEER_SECRET).public_key().to_bytes())
            .expect("valid key")
    }

    fn second_peer() -> SequencerKey {
        SequencerKey::new(
            Ed25519Key::from_bytes(&SECOND_PEER_SECRET)
                .public_key()
                .to_bytes(),
        )
        .expect("valid key")
    }

    /// Three keys: `slash_approval_threshold` asks two of them.
    fn committee() -> SequencerStakeConfig {
        config_staking(&[approver(), offender(), peer()])
    }

    /// Four keys with the peer released, so the three left still clear the bar.
    fn committee_with_the_peer_leaving() -> SequencerStakeConfig {
        let mut config = config_staking(&[approver(), offender(), peer(), second_peer()]);
        config
            .entries
            .get_mut(&peer())
            .expect("the peer is staked")
            .total_pending_unstake = 1;

        config
    }

    fn approver() -> SequencerKey {
        SequencerKey::new(approver_signing_key().public_key().to_bytes()).expect("valid key")
    }

    async fn slasher(approver: Ed25519Key) -> Slasher {
        SlasherActor::spawn(SlasherActor::load(storage(), approver).await)
    }

    fn signed_by(key: &Ed25519Key, inscription: [u8; 32]) -> ReportedOffence {
        ReportedOffence {
            signer: key.public_key().to_bytes(),
            inscription,
        }
    }

    fn signed_by_offender(inscription: [u8; 32]) -> ReportedOffence {
        signed_by(&offender_signing_key(), inscription)
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
            channel_params: Some(sequencer_stake_core::ChannelParams {
                minimum_sequencer_stake: 1,
                posting_timeframe: 300,
                posting_timeout: 25,
            }),
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

    /// A peer's approval of `offender`'s `inscription`, signed by `secret`.
    fn peer_approval(secret: [u8; 32], inscription: [u8; 32]) -> Approval {
        approval_of(secret, offender(), inscription)
    }

    /// A peer's approval of `offender`'s `inscription`, signed by `secret`.
    fn approval_of(secret: [u8; 32], offender: SequencerKey, inscription: [u8; 32]) -> Approval {
        let key = Ed25519Key::from_bytes(&secret);
        let offence = Offence {
            offender,
            inscription,
        };
        let message =
            sequencer_stake_core::slash_approval_message(offence.offender, offence.inscription);

        Approval {
            offence,
            signer: SequencerKey::new(key.public_key().to_bytes()).expect("valid key"),
            signature: key.sign_payload(&message).to_bytes(),
        }
    }

    async fn send(slasher: &Slasher, approval: Approval) {
        slasher
            .tell(approval)
            .await
            .expect("the slasher should accept an approval");
    }

    /// The approvals the one proposed tx carries.
    fn approvals_in(txs: &[LeeTransaction]) -> Vec<SequencerKey> {
        let [LeeTransaction::Public(tx)] = txs else {
            panic!("expected exactly one public slash transaction");
        };
        let sequencer_stake_core::Instruction::Slash { approvals, .. } =
            borsh::from_slice(tx.message().instruction_data.as_ref())
                .expect("the instruction should decode")
        else {
            panic!("expected a Slash instruction");
        };

        approvals.into_iter().map(|a| a.signer).collect()
    }

    #[tokio::test]
    async fn a_reported_offence_becomes_a_slash_candidate() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;

        assert_eq!(propose(&slasher, committee()).await.len(), 1);
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
        // Both offences clear the bar, so only the dedup can hold one back.
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;
        send(&slasher, peer_approval(PEER_SECRET, [9; 32])).await;

        // The first burn takes everything, so the second would only abort.
        assert_eq!(propose(&slasher, committee()).await.len(), 1);
    }

    #[tokio::test]
    async fn each_offender_yields_one_slash_whatever_the_offence_order() {
        let slasher = slasher(approver_signing_key()).await;
        // Interleaved by inscription, so ordering `found` on anything but the
        // offender splits the first offender's two offences around the second's.
        report(
            &slasher,
            vec![
                signed_by(&offender_signing_key(), [1; 32]),
                signed_by(&second_offender_signing_key(), [5; 32]),
                signed_by(&offender_signing_key(), [9; 32]),
            ],
        )
        .await;

        send(&slasher, peer_approval(PEER_SECRET, [1; 32])).await;
        send(&slasher, peer_approval(PEER_SECRET, [9; 32])).await;
        send(
            &slasher,
            approval_of(PEER_SECRET, second_offender(), [5; 32]),
        )
        .await;

        // Both offenders keep an entry to burn, but neither is accredited, so
        // the approver and the peer are the whole committee that counts.
        let mut config = config_staking(&[approver(), peer(), offender(), second_offender()]);
        for offender in [offender(), second_offender()] {
            config
                .entries
                .get_mut(&offender)
                .expect("the offender is staked")
                .total_pending_unstake = 1;
        }

        assert_eq!(
            propose(&slasher, config).await.len(),
            2,
            "one slash per offender, not one per offence"
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
    #[tokio::test]
    async fn a_peer_approval_carries_a_three_key_committee_over_the_threshold() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        assert!(
            propose(&slasher, committee()).await.is_empty(),
            "one approval is under a three-key committee's threshold"
        );

        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;
        let proposed = propose(&slasher, committee()).await;

        assert_eq!(approvals_in(&proposed), vec![approver(), peer()]);
    }

    #[tokio::test]
    async fn an_approval_for_an_offence_this_node_never_saw_is_dropped() {
        let slasher = slasher(approver_signing_key()).await;

        // Arrives before this node finalized the inscription for itself.
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        assert!(
            propose(&slasher, committee()).await.is_empty(),
            "a peer is not trusted for the offence, only for its signature"
        );
    }

    #[tokio::test]
    async fn an_approval_whose_signature_does_not_verify_is_dropped() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        // Signed over one inscription, then claimed over the reported one.
        let mut forged = peer_approval(PEER_SECRET, [9; 32]);
        forged.offence.inscription = INSCRIPTION;
        send(&slasher, forged).await;

        assert!(propose(&slasher, committee()).await.is_empty());
    }

    #[tokio::test]
    async fn an_approval_from_a_key_the_config_does_not_accredit_does_not_count() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;

        // Same threshold, but the peer that signed is not in this config.
        let outsiders = config_staking(&[
            approver(),
            offender(),
            SequencerKey::new(Ed25519Key::from_bytes(&[7; 32]).public_key().to_bytes())
                .expect("valid key"),
        ]);

        assert!(propose(&slasher, outsiders).await.is_empty());
    }

    #[tokio::test]
    async fn an_approval_screened_out_on_arrival_is_never_stored() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;

        // A config without the peer, so its approval is turned away on arrival.
        propose(&slasher, config_staking(&[approver(), offender()])).await;
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;

        assert!(
            propose(&slasher, committee()).await.is_empty(),
            "an approval turned away on arrival must not be kept"
        );
    }

    #[tokio::test]
    async fn a_repeated_approval_counts_once() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;

        // `Slash` aborts on a repeated signer, so a duplicate must not be added.
        assert_eq!(
            approvals_in(&propose(&slasher, committee()).await),
            vec![approver(), peer()]
        );
    }

    #[tokio::test]
    async fn own_approval_is_published_on_report_and_answered_to_a_peer() {
        let slasher = slasher(approver_signing_key()).await;
        let (tx, mut rx) = mpsc::channel(8);
        slasher
            .tell(SetApprovalPublisher(tx))
            .await
            .expect("the slasher should accept a publisher");

        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;
        assert_eq!(
            rx.recv().await.map(|a| a.signer),
            Some(approver()),
            "a newly found offence should be announced"
        );

        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;
        assert_eq!(
            rx.recv().await.map(|a| a.signer),
            Some(approver()),
            "a peer that approved first should be answered"
        );
    }

    #[tokio::test]
    async fn an_approval_from_a_peer_on_its_way_out_does_not_count() {
        let slasher = slasher(approver_signing_key()).await;
        report(&slasher, vec![signed_by_offender(INSCRIPTION)]).await;
        send(&slasher, peer_approval(PEER_SECRET, INSCRIPTION)).await;
        send(&slasher, peer_approval(SECOND_PEER_SECRET, INSCRIPTION)).await;

        // The staying peer carries the bar on its own, so the leaver's approval
        // is dropped for being unaccredited, not for being unnecessary.
        let signers = approvals_in(&propose(&slasher, committee_with_the_peer_leaving()).await);

        assert!(signers.contains(&second_peer()), "got {signers:?}");
        assert!(
            !signers.contains(&peer()),
            "a key with nothing left staked must not appear in a Slash, got {signers:?}"
        );
    }
}
