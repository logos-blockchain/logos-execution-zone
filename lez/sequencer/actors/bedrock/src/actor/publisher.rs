use std::time::Duration;

use anyhow::Context as _;
use common::block::Block;
use kameo::actor::ActorRef;
use kameo_actors::broker::Broker;
use log::info;
use logos_blockchain_core::{
    mantle::{
        Op, OpProof, SignedOps,
        channel::{SlotTimeframe, SlotTimeout},
        gas::GasCost,
        ops::channel::{VerifiedChannelKeys, config::ChannelConfigOp, inscribe::InscriptionOp},
        traits::Hashable as _,
        transactions::{MantleTxBuilder, OpProofs},
    },
    proofs::channel_multi_sig_proof::{ChannelMultiSigProof, IndexedSignatures},
};
use logos_blockchain_zone_sdk::{
    adapter::{Node as _, NodeHttpClient},
    node_types::{Inscription, WalletFundRequestBody, WalletFundResponseBody},
    sequencer::{
        ChannelUpdate as SdkChannelUpdate, ChannelUpdateTx, Event, FinalizedOp, FinalizedTx,
        FundingConfig, InscriptionInfo, SequencerConfig, WithdrawInputs, ZoneSequencer,
    },
};
use sequencer_actors_common::SendErrorExt as _;
use sequencer_storage_actor::protocol::ZoneCheckpointRecord;

use crate::{
    Result,
    actor::{block_from_inscription, released_notes, verified_keys},
    error::Error,
    protocol::{
        ChannelEntry, ChannelEvent, ChannelEventKind, ChannelId, ChannelParams, ChannelSeq,
        ChannelUpdate, DeserializeOp as _, Ed25519Key, Ed25519PublicKey, IndexedSignature,
        LiveChannelConfig, MsgId, PreparedConfig, PublishOutcome, PublisherEvent,
        SequencerCheckpoint, ViewChange, WithdrawArg, ZkPublicKey,
    },
};

pub struct PublisherConfig {
    pub channel_id: ChannelId,
    pub bedrock_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
    pub resubmit_interval: Duration,
}

pub struct Publisher {
    node: NodeHttpClient,
    sequencer: ZoneSequencer<NodeHttpClient>,
    channel_id: ChannelId,
    bedrock_signing_key: Ed25519Key,
    funding_pk: ZkPublicKey,
    priority_fee_percent: u64,
    /// Version of the channel view this actor holds, bumped by every broadcast
    /// update and every publish.
    seq: ChannelSeq,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
}

impl Publisher {
    pub async fn new(
        config: PublisherConfig,
        node: NodeHttpClient,
        initial_checkpoint: Option<ZoneCheckpointRecord>,
        broker_ref: ActorRef<Broker<ChannelEvent>>,
    ) -> Result<Self> {
        let PublisherConfig {
            channel_id,
            bedrock_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
        } = config;

        let seq = initial_checkpoint
            .as_ref()
            .map_or(ChannelSeq::ZERO, |stored| ChannelSeq::resumed(stored.seq));
        let initial_checkpoint = initial_checkpoint
            .map(|stored| SequencerCheckpoint::from_bytes(&stored.bytes))
            .transpose()?;

        if let Some(checkpoint) = &initial_checkpoint
            && has_channel_activity(checkpoint)
            && node
                .channel_state(channel_id)
                .await
                .map_err(|err| Error::NodeRequestFailed(err.into()))?
                .is_none()
        {
            return Err(Error::CheckpointChannelMissing);
        }

        let zone_sdk_config = SequencerConfig {
            resubmit_interval,
            ..SequencerConfig::new(FundingConfig {
                funding_pk,
                // Withdraw change goes back to the funding key.
                change_pk: None,
                max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
                priority_fee_percent,
            })
        };

        let sequencer = ZoneSequencer::init_with_config(
            channel_id,
            bedrock_signing_key.clone(),
            node.clone(),
            zone_sdk_config,
            initial_checkpoint,
        );

        let mut publisher = Self {
            node,
            sequencer,
            channel_id,
            bedrock_signing_key,
            funding_pk,
            priority_fee_percent,
            seq,
            broker_ref,
        };

        // Wait for cold-start backfill to complete before returning so callers
        // can publish immediately without racing readiness. The events on the
        // way report the channel up to its tip, so they are published as well.
        while !publisher.sequencer.is_ready() {
            let event = publisher.sequencer.next_event().await;
            publisher.on_event(event).await?;
        }

        Ok(publisher)
    }

    /// The next zone-sdk event. Cancel safe, unlike [`Self::on_event`].
    pub async fn next_event(&mut self) -> Event {
        self.sequencer.next_event().await
    }

    /// Publishes what `event` reports to the broker.
    pub async fn on_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::BlocksProcessed {
                checkpoint,
                channel_update,
                finalized,
                deposits: _,
            } => {
                self.on_blocks_processed(checkpoint, channel_update, finalized)
                    .await?;
                self.publish_live_config().await
            }
            Event::TurnNotification { notification } => {
                info!(
                    "Turn update: our_turn={}, starting_slot={:?}, ends_at_slot={:?}",
                    notification.our_turn_to_write,
                    notification.starting_slot,
                    notification.ends_at_slot
                );

                self.publish(
                    "turn",
                    PublisherEvent::Turn {
                        our_turn_to_write: notification.our_turn_to_write,
                    },
                )
                .await
            }
            Event::Ready => self.publish_live_config().await,
            Event::MempoolPending(_) => Ok(()),
        }
    }

    /// Publishes the channel update one processed L1 block carries.
    async fn on_blocks_processed(
        &mut self,
        checkpoint: SequencerCheckpoint,
        channel_update: SdkChannelUpdate,
        finalized: Vec<FinalizedTx>,
    ) -> Result<()> {
        // An L1 block that moved nothing on this channel: it only advances the checkpoint.
        if matches!(&channel_update, SdkChannelUpdate::Extension { adopted } if adopted.is_empty())
            && finalized.is_empty()
        {
            return Ok(());
        }
        let channel_id = self.channel_id;
        let entries = |txs: &mut dyn Iterator<Item = &ChannelUpdateTx>| {
            txs.flat_map(|tx| channel_entries(tx, channel_id)).collect()
        };
        let view = match &channel_update {
            SdkChannelUpdate::Extension { adopted } => {
                ViewChange::Extension(entries(&mut adopted.iter()))
            }
            SdkChannelUpdate::Conflict { orphaned, .. } => ViewChange::Conflict {
                canonical: entries(&mut channel_update.canonical_chain().into_iter().flatten()),
                orphaned: entries(&mut orphaned.iter()),
            },
        };

        let mut finalized_entries = Vec::new();
        let mut deposits = Vec::new();
        let mut withdrawals = Vec::new();
        let mut undecodable = Vec::new();
        let mut finalized_signers = Vec::new();
        for op in finalized.into_iter().flat_map(|item| item.ops) {
            match op {
                FinalizedOp::Inscription(inscription) => {
                    let entry = channel_entry(&inscription);
                    let signed = inscription
                        .signer
                        .and_then(|signer| Ed25519PublicKey::try_from(signer).ok())
                        .map(|signer| (inscription.this_msg, signer));
                    let empty =
                        <Inscription as AsRef<[u8]>>::as_ref(&inscription.payload).is_empty();
                    match (&entry.block, empty) {
                        (Some(_), _) => finalized_signers.extend(signed),
                        // Empty payload: a missed turn for the liveness
                        // fault. Signer-less entries are configs, via
                        // `FinalizedOp::Config`.
                        (None, true) => {}
                        (None, false) => undecodable.extend(signed),
                    }
                    finalized_entries.push(entry);
                }
                FinalizedOp::Deposit(deposit) => deposits.push(deposit),
                FinalizedOp::Withdraw(withdraw) => {
                    withdrawals.push(withdraw);
                }
                // Neither carries a block or an
                // author the LEZ chain models.
                FinalizedOp::Config(_) | FinalizedOp::ChannelTransfer(_) => {}
            }
        }

        let seq = self.next_seq();
        self.publish(
            "update",
            PublisherEvent::Update(Box::new(ChannelUpdate {
                checkpoint,
                seq,
                view,
                finalized: finalized_entries,
                deposits,
                withdrawals,
                undecodable,
                finalized_signers,
            })),
        )
        .await
    }

    /// Publishes the channel config zone-sdk last read from the node.
    ///
    /// Sent on every live block, changed or not: what the config should become
    /// follows the chain, so consumers re-evaluate it as the chain moves. Skipped
    /// during cold-start backfill, which reads the config only once.
    async fn publish_live_config(&mut self) -> Result<()> {
        if !self.sequencer.is_ready() {
            return Ok(());
        }
        let Some(channel) = self
            .sequencer
            .subscribe_channel_view()
            .borrow()
            .channel
            .clone()
        else {
            return Ok(());
        };

        let config = LiveChannelConfig::try_from(&channel)?;
        self.publish("config", PublisherEvent::Config(config)).await
    }

    /// Publishes `event` to `channel/<channel_id>/publisher/<topic>`.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Helps to make returned future Send"
    )]
    async fn publish(&mut self, topic: &str, event: PublisherEvent) -> Result<()> {
        self.broker_ref
            .tell(kameo_actors::broker::Publish {
                topic: format!("channel/{}/publisher/{topic}", self.channel_id),
                message: ChannelEvent {
                    channel_id: self.channel_id,
                    event: ChannelEventKind::Publisher(event),
                },
            })
            .await
            .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
    }

    pub async fn create_channel(
        &mut self,
        genesis: Block,
        keys: Vec<Ed25519PublicKey>,
        channel_params: ChannelParams,
        configuration_threshold: u16,
    ) -> Result<PublishOutcome> {
        let own_key = self.bedrock_signing_key.public_key();
        if keys.first() != Some(&own_key) {
            return Err(Error::ChannelCreationRequiresOurKey);
        }

        let key_count = keys.len();
        let keys = VerifiedChannelKeys::try_from(keys)
            .map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        let config_op = genesis_config_op(
            self.channel_id,
            keys,
            &channel_params,
            configuration_threshold,
        );

        let data = borsh::to_vec(&genesis).map_err(Error::BlockEncodingFailed)?;
        let inscription: Inscription = data.try_into().map_err(|_rr| Error::BlockTooLarge)?;
        // A config moves the config tip only, so the first block chains on the root.
        let inscribe_op = InscriptionOp {
            channel_id: self.channel_id,
            inscription,
            parent: MsgId::root(),
            signer: own_key.into_unverified(),
        };
        let msg_id = inscribe_op.id();

        let funded = self
            .fund_ops([
                Op::ChannelConfig(config_op),
                Op::ChannelInscribe(inscribe_op),
            ])
            .await?;
        let mantle_tx = funded.funded_tx;

        let signature = self
            .bedrock_signing_key
            .sign_payload(mantle_tx.hash().as_signing_bytes().as_ref());

        let mut op_proofs =
            OpProofs::from([OpProof::ChannelMultiSigProof(genesis_config_proof()?)]);
        op_proofs
            .try_push(OpProof::Ed25519Sig(signature))
            .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        if let Some(transfer_proof) = funded.transfer_proof {
            op_proofs
                .try_push(transfer_proof)
                .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        }

        info!("Creating the channel with {key_count} accredited key(s), genesis block bundled");

        let tx = SignedOps::from_parts(mantle_tx, op_proofs)?;
        self.submit_tx(tx, msg_id, MsgId::root())
    }

    pub async fn publish_block(
        &mut self,
        block: Block,
        withdrawals: Vec<WithdrawArg>,
        parent: Option<MsgId>,
        expected_seq: Option<ChannelSeq>,
    ) -> Result<PublishOutcome> {
        if let Some(expected) = expected_seq
            && expected != self.seq
        {
            return Err(Error::ChannelMoved {
                provided: expected,
                current: self.seq,
            });
        }

        let data = borsh::to_vec(&block).map_err(Error::BlockEncodingFailed)?;
        let inscription: Inscription = data.try_into().map_err(|_err| Error::BlockTooLarge)?;

        if let Some(parent) = parent {
            if !withdrawals.is_empty() {
                return Err(Error::CannotPublishBlockOnParentWithWithdrawals);
            }

            let inscribe_op = InscriptionOp {
                channel_id: self.channel_id,
                inscription,
                parent,
                signer: self.bedrock_signing_key.public_key().into_unverified(),
            };

            let msg_id = inscribe_op.id();

            let funded = self.fund_ops([Op::ChannelInscribe(inscribe_op)]).await?;
            let mantle_tx = funded.funded_tx;

            let signature = self
                .bedrock_signing_key
                .sign_payload(mantle_tx.hash().as_signing_bytes().as_ref());
            let mut op_proofs = OpProofs::from([OpProof::Ed25519Sig(signature)]);
            if let Some(transfer_proof) = funded.transfer_proof {
                op_proofs
                    .try_push(transfer_proof)
                    .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
            }

            let tx = SignedOps::from_parts(mantle_tx, op_proofs)?;
            self.submit_tx(tx, msg_id, parent)
        } else {
            let (result, checkpoint) = if withdrawals.is_empty() {
                self.sequencer
                    .handle()
                    .publish(inscription)
                    .await
                    .map_err(|err| Error::SubmitSignedTransactionFailed(err.into()))?
            } else {
                self.sequencer
                    .handle()
                    .publish_atomic_withdraw(inscription, withdrawals, WithdrawInputs::Auto)
                    .await
                    .map_err(|err| Error::PublishAtomicWithdrawFailed(err.into()))?
            };

            Ok(PublishOutcome {
                this_msg: result.tx.inscription().this_msg,
                parent: result.tx.inscription().parent_msg,
                checkpoint,
                seq: self.next_seq(),
                released_notes: released_notes(&result.tx),
            })
        }
    }

    pub async fn prepare_config(
        &mut self,
        keys: Vec<Ed25519PublicKey>,
        posting_timeframe: u32,
        posting_timeout: u32,
        configuration_threshold: u16,
        transfer_threshold: u16,
    ) -> Result<PreparedConfig> {
        let keys = VerifiedChannelKeys::try_from(keys)
            .map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        let prepared = self
            .sequencer
            .handle()
            .prepare_channel_config(
                keys,
                SlotTimeframe::from(posting_timeframe),
                SlotTimeout::from(posting_timeout),
                configuration_threshold,
                transfer_threshold,
            )
            .await?;
        let accredited_keys = verified_keys(&prepared.accredited_keys)?;

        Ok(PreparedConfig::new(prepared, accredited_keys))
    }

    pub fn change_channel_config(
        &mut self,
        prepared: PreparedConfig,
        signatures: Vec<IndexedSignature>,
    ) -> Result<()> {
        self.sequencer
            .handle()
            .submit_channel_config(prepared.into_inner(), signatures)?;

        Ok(())
    }

    pub fn check_is_our_turn(&self) -> bool {
        self.sequencer
            .subscribe_turn_to_write()
            .borrow()
            .our_turn_to_write
    }

    #[cfg(feature = "test-utils")]
    pub async fn publish_raw_inscription(&mut self, data: Vec<u8>) -> Result<PublishOutcome> {
        let inscription: Inscription =
            data.try_into().map_err(|_err| Error::InscriptionTooLarge)?;

        let (result, checkpoint) = self
            .sequencer
            .handle()
            .publish(inscription)
            .await
            .map_err(|err| Error::SubmitSignedTransactionFailed(err.into()))?;

        Ok(PublishOutcome {
            this_msg: result.tx.inscription().this_msg,
            parent: result.tx.inscription().parent_msg,
            checkpoint,
            seq: self.next_seq(),
            released_notes: released_notes(&result.tx),
        })
    }

    fn submit_tx(
        &mut self,
        tx: SignedOps<
            logos_blockchain_zone_sdk::node_types::Unverified,
            logos_blockchain_core::mantle::ledger::verification_mode::StandardMode,
        >,
        msg_id: MsgId,
        parent: MsgId,
    ) -> Result<PublishOutcome> {
        let (result, checkpoint) = self
            .sequencer
            .handle()
            .submit_signed_tx(tx, msg_id)
            .map_err(|err| Error::SubmitSignedTransactionFailed(err.into()))?;

        Ok(PublishOutcome {
            this_msg: result.tx.inscription().this_msg,
            parent,
            checkpoint,
            seq: self.next_seq(),
            released_notes: released_notes(&result.tx),
        })
    }

    /// Bumps the channel sequence and hands back the new one.
    const fn next_seq(&mut self) -> ChannelSeq {
        self.seq = self.seq.next();
        self.seq
    }

    /// Funds `ops` from the node's wallet, which appends a fee transfer (paid from
    /// `funding_pk`, change back to it) and returns its proof.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Helps to make returned future Send"
    )]
    async fn fund_ops(
        &mut self,
        ops: impl IntoIterator<Item = Op>,
    ) -> Result<WalletFundResponseBody> {
        let tx_builder = MantleTxBuilder::new()
            .extend_ops(ops)
            .map_err(|err| Error::TooManyOperationProofs(err.into()))?;

        self.node
            .fund_tx(WalletFundRequestBody {
                tip: None,
                tx_builder,
                change_public_key: self.funding_pk,
                funding_public_keys: vec![self.funding_pk],
                max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
                priority_fee_percent: self.priority_fee_percent,
            })
            .await
            .context("Failed to fund channel transaction")
            .map_err(Error::NodeRequestFailed)
    }
}

/// The config op that creates `channel_id` with `keys` as its founding committee.
pub(super) fn genesis_config_op(
    channel_id: ChannelId,
    keys: VerifiedChannelKeys,
    channel_params: &ChannelParams,
    configuration_threshold: u16,
) -> ChannelConfigOp {
    ChannelConfigOp {
        channel: channel_id,
        // The channel does not exist yet, so the config lineage starts here.
        parent: MsgId::root(),
        keys,
        posting_timeframe: SlotTimeframe::from(channel_params.posting_timeframe),
        posting_timeout: SlotTimeout::from(channel_params.posting_timeout),
        configuration_threshold,
        transfer_threshold: system_accounts::DEFAULT_SEQUENCER_WITHDRAW_THRESHOLD,
    }
}

/// The proof a channel-creating config op carries. No key is accredited before
/// creation, so Bedrock verifies against a threshold of zero and rejects the
/// whole creation tx over a proof holding any signature.
pub(super) fn genesis_config_proof() -> Result<ChannelMultiSigProof> {
    ChannelMultiSigProof::try_new(IndexedSignatures::default()).map_err(Into::into)
}

/// Whether `checkpoint` records messages published to or observed on the channel.
fn has_channel_activity(checkpoint: &SequencerCheckpoint) -> bool {
    checkpoint.last_msg_id != MsgId::root() || !checkpoint.pending_txs.is_empty()
}

/// A message-lineage entry, with its block when the payload decodes to one.
fn channel_entry(inscription: &InscriptionInfo) -> ChannelEntry {
    let block = if <Inscription as AsRef<[u8]>>::as_ref(&inscription.payload).is_empty() {
        None
    } else {
        block_from_inscription(inscription)
    };
    ChannelEntry {
        msg: inscription.this_msg,
        parent: inscription.parent_msg,
        block,
    }
}

/// Every message-lineage entry a channel tx carries, in op order.
///
/// A config op is on the config lineage, not this one, so it is skipped.
pub(super) fn channel_entries(tx: &ChannelUpdateTx, channel_id: ChannelId) -> Vec<ChannelEntry> {
    match tx {
        ChannelUpdateTx::Inscription(info) => vec![channel_entry(info)],
        ChannelUpdateTx::AtomicWithdraw(bundle) => vec![channel_entry(&bundle.inscription)],
        ChannelUpdateTx::PinDeposit(bundle) => vec![channel_entry(&bundle.inscription)],
        ChannelUpdateTx::Config(_) => Vec::new(),
        ChannelUpdateTx::Custom(signed_tx) => {
            logos_blockchain_zone_sdk::sequencer::channel_inscriptions(signed_tx, channel_id)
                .iter()
                .map(channel_entry)
                .collect()
        }
    }
}
