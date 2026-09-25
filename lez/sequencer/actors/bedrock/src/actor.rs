use std::sync::Arc;

use anyhow::Context as _;
use common::block::Block;
use futures::StreamExt as _;
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
};
use kameo_actors::broker::Broker;
use log::{info, warn};
use logos_blockchain_binary_codec::bincode::DeserializeOp as _;
use logos_blockchain_core::{
    mantle::{
        NoteId, Op, OpProof, SignedOps,
        channel::{SlotTimeframe, SlotTimeout},
        gas::GasCost,
        ops::channel::{VerifiedChannelKeys, config::ChannelConfigOp, inscribe::InscriptionOp},
        traits::Hashable as _,
        transactions::{MantleTxBuilder, OpProofs},
    },
    proofs::channel_multi_sig_proof::{ChannelMultiSigProof, IndexedSignatures},
};
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    node_types::{Inscription, WalletFundRequestBody, WalletFundResponseBody},
    sequencer::{
        ChannelUpdate as SdkChannelUpdate, ChannelUpdateTx, Event, FinalizedOp, FundingConfig,
        InscriptionInfo, PendingTx, SequencerChannelView, SequencerCheckpoint, SequencerConfig,
        WithdrawInputs, ZoneSequencer,
    },
};
use sequencer_actors_common::EraseMessage as _;
use sequencer_storage_actor::{StorageActorTrait, protocol::GetZoneCheckpoint};
use tokio::{select, sync::watch};

#[cfg(feature = "test-utils")]
use crate::protocol::PublishRawInscription;
use crate::{
    BedrockActorTrait, Result,
    actor::config::Config,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, ChannelEntry, ChannelEvent, ChannelId,
        ChannelParams, ChannelSeq, ChannelUpdate, CheckChannelExists, CheckIsOurTurn,
        CreateChannel, Ed25519PublicKey, GetAccreditedKeys, GetChannelId, GetChannelIdReply,
        GetChannelTipMessageId, GetChannelTipSlot, LiveChannelConfig, MsgId, PrepareConfig,
        PreparedChannelConfig, PublishBlock, PublishOutcome, ReadChannel, Slot, ViewChange,
        ZoneMessage, verified_keys,
    },
};

pub mod config;
#[cfg(test)]
mod tests;

/// Bedrock Actor responsible for interacting with the Bedrock node and managing channel events.
///
/// [`BedrockActor`] will post [`ChannelEvent`]s to the provided broker using the following topics:
/// - `channel/<channel_id>/update`: for [`ChannelEvent::Update`]
/// - `channel/<channel_id>/turn`: for [`ChannelEvent::Turn`]
/// - `channel/<channel_id>/config`: for [`ChannelEvent::Config`]
pub struct BedrockActor {
    config: Config,
    node: NodeHttpClient,
    sequencer: ZoneSequencer<NodeHttpClient>,
    channel_view_rx: watch::Receiver<SequencerChannelView>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
    /// Version of the channel view this actor holds, bumped by everything that
    /// mints a checkpoint.
    seq: ChannelSeq,
}

impl BedrockActor {
    pub async fn new<S: StorageActorTrait>(
        config: Config,
        storage_ref: ActorRef<S>,
        broker_ref: ActorRef<Broker<ChannelEvent>>,
    ) -> Result<Self> {
        let stored_checkpoint = storage_ref.ask(GetZoneCheckpoint).await?;
        let seq = stored_checkpoint
            .as_ref()
            .map_or(ChannelSeq::ZERO, |stored| ChannelSeq::resumed(stored.seq));
        let initial_checkpoint = stored_checkpoint
            .as_ref()
            .map(|stored| SequencerCheckpoint::from_bytes(&stored.bytes))
            .transpose()?;

        let Config {
            channel_id,
            node_url,
            basic_auth,
            bedrock_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
        } = &config;

        let node = NodeHttpClient::new(CommonHttpClient::new(basic_auth.clone()), node_url.clone());

        if let Some(checkpoint) = &initial_checkpoint
            && has_channel_activity(checkpoint)
            && node
                .channel_state(*channel_id)
                .await
                .map_err(|err| Error::NodeRequestFailed(err.into()))?
                .is_none()
        {
            return Err(Error::CheckpointChannelMissing);
        }

        let zone_sdk_config = SequencerConfig {
            resubmit_interval: *resubmit_interval,
            ..SequencerConfig::new(FundingConfig {
                funding_pk: *funding_pk,
                // Withdraw change goes back to the funding key.
                change_pk: None,
                max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
                priority_fee_percent: *priority_fee_percent,
            })
        };

        let sequencer = ZoneSequencer::init_with_config(
            *channel_id,
            bedrock_signing_key.clone(),
            node.clone(),
            zone_sdk_config,
            initial_checkpoint,
        );

        let channel_view_rx = sequencer.subscribe_channel_view();

        let mut bedrock = Self {
            config,
            node,
            sequencer,
            channel_view_rx,
            broker_ref,
            seq,
        };

        // Wait for cold-start backfill to complete before returning so callers
        // can publish immediately without racing readiness.
        while !bedrock.sequencer.is_ready() {
            // Zone SDK sequencer will process ready event internally.
            let event = bedrock.sequencer.next_event().await;
            bedrock.on_event(event).await?;
        }

        Ok(bedrock)
    }

    async fn on_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::BlocksProcessed {
                checkpoint,
                channel_update,
                finalized,
                deposits: _,
            } => {
                let channel_id = self.config.channel_id;
                let entries = |txs: &mut dyn Iterator<Item = &ChannelUpdateTx>| {
                    txs.flat_map(|tx| channel_entries(tx, channel_id)).collect()
                };
                let view = match &channel_update {
                    SdkChannelUpdate::Extension { adopted } => {
                        ViewChange::Extension(entries(&mut adopted.iter()))
                    }
                    SdkChannelUpdate::Conflict { orphaned, .. } => ViewChange::Conflict {
                        canonical: entries(
                            &mut channel_update.canonical_chain().into_iter().flatten(),
                        ),
                        orphaned: entries(&mut orphaned.iter()),
                    },
                };

                let mut finalized_entries = Vec::new();
                let mut deposits = Vec::new();
                let mut withdrawals = Vec::new();
                let mut undecodable = Vec::new();
                for op in finalized.into_iter().flat_map(|item| item.ops) {
                    match op {
                        FinalizedOp::Inscription(inscription) => {
                            let entry = channel_entry(&inscription);
                            // Empty payload: a missed turn for the liveness
                            // fault. Signer-less entries are configs, via
                            // `FinalizedOp::Config`.
                            if entry.block.is_none()
                                && !<Inscription as AsRef<[u8]>>::as_ref(&inscription.payload)
                                    .is_empty()
                            {
                                undecodable.extend(
                                    inscription
                                        .signer
                                        .and_then(|signer| Ed25519PublicKey::try_from(signer).ok())
                                        .map(|signer| (inscription.this_msg, signer)),
                                );
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
                self.broker_ref
                    .tell(kameo_actors::broker::Publish {
                        topic: format!("channel/{}/update", self.config.channel_id),
                        message: ChannelEvent::Update(Arc::new(ChannelUpdate {
                            checkpoint,
                            seq,
                            view,
                            finalized: finalized_entries,
                            deposits,
                            withdrawals,
                            undecodable,
                        })),
                    })
                    .await
                    .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
            }
            Event::TurnNotification { notification } => {
                info!(
                    "Turn update: our_turn={}, starting_slot={:?}, ends_at_slot={:?}",
                    notification.our_turn_to_write,
                    notification.starting_slot,
                    notification.ends_at_slot
                );

                self.broker_ref
                    .tell(kameo_actors::broker::Publish {
                        topic: format!("channel/{}/turn", self.config.channel_id),
                        message: ChannelEvent::Turn {
                            our_turn_to_write: notification.our_turn_to_write,
                        },
                    })
                    .await
                    .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
            }
            Event::Ready | Event::MempoolPending(_) => Ok(()),
        }
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Helps to make returned future Send"
    )]
    async fn on_channel_view_change(&mut self, channel_view: SequencerChannelView) -> Result<()> {
        let Some(channel) = channel_view.channel else {
            return Ok(());
        };

        let config = LiveChannelConfig::try_from(&channel)?;

        self.broker_ref
            .tell(kameo_actors::broker::Publish {
                topic: format!("channel/{}/config", self.config.channel_id),
                message: ChannelEvent::Config(config),
            })
            .await
            .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
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
}

impl BedrockActorTrait for BedrockActor {}

impl Actor for BedrockActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }

    async fn next(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        mailbox_rx: &mut MailboxReceiver<Self>,
    ) -> Result<Option<Signal<Self>>> {
        #[expect(
            clippy::integer_division_remainder_used,
            reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
        )]
        loop {
            select! {
                event = self.sequencer.next_event() => {
                    self.on_event(event).await?;
                }
                Ok(()) = self.channel_view_rx.changed() => {
                    let channel_view = self.channel_view_rx.borrow_and_update().clone();
                    self.on_channel_view_change(channel_view).await?;
                }
                signal = mailbox_rx.recv() => {
                    return Ok(signal)
                }
            }
        }
    }
}

impl Message<CreateChannel> for BedrockActor {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        CreateChannel {
            genesis,
            keys,
            channel_params,
            configuration_threshold,
        }: CreateChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let own_key = self.config.bedrock_signing_key.public_key();
        if keys.first() != Some(&own_key) {
            return Err(Error::ChannelCreationRequiresOurKey);
        }

        let key_count = keys.len();
        let keys = VerifiedChannelKeys::try_from(keys)
            .map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        let config_op = genesis_config_op(
            self.config.channel_id,
            keys,
            &channel_params,
            configuration_threshold,
        );

        let data = borsh::to_vec(&genesis).map_err(Error::BlockEncodingFailed)?;
        let inscription: Inscription = data.try_into().map_err(|_rr| Error::BlockTooLarge)?;
        // A config moves the config tip only, so the first block chains on the root.
        let inscribe_op = InscriptionOp {
            channel_id: self.config.channel_id,
            inscription,
            parent: MsgId::root(),
            signer: own_key.into_unverified(),
        };
        let msg_id = inscribe_op.id();

        let funded = fund_ops(
            &self.node,
            &self.config,
            [
                Op::ChannelConfig(config_op),
                Op::ChannelInscribe(inscribe_op),
            ],
        )
        .await?;
        let mantle_tx = funded.funded_tx;

        let signature = self
            .config
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
}

impl Message<PublishBlock> for BedrockActor {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishBlock {
            block,
            withdrawals,
            parent,
            expected_seq,
        }: PublishBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
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
                channel_id: self.config.channel_id,
                inscription,
                parent,
                signer: self
                    .config
                    .bedrock_signing_key
                    .public_key()
                    .into_unverified(),
            };

            let msg_id = inscribe_op.id();

            let funded =
                fund_ops(&self.node, &self.config, [Op::ChannelInscribe(inscribe_op)]).await?;
            let mantle_tx = funded.funded_tx;

            let signature = self
                .config
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
}

impl Message<PrepareConfig> for BedrockActor {
    type Reply = Result<PreparedChannelConfig>;

    async fn handle(
        &mut self,
        PrepareConfig { target }: PrepareConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let keys = VerifiedChannelKeys::try_from(target.keys.clone())
            .map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        self.sequencer
            .handle()
            .prepare_channel_config(
                keys,
                SlotTimeframe::from(target.posting_timeframe),
                SlotTimeout::from(target.posting_timeout),
                target.configuration_threshold,
                target.transfer_threshold,
            )
            .await
            .map_err(Into::into)
    }
}

impl Message<ChangeChannelConfig> for BedrockActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        ChangeChannelConfig {
            prepared,
            signatures,
        }: ChangeChannelConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.sequencer
            .handle()
            .submit_channel_config(prepared, signatures)?;

        Ok(())
    }
}

impl Message<CheckChannelExists> for BedrockActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        _msg: CheckChannelExists,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .node
            .channel_state(self.config.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .is_some())
    }
}

impl Message<GetChannelId> for BedrockActor {
    type Reply = GetChannelIdReply;

    async fn handle(
        &mut self,
        GetChannelId: GetChannelId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        GetChannelIdReply {
            channel_id: self.config.channel_id,
        }
    }
}

impl Message<CheckIsOurTurn> for BedrockActor {
    type Reply = bool;

    async fn handle(
        &mut self,
        CheckIsOurTurn: CheckIsOurTurn,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.sequencer
            .subscribe_turn_to_write()
            .borrow()
            .our_turn_to_write
    }
}

impl Message<GetAccreditedKeys> for BedrockActor {
    type Reply = Result<Option<AccreditedKeys>>;

    async fn handle(
        &mut self,
        _msg: GetAccreditedKeys,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.node
            .channel_state(self.config.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| -> Result<AccreditedKeys> {
                Ok(AccreditedKeys {
                    keys: verified_keys(&state.accredited_keys)?,
                    config_tip: state.config_tip_hash,
                    tip_sequencer: state.tip_sequencer,
                })
            })
            .transpose()
    }
}

impl Message<GetChannelTipSlot> for BedrockActor {
    type Reply = Result<Option<Slot>>;

    async fn handle(
        &mut self,
        _msg: GetChannelTipSlot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .node
            .channel_state(self.config.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| state.tip_slot))
    }
}

impl Message<GetChannelTipMessageId> for BedrockActor {
    type Reply = Result<Option<MsgId>>;

    async fn handle(
        &mut self,
        _msg: GetChannelTipMessageId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .node
            .channel_state(self.config.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| state.tip_message))
    }
}

impl Message<ReadChannel> for BedrockActor {
    type Reply = Result<BoxStream<(ZoneMessage, Slot)>>;

    async fn handle(
        &mut self,
        ReadChannel { after }: ReadChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        const BATCH_SIZE: Slot = Slot::new(100);

        let lib_slot = self
            .node
            .consensus_info()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .cryptarchia_info
            .lib_slot;
        let start_slot = after.map_or_else(Slot::genesis, |s| s.strict_add(1.into()));

        let node = self.node.clone();
        let channel_id = self.config.channel_id;
        let stream = futures::stream::unfold(start_slot, move |current_slot| {
            let node = node.clone();
            async move {
                if current_slot > lib_slot {
                    return None;
                }

                let end_slot = (Slot::from(
                    current_slot
                        .into_inner()
                        .saturating_add(BATCH_SIZE.into_inner())
                        .checked_sub(1)
                        .expect("slot shouldn't overflow"),
                ))
                .min(lib_slot);

                match node
                    .zone_messages_in_blocks(current_slot, end_slot, channel_id)
                    .await
                {
                    Ok(messages) => Some((messages, end_slot.strict_add(1.into()))),
                    Err(e) => {
                        log::warn!(
                            "Failed to fetch zone messages from blocks {current_slot:?}..={end_slot:?}: {e}",
                        );
                        None
                    }
                }
            }
        })
        .flatten();

        Ok(Box::pin(stream))
    }
}

#[cfg(feature = "test-utils")]
impl Message<PublishRawInscription> for BedrockActor {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishRawInscription { data }: PublishRawInscription,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
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
}

impl TryFrom<&logos_blockchain_zone_sdk::node_types::ChannelState> for LiveChannelConfig {
    type Error = Error;

    fn try_from(state: &logos_blockchain_zone_sdk::node_types::ChannelState) -> Result<Self> {
        Ok(Self {
            keys: verified_keys(&state.accredited_keys)?,
            config_tip: state.config_tip_hash,
            required_signatures: state.configuration_threshold,
        })
    }
}

/// The config op that creates `channel_id` with `keys` as its founding committee.
fn genesis_config_op(
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
fn genesis_config_proof() -> Result<ChannelMultiSigProof> {
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
fn channel_entries(tx: &ChannelUpdateTx, channel_id: ChannelId) -> Vec<ChannelEntry> {
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

/// Deserialize an inscription payload into `(this_msg, Block)`. Bad payloads are
/// logged and skipped.
fn block_from_inscription(inscription: &InscriptionInfo) -> Option<Block> {
    borsh::from_slice::<Block>(&inscription.payload)
        .inspect_err(|err| {
            warn!("Failed to deserialize block from inscription: {err:?}");
        })
        .ok()
}

/// Channel notes the withdraws bundled with a published tx release; empty for a
/// plain inscription. See [`PublishOutcome::released_notes`].
fn released_notes(tx: &PendingTx) -> Vec<NoteId> {
    match tx {
        PendingTx::Inscription(_) | PendingTx::PinDeposit(_) => Vec::new(),
        PendingTx::AtomicWithdraw(bundle) => bundle
            .withdraws
            .iter()
            .flat_map(|withdraw| withdraw.op.inputs.iter().copied())
            .collect(),
    }
}

/// Funds `ops` from the node's wallet, which appends a fee transfer (paid from
/// `funding_key`, change back to it) and returns its proof.
async fn fund_ops(
    node: &NodeHttpClient,
    config: &Config,
    ops: impl IntoIterator<Item = Op>,
) -> Result<WalletFundResponseBody> {
    let tx_builder = MantleTxBuilder::new()
        .extend_ops(ops)
        .map_err(|err| Error::TooManyOperationProofs(err.into()))?;

    node.fund_tx(WalletFundRequestBody {
        tip: None,
        tx_builder,
        change_public_key: config.funding_pk,
        funding_public_keys: vec![config.funding_pk],
        max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
        priority_fee_percent: config.priority_fee_percent,
    })
    .await
    .context("Failed to fund channel transaction")
    .map_err(Error::NodeRequestFailed)
}
