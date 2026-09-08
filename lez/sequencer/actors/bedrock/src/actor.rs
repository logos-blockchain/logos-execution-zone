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
use logos_blockchain_core::{
    codec::DeserializeOp as _,
    mantle::{
        NoteId, Op, OpProof, SignedMantleTx,
        channel::{SlotTimeframe, SlotTimeout},
        gas::GasCost,
        ops::channel::{
            config::{ChannelConfigOp, Keys},
            inscribe::InscriptionOp,
        },
        traits::Hashable as _,
        transactions::{MantleTxBuilder, OpsProofs},
    },
    proofs::channel_multi_sig_proof::{ChannelMultiSigProof, IndexedSignature},
};
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    node_types::{Inscription, Unverified, WalletFundRequestBody, WalletFundResponseBody},
    sequencer::{
        ChannelUpdateTx, Event, FinalizedOp, FundingConfig, InscriptionInfo, PendingTx,
        SequencerCheckpoint, SequencerConfig, WithdrawInputs, ZoneSequencer,
    },
};
use sequencer_actors_common::EraseMessage as _;
use sequencer_storage_actor::{StorageActorTrait, protocol::GetZoneCheckpointBytes};
use tokio::select;

#[cfg(feature = "test-utils")]
use crate::protocol::PublishRawInscription;
use crate::{
    BedrockActorTrait, Result,
    actor::config::Config,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, ChannelEvent, ChannelId, ChannelUpdate,
        CheckChannelExists, CheckIsOurTurn, CreateChannel, GetAccreditedKeys, GetChannelId,
        GetChannelIdReply, GetChannelTipMessageId, GetChannelTipSlot, MsgId, PublishBlock,
        PublishOutcome, ReadChannel, Slot, ZoneMessage,
    },
};

pub mod config;

/// Bedrock Actor responsible for interacting with the Bedrock node and managing channel events.
///
/// [`BedrockActor`] will post [`ChannelEvent`]s to the provided broker using the following topics:
/// - `channel/<channel_id>/update`: for [`ChannelEvent::Update`]
/// - `channel/<channel_id>/turn`: for [`ChannelEvent::Turn`]
pub struct BedrockActor {
    config: Config,
    node: NodeHttpClient,
    sequencer: ZoneSequencer<NodeHttpClient>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
}

impl BedrockActor {
    pub async fn new<S: StorageActorTrait>(
        config: Config,
        storage_ref: ActorRef<S>,
        broker_ref: ActorRef<Broker<ChannelEvent>>,
    ) -> Result<Self> {
        let initial_checkpoint = storage_ref
            .ask(GetZoneCheckpointBytes)
            .await?
            .as_deref()
            .map(SequencerCheckpoint::from_bytes)
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

        let mut sequencer = ZoneSequencer::init_with_config(
            *channel_id,
            bedrock_signing_key.clone(),
            node.clone(),
            zone_sdk_config,
            initial_checkpoint,
        );

        // Wait for cold-start backfill to complete before returning so callers
        // can publish immediately without racing readiness.
        while !sequencer.is_ready() {
            // Zone SDK sequencer will process ready event internally.
            sequencer.next_event().await;
        }

        Ok(Self {
            config,
            node,
            sequencer,
            broker_ref,
        })
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Helps to make returned future Send"
    )]
    async fn on_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::BlocksProcessed {
                checkpoint,
                channel_update,
                finalized,
            } => {
                let adopted = channel_update
                    .adopted
                    .iter()
                    .flat_map(|tx| adopted_blocks(tx, self.config.channel_id))
                    .collect();
                let orphaned = channel_update
                    .orphaned
                    .iter()
                    .filter_map(channel_update_inscription)
                    .filter_map(block_from_inscription)
                    .collect();

                let mut finalized_blocks = Vec::new();
                let mut deposits = Vec::new();
                let mut withdrawals = Vec::new();
                let mut undecodable = Vec::new();
                for (l1_slot, op) in finalized.into_iter().flat_map(|item| {
                    let l1_slot = item.l1_slot;
                    item.ops.into_iter().map(move |op| (l1_slot, op))
                }) {
                    match op {
                        FinalizedOp::Inscription(inscription) => {
                            match block_from_inscription(&inscription) {
                                Some(block) => {
                                    finalized_blocks.push((block, l1_slot));
                                }
                                // An empty payload is not a
                                // block, but we don't slash
                                // for it.
                                None if <Inscription as AsRef<[u8]>>::as_ref(
                                    &inscription.payload,
                                )
                                .is_empty() => {}
                                // An inscription always names
                                // its signer.
                                None => undecodable.extend(
                                    inscription
                                        .signer
                                        .map(|signer| (inscription.this_msg, signer)),
                                ),
                            }
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

                self.broker_ref
                    .tell(kameo_actors::broker::Publish {
                        topic: format!("channel/{}/update", self.config.channel_id),
                        message: ChannelEvent::Update(Box::new(ChannelUpdate {
                            checkpoint,
                            adopted,
                            orphaned,
                            finalized: finalized_blocks,
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

    fn submit_tx(
        &mut self,
        tx: SignedMantleTx<Unverified>,
        msg_id: MsgId,
    ) -> Result<PublishOutcome> {
        let (result, checkpoint) = self
            .sequencer
            .handle()
            .submit_signed_tx(tx, msg_id)
            .map_err(|err| Error::SubmitSignedTransactionFailed(err.into()))?;

        Ok(PublishOutcome {
            this_msg: result.tx.inscription().this_msg,
            checkpoint,
            released_notes: released_notes(&result.tx),
        })
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
        }: CreateChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let own_key = self.config.bedrock_signing_key.public_key();
        if keys.first() != Some(&own_key) {
            return Err(Error::ChannelCreationRequiresOurKey);
        }

        let key_count = keys.len();
        let keys = Keys::try_from(keys).map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        let config_op = ChannelConfigOp {
            channel: self.config.channel_id,
            // The channel does not exist yet, so the config lineage starts here.
            parent: MsgId::root(),
            keys,
            posting_timeframe: SlotTimeframe::from(channel_params.posting_timeframe),
            posting_timeout: SlotTimeout::from(channel_params.posting_timeout),
            configuration_threshold: system_accounts::DEFAULT_SEQUENCER_CONFIGURATION_THRESHOLD,
            transfer_threshold: system_accounts::DEFAULT_SEQUENCER_WITHDRAW_THRESHOLD,
        };

        let data = borsh::to_vec(&genesis).map_err(Error::BlockEncodingFailed)?;
        let inscription: Inscription = data.try_into().map_err(|_rr| Error::BlockTooLarge)?;
        // A config moves the config tip only, so the first block chains on the root.
        let inscribe_op = InscriptionOp {
            channel_id: self.config.channel_id,
            inscription,
            parent: MsgId::root(),
            signer: own_key,
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
        // Creation skips the channel-config signature check, but the proof must
        // still be well formed; index 0 is our own key.
        let config_proof =
            ChannelMultiSigProof::try_new(IndexedSignature::new(0, signature).into())?;

        let mut ops_proofs: OpsProofs = OpProof::ChannelMultiSigProof(config_proof).into();
        ops_proofs
            .try_push(OpProof::Ed25519Sig(signature))
            .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        if let Some(transfer_proof) = funded.transfer_proof {
            ops_proofs
                .try_push(transfer_proof)
                .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        }

        info!("Creating the channel with {key_count} accredited key(s), genesis block bundled");

        let tx = SignedMantleTx::new(mantle_tx, ops_proofs);
        self.submit_tx(tx, msg_id)
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
        }: PublishBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
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
                signer: self.config.bedrock_signing_key.public_key(),
            };

            let msg_id = inscribe_op.id();

            let funded =
                fund_ops(&self.node, &self.config, [Op::ChannelInscribe(inscribe_op)]).await?;
            let mantle_tx = funded.funded_tx;

            let signature = self
                .config
                .bedrock_signing_key
                .sign_payload(mantle_tx.hash().as_signing_bytes().as_ref());
            let mut ops_proofs: OpsProofs = OpProof::Ed25519Sig(signature).into();
            if let Some(transfer_proof) = funded.transfer_proof {
                ops_proofs
                    .try_push(transfer_proof)
                    .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
            }

            let tx = SignedMantleTx::new(mantle_tx, ops_proofs);
            self.submit_tx(tx, msg_id)
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
                checkpoint,
                released_notes: released_notes(&result.tx),
            })
        }
    }
}

impl Message<ChangeChannelConfig> for BedrockActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        ChangeChannelConfig {
            new_keys,
            posting_timeframe,
            posting_timeout,
            configuration_threshold,
            transfer_threshold,
        }: ChangeChannelConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let keys =
            Keys::try_from(new_keys).map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        self.sequencer
            .handle()
            .channel_config(
                keys,
                SlotTimeframe::from(posting_timeframe),
                SlotTimeout::from(posting_timeout),
                configuration_threshold,
                transfer_threshold,
            )
            .await?;

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
        let rx = self.sequencer.subscribe_turn_to_write();
        rx.borrow().our_turn_to_write
    }
}

impl Message<GetAccreditedKeys> for BedrockActor {
    type Reply = Result<Option<AccreditedKeys>>;

    async fn handle(
        &mut self,
        _msg: GetAccreditedKeys,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .node
            .channel_state(self.config.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| AccreditedKeys {
                keys: state.accredited_keys.to_vec(),
                config_tip: state.config_tip_hash,
                tip_sequencer: state.tip_sequencer,
            }))
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
            checkpoint,
            released_notes: released_notes(&result.tx),
        })
    }
}

/// Every block an adopted tx carries, in op order. Non-block entries are
/// dropped: they reach consumers as the checkpoint's tip, not as payloads.
fn adopted_blocks(tx: &ChannelUpdateTx, channel_id: ChannelId) -> Vec<Block> {
    let entry = |inscription: &InscriptionInfo| {
        if <Inscription as AsRef<[u8]>>::as_ref(&inscription.payload).is_empty() {
            None
        } else {
            block_from_inscription(inscription)
        }
    };
    match tx {
        ChannelUpdateTx::Inscription(info) => entry(info).into_iter().collect(),
        ChannelUpdateTx::AtomicWithdraw(bundle) => entry(&bundle.inscription).into_iter().collect(),
        // A config-only tx carries no payload to apply.
        ChannelUpdateTx::Config(_) => Vec::new(),
        ChannelUpdateTx::Custom(signed_tx) => {
            logos_blockchain_zone_sdk::sequencer::channel_inscriptions(signed_tx, channel_id)
                .iter()
                .filter_map(entry)
                .collect()
        }
    }
}

/// The inscription carried by an orphaned tx (plain or atomic-withdraw bundle).
const fn channel_update_inscription(orphan: &ChannelUpdateTx) -> Option<&InscriptionInfo> {
    match orphan {
        ChannelUpdateTx::Inscription(info) => Some(info),
        ChannelUpdateTx::AtomicWithdraw(bundle) => Some(&bundle.inscription),
        ChannelUpdateTx::Config(_) | ChannelUpdateTx::Custom(_) => None,
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
        PendingTx::Inscription(_) => Vec::new(),
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
    let tx_builder = MantleTxBuilder::new().extend_ops(ops)?;
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
