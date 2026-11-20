use std::{
    collections::{BTreeSet, VecDeque},
    num::NonZero,
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use chain_state::timeout_node::TimeoutNode;
use common::block::Block;
use kameo::actor::ActorRef;
use kameo_actors::broker::Broker;
use logos_blockchain_zone_sdk::{
    adapter::{Node as _, NodeHttpClient},
    core::{
        mantle::{
            Op, OpProof, SignedOps,
            channel::{SlotTimeframe, SlotTimeout},
            gas::GasCost,
            ops::{
                ChannelInscribeProof, NoOpProof,
                channel::{
                    VerifiedChannelKeys,
                    config::ChannelConfigOp,
                    inscribe::{InscriptionOp, MiniBlocks},
                },
                program::ProgramRegisterOp,
            },
            traits::Hashable as _,
            transactions::{MantleTxBuilder, OpProofs},
        },
        proofs::channel_multi_sig_proof::ChannelMultiSigProof,
    },
    node_types::{Inscription, StepProof, WalletFundRequestBody, WalletFundResponseBody},
    sequencer::{
        ChannelUpdate as SdkChannelUpdate, ChannelUpdateTx, Event, FinalizedOp, FinalizedTx,
        FundingConfig, InscriptionInfo, SequencerConfig, ZoneSequencer,
    },
};
use sequencer_actors_common::SendErrorExt as _;
use sequencer_storage_actor::protocol::ZoneCheckpointRecord;
use tracing::info;
use vault_circuit::{Committee, PublicInputs, SigningKey};

use crate::{
    Result,
    actor::{
        block_from_inscription,
        finality::{self, ConfigIndex},
        vault::{VAULT_PROGRAM, VaultDeposit, VaultNote, VaultStep, vault_key},
        verified_keys,
    },
    error::Error,
    protocol::{
        BridgeMoves, ChannelEntry, ChannelEvent, ChannelEventKind, ChannelId, ChannelParams,
        ChannelSeq, ChannelUpdate, DeserializeOp as _, Ed25519Key, Ed25519PublicKey,
        IndexedSignatures, LiveChannelConfig, MsgId, Ops, PreparedConfig, PublishOutcome,
        PublisherEvent, SequencerCheckpoint, Slot, VaultMint, ViewChange, ZkPublicKey,
    },
};

pub struct PublisherConfig {
    pub channel_id: ChannelId,
    pub channel_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
    pub resubmit_interval: Duration,
    pub stale_refund_slots: u64,
    pub backfill_batch_slots: NonZero<u64>,
}

pub struct Publisher {
    node: TimeoutNode<NodeHttpClient>,
    sequencer: ZoneSequencer<TimeoutNode<NodeHttpClient>>,
    channel_id: ChannelId,
    channel_signing_key: Ed25519Key,
    funding_pk: ZkPublicKey,
    priority_fee_percent: u64,
    /// Version of the channel view this actor holds, bumped by every broadcast
    /// update and every publish.
    seq: ChannelSeq,
    /// History finalized up to this slot was replayed by the consumer, so it is left out.
    replayed_up_to: Option<Slot>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
    /// Events zone-sdk raised while a publish waited on the node, in order.
    backlog: VecDeque<Event>,
}

impl Publisher {
    /// Starts a publisher, returning it with the sequence it started at, feeding the configs
    /// zone-sdk reports final to `config_index`.
    pub async fn new(
        config: PublisherConfig,
        node: TimeoutNode<NodeHttpClient>,
        initial_checkpoint: Option<ZoneCheckpointRecord>,
        replayed_up_to: Option<Slot>,
        broker_ref: ActorRef<Broker<ChannelEvent>>,
        config_index: &mut ConfigIndex,
    ) -> Result<(Self, ChannelSeq)> {
        let PublisherConfig {
            channel_id,
            channel_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
            stale_refund_slots,
            backfill_batch_slots,
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
            stale_refund_slots,
            backfill_batch_slots: backfill_batch_slots.get(),
            ..SequencerConfig::new(FundingConfig {
                funding_pk,
                max_tx_fee: GasCost::new(logos_blockchain_zone_sdk::core::mantle::Value::MAX),
                priority_fee_percent,
            })
        };

        let sequencer = ZoneSequencer::init_with_config(
            channel_id,
            channel_signing_key.clone(),
            node.clone(),
            zone_sdk_config,
            initial_checkpoint,
        );

        let mut publisher = Self {
            node,
            sequencer,
            channel_id,
            channel_signing_key,
            funding_pk,
            priority_fee_percent,
            seq,
            replayed_up_to,
            broker_ref,
            backlog: VecDeque::new(),
        };

        // Wait for cold-start backfill to complete before returning so callers
        // can publish immediately without racing readiness. The events on the
        // way report the channel up to its tip, so they are published as well.
        while !publisher.sequencer.is_ready() {
            let event = publisher.sequencer.next_event().await;
            publisher.on_event(event, config_index).await?;
        }

        Ok((publisher, seq))
    }

    /// The next zone-sdk event. Cancel safe, unlike [`Self::on_event`].
    pub async fn next_event(&mut self) -> Event {
        if let Some(event) = self.backlog.pop_front() {
            return event;
        }
        self.sequencer.next_event().await
    }

    /// Publishes what `event` reports to the broker, after adding the configs it reports final to
    /// `config_index`.
    pub async fn on_event(&mut self, event: Event, config_index: &mut ConfigIndex) -> Result<()> {
        match event {
            Event::BlocksProcessed {
                checkpoint,
                channel_update,
                finalized,
                // A plain channel deposit stays under its holder's key and mints nothing.
                observed: _,
            } => {
                let config_keys = finalized.iter().flat_map(|item| {
                    item.ops.iter().filter_map(|op| {
                        if let FinalizedOp::Config(info) = op {
                            Some((
                                item.l1_slot.into_inner(),
                                finality::config_key_bytes(&info.config),
                            ))
                        } else {
                            None
                        }
                    })
                });
                config_index.extend_final(config_keys, checkpoint.lib_slot.into_inner());
                self.on_blocks_processed(checkpoint, channel_update, finalized)
                    .await?;
                self.publish_live_config().await
            }
            Event::TurnNotification { notification } => {
                info!(
                    our_turn = notification.our_turn_to_write,
                    starting_slot = notification.starting_slot,
                    ends_at_slot = notification.ends_at_slot,
                    "Turn update"
                );

                self.publish(
                    "turn",
                    PublisherEvent::Turn {
                        our_turn_to_write: notification.our_turn_to_write,
                        starting_slot: notification.starting_slot.map(Slot::from),
                    },
                )
                .await
            }
            Event::Ready => self.publish_live_config().await,
        }
    }

    /// Publishes the channel update one processed L1 block carries.
    async fn on_blocks_processed(
        &mut self,
        checkpoint: SequencerCheckpoint,
        channel_update: SdkChannelUpdate,
        finalized: Vec<FinalizedTx>,
    ) -> Result<()> {
        let finalized: Vec<_> = finalized
            .into_iter()
            .filter(|tx| self.replayed_up_to.is_none_or(|up_to| tx.l1_slot > up_to))
            .collect();

        // An L1 block that moved nothing on this channel the consumer has not seen: it only
        // advances the checkpoint.
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
        let mut undecodable = Vec::new();
        let mut finalized_signers = Vec::new();
        for (slot, op) in finalized
            .into_iter()
            .flat_map(|item| item.ops.into_iter().map(move |op| (item.l1_slot, op)))
        {
            match op {
                FinalizedOp::Inscription(inscription) => {
                    let entry = channel_entry(&inscription, Some(slot.into_inner()));
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
                // None carries a block or an author the LEZ chain models; deposits and
                // withdrawals move their holders' own notes.
                FinalizedOp::Deposit(_)
                | FinalizedOp::Withdraw(_)
                | FinalizedOp::Config(_)
                | FinalizedOp::ProgramRegister(_) => {}
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
                    event: ChannelEventKind::Publisher(Arc::new(event)),
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
        configuration_threshold: NonZero<u16>,
    ) -> Result<PublishOutcome> {
        let own_key = self.channel_signing_key.public_key();
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
        )?;

        let inscription = block_inscription(&self.node, &genesis).await?;
        // A config moves the config tip only, so the first block chains on the root.
        let inscribe_op = InscriptionOp {
            channel_id: self.channel_id,
            inscription,
            parent: MsgId::root(),
            signer: own_key.into_unverified(),
            mini_blocks: MiniBlocks::default(),
        };
        let msg_id = inscribe_op.id();

        // Registering a program already registered has no effect, so every zone can do it.
        let funded = self
            .fund_ops([
                Op::ProgramRegister(ProgramRegisterOp {
                    verification_key: vault_key(),
                }),
                Op::ChannelConfig(config_op),
                Op::ChannelInscribe(inscribe_op),
            ])
            .await?;
        let mantle_tx = funded.funded_tx;

        let signature = self
            .channel_signing_key
            .sign_payload(mantle_tx.hash().as_signing_bytes().as_ref());

        let mut op_proofs = OpProofs::from([OpProof::None(NoOpProof)]);
        for proof in [
            OpProof::ChannelMultiSigProof(genesis_config_proof()),
            OpProof::ChannelInscribe(ChannelInscribeProof::without_steps(signature)),
        ] {
            op_proofs
                .try_push(proof)
                .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        }
        if let Some(transfer_proof) = funded.transfer_proof {
            op_proofs
                .try_push(transfer_proof)
                .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        }

        info!(
            accredited_keys = key_count,
            vault_program = %*VAULT_PROGRAM,
            "Creating the channel, genesis block and vault program registration bundled"
        );

        let tx = SignedOps::from_parts(mantle_tx, op_proofs)?;
        self.submit_tx(tx, msg_id, MsgId::root())
    }

    pub async fn publish_block(
        &mut self,
        block: Block,
        parent: Option<MsgId>,
        expected_seq: Option<ChannelSeq>,
        bridge: BridgeMoves,
    ) -> Result<PublishOutcome> {
        self.check_seq(expected_seq)?;
        let inscription = block_inscription(&self.node, &block).await?;
        let data_byte_size = inscription.len();

        let published = if let Some(parent) = parent {
            let (inscribe_op, step_proofs) = if bridge.is_empty() {
                (self.inscription_op(inscription, parent), Vec::new())
            } else {
                self.vault_inscription(inscription, parent, &bridge).await?
            };
            let msg_id = inscribe_op.id();
            let funded = self.fund_ops([Op::ChannelInscribe(inscribe_op)]).await?;
            self.check_backlog(expected_seq)?;

            self.sign_and_submit(
                funded.funded_tx,
                msg_id,
                parent,
                step_proofs,
                funded.transfer_proof,
            )
        } else if !bridge.is_empty() {
            Err(Error::InvalidVaultStep(
                "a block moving funds through the bridge names its parent",
            ))
        } else {
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
            })
        };
        if published.is_ok() {
            info!(
                block_id = block.header.block_id,
                size_bytes = data_byte_size,
                "Published block"
            );
        }
        published
    }

    pub async fn prepare_config(
        &mut self,
        keys: Vec<Ed25519PublicKey>,
        posting_timeframe: u32,
        posting_timeout: u32,
        configuration_threshold: NonZero<u16>,
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
                configuration_threshold.get(),
            )
            .await?;
        let accredited_keys = verified_keys(&prepared.accredited_keys)?;

        Ok(PreparedConfig::new(prepared, accredited_keys))
    }

    pub fn change_channel_config(
        &mut self,
        prepared: PreparedConfig,
        signatures: IndexedSignatures,
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
        let inscription = checked_inscription(&self.node, data).await?;

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
        })
    }

    fn submit_tx(
        &mut self,
        tx: SignedOps<
            logos_blockchain_zone_sdk::node_types::Unverified,
            logos_blockchain_zone_sdk::core::mantle::ledger::verification_mode::StandardMode,
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
        })
    }

    /// Refuses a publish built on a channel sequence other than the current one.
    fn check_seq(&self, expected_seq: Option<ChannelSeq>) -> Result<()> {
        if let Some(expected) = expected_seq
            && expected != self.seq
        {
            return Err(Error::ChannelMoved {
                provided: expected,
                current: self.seq,
            });
        }

        Ok(())
    }

    /// The inscription of `data` on `parent` carrying the vault's program step for `bridge`,
    /// with the proofs of its steps.
    /// Checks a deposit its holder submitted for this channel's vault.
    pub fn admit_deposit(&self, deposit: &[u8]) -> Result<VaultMint> {
        let committee = Self::committee(&self.vault_signing_key());
        let admitted = VaultDeposit::admit(deposit, &self.channel_id, &committee)?;
        VaultMint::of(&admitted.deposit).ok_or(Error::InvalidVaultDeposit("it spends no note"))
    }

    fn vault_signing_key(&self) -> SigningKey {
        SigningKey::from_channel_seed(self.channel_signing_key.clone().into_unsecured().as_bytes())
    }

    // FIXME: the committee is this sequencer alone until the sequencer set shares one.
    fn committee(signing_key: &SigningKey) -> Committee {
        Committee {
            threshold: 1,
            signers: vec![signing_key.public_key()],
        }
    }

    async fn vault_inscription(
        &mut self,
        data: Inscription,
        parent: MsgId,
        bridge: &BridgeMoves,
    ) -> Result<(InscriptionOp, Vec<StepProof>)> {
        let signing_key = self.vault_signing_key();
        let committee = Self::committee(&signing_key);
        let deposits = bridge
            .deposits
            .iter()
            .map(|deposit| VaultDeposit::admit(deposit, &self.channel_id, &committee))
            .collect::<Result<Vec<_>>>()?;
        let payouts: Vec<_> = bridge
            .payouts
            .iter()
            .map(|(value, key)| (*value, ZkPublicKey::new(PublicInputs::op_id_element(key))))
            .collect();
        let vault = VaultStep {
            inputs: self.vault_inputs(&committee, &deposits, &payouts)?,
            committee,
            deposits,
            payouts,
        };

        let inscription = self
            .sequencer
            .handle()
            .prepare_program_inscription(data, vec![vault.mini_block()?])
            .map_err(|err| Error::VaultStepRefused(err.into()))?;
        // zone-sdk chains on its own publish tip, the caller on the view it applied.
        if inscription.op.parent != parent {
            return Err(Error::InvalidVaultStep(
                "its inscription is not on the parent the block was built on",
            ));
        }
        let draft = inscription
            .program_steps()
            .next()
            .cloned()
            .ok_or(Error::InvalidVaultStep(
                "its inscription has no program step",
            ))?;
        let signature = signing_key.sign(&VaultStep::public_inputs(&draft));

        // Proving takes seconds: off the actor's thread, and with zone-sdk still followed.
        let proving =
            tokio::task::spawn_blocking(move || vault.prove(&draft, vec![Some(signature)]));
        let proofs = self
            .following(proving)
            .await
            .map_err(|err| Error::VaultProofFailed(err.into()))??;
        let step_proofs = inscription
            .step_proofs(vec![proofs])
            .map_err(|err| Error::VaultStepRefused(err.into()))?;
        Ok((inscription.op, step_proofs))
    }

    /// The spendable vault notes of `committee` a step consumes to pay `payouts`, the largest
    /// first. A step that pays nothing out consumes none.
    fn vault_inputs(
        &mut self,
        committee: &Committee,
        deposits: &[VaultDeposit],
        payouts: &[(u64, ZkPublicKey)],
    ) -> Result<Vec<VaultNote>> {
        let overflows = Error::InvalidVaultStep("the value it moves overflows");
        let Some(owed) = payouts
            .iter()
            .try_fold(0_u64, |owed, (value, _)| owed.checked_add(*value))
        else {
            return Err(overflows);
        };
        let Some(mut held) = deposits.iter().try_fold(0_u64, |held, deposit| {
            held.checked_add(deposit.deposit.value)
        }) else {
            return Err(overflows);
        };

        let committee = committee.id();
        let view = self.sequencer.handle().program_notes();
        let mut spendable: Vec<_> = view
            .finalized
            .iter()
            .chain(&view.unfinalized)
            .filter(|note| note.program == *VAULT_PROGRAM && note.opening.data == committee)
            .collect();
        spendable.sort_unstable_by_key(|note| std::cmp::Reverse(note.opening.value));

        let mut inputs = Vec::new();
        for note in spendable {
            if held >= owed || inputs.len() == vault_circuit::MAX_INPUTS {
                break;
            }
            held = held.saturating_add(note.opening.value);
            inputs.push(VaultNote {
                commitment: note.commitment,
                opening: note.opening,
            });
        }
        if held < owed {
            return Err(Error::InvalidVaultStep(
                "its spendable notes do not cover its payouts",
            ));
        }
        Ok(inputs)
    }

    /// Awaits `task` with zone-sdk still followed: the events it raises meanwhile are queued
    /// for [`Self::next_event`].
    #[expect(
        clippy::integer_division_remainder_used,
        reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
    )]
    async fn following<T>(&mut self, task: impl Future<Output = T>) -> T {
        tokio::pin!(task);
        loop {
            tokio::select! {
                biased;
                done = &mut task => break done,
                event = self.sequencer.next_event() => self.backlog.push_back(event),
            }
        }
    }

    /// Refuses a publish when the channel moved while the node funded it. The queued events
    /// reach the consumer after the publish would, with checkpoints taken before it, so the
    /// block has to be rebuilt on the view they leave.
    fn check_backlog(&self, expected_seq: Option<ChannelSeq>) -> Result<()> {
        let current = self
            .backlog
            .iter()
            .filter(|event| self.moves_channel(event))
            .fold(self.seq, |seq, _| seq.next());
        if current == self.seq {
            return Ok(());
        }
        Err(Error::ChannelMoved {
            provided: expected_seq.unwrap_or(self.seq),
            current,
        })
    }

    /// Whether [`Self::on_blocks_processed`] will hand `event` on under a new channel sequence.
    fn moves_channel(&self, event: &Event) -> bool {
        let Event::BlocksProcessed {
            channel_update,
            finalized,
            ..
        } = event
        else {
            return false;
        };
        !matches!(channel_update, SdkChannelUpdate::Extension { adopted } if adopted.is_empty())
            || finalized
                .iter()
                .any(|tx| self.replayed_up_to.is_none_or(|up_to| tx.l1_slot > up_to))
    }

    /// This node's inscription of `inscription` chained on `parent`.
    fn inscription_op(&self, inscription: Inscription, parent: MsgId) -> InscriptionOp {
        InscriptionOp {
            channel_id: self.channel_id,
            inscription,
            parent,
            signer: self.channel_signing_key.public_key().into_unverified(),
            mini_blocks: MiniBlocks::default(),
        }
    }

    /// Signs the inscription leading `tx` and submits it with the proofs of
    /// the ops after it, in op order.
    fn sign_and_submit(
        &mut self,
        tx: Ops,
        msg_id: MsgId,
        parent: MsgId,
        step_proofs: Vec<StepProof>,
        proofs: impl IntoIterator<Item = OpProof>,
    ) -> Result<PublishOutcome> {
        let signature = self
            .channel_signing_key
            .sign_payload(tx.hash().as_signing_bytes().as_ref());
        let mut op_proofs = OpProofs::from([OpProof::ChannelInscribe(ChannelInscribeProof::new(
            signature,
            step_proofs,
        ))]);
        for proof in proofs {
            op_proofs
                .try_push(proof)
                .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        }

        let tx = SignedOps::from_parts(tx, op_proofs)?;
        self.submit_tx(tx, msg_id, parent)
    }

    /// Bumps the channel sequence and hands back the new one.
    const fn next_seq(&mut self) -> ChannelSeq {
        self.seq = self.seq.next();
        self.seq
    }

    /// Funds `ops` from the node's wallet, which appends a fee transfer (paid from
    /// `funding_pk`, change back to it) and returns its proof.
    ///
    /// A timed-out call can leave the node's wallet holding its funding-note
    /// reservation until `pending_note_expiry_blocks` releases it.
    async fn fund_ops(
        &mut self,
        ops: impl IntoIterator<Item = Op>,
    ) -> Result<WalletFundResponseBody> {
        let tx_builder = MantleTxBuilder::new()
            .extend_ops(ops)
            .map_err(|err| Error::TooManyOperationProofs(err.into()))?;
        let request = WalletFundRequestBody {
            tip: None,
            tx_builder,
            change_public_key: self.funding_pk,
            funding_public_keys: vec![self.funding_pk],
            max_tx_fee: GasCost::new(logos_blockchain_zone_sdk::core::mantle::Value::MAX),
            priority_fee_percent: self.priority_fee_percent,
        };

        // The node proves the fee transfer, which can take longer than a block interval. zone-sdk
        // keeps following the channel meanwhile: publishing back to back would otherwise leave it
        // no time to, and the channel view would freeze.
        let node = self.node.clone();
        self.following(async move { node.fund_tx(request).await })
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
    configuration_threshold: NonZero<u16>,
) -> Result<ChannelConfigOp> {
    ChannelConfigOp::new(
        channel_id,
        // The channel does not exist yet, so the config lineage starts here.
        MsgId::root(),
        keys,
        SlotTimeframe::from(channel_params.posting_timeframe),
        SlotTimeout::from(channel_params.posting_timeout),
        configuration_threshold,
    )
    .map_err(|err| Error::InvalidChannelConfig(err.into()))
}

/// The proof a channel-creating config op carries. No key is accredited before
/// creation, so Bedrock verifies against a threshold of zero and rejects the
/// whole creation tx over a proof holding any signature.
pub(super) const fn genesis_config_proof() -> ChannelMultiSigProof {
    ChannelMultiSigProof::empty()
}

/// `data` as an inscription, if it fits what an operation may carry in the era
/// of the node's current slot.
async fn checked_inscription(
    node: &TimeoutNode<NodeHttpClient>,
    data: Vec<u8>,
) -> Result<Inscription> {
    let max_op_data_size = node
        .limits()
        .await
        .context("Failed to fetch the node's limits")
        .map_err(Error::NodeRequestFailed)?
        .max_op_data_size;
    if u32::try_from(data.len()).map_or(true, |len| len > max_op_data_size) {
        return Err(Error::InscriptionTooLarge);
    }
    Ok(Inscription::new_unchecked(data))
}

/// `block` as the bytes of an inscription.
async fn block_inscription(
    node: &TimeoutNode<NodeHttpClient>,
    block: &Block,
) -> Result<Inscription> {
    let data = borsh::to_vec(block).map_err(Error::BlockEncodingFailed)?;
    checked_inscription(node, data).await
}

/// The name of the span `event` is handled in, which roots the trace of what it
/// sets off.
pub const fn span_name(event: &Event) -> &'static str {
    match event {
        Event::BlocksProcessed { .. } => "bedrock.blocks_processed",
        Event::TurnNotification { .. } => "bedrock.turn_notification",
        Event::Ready => "bedrock.ready",
    }
}

/// Whether `checkpoint` records messages published to or observed on the channel.
fn has_channel_activity(checkpoint: &SequencerCheckpoint) -> bool {
    checkpoint.last_msg_id != MsgId::root() || !checkpoint.pending_txs.is_empty()
}

/// A message-lineage entry, with its block when the payload decodes to one, in the final block at
/// `final_slot` or in the view when `None`.
fn channel_entry(inscription: &InscriptionInfo, final_slot: Option<u64>) -> ChannelEntry {
    let block = if <Inscription as AsRef<[u8]>>::as_ref(&inscription.payload).is_empty() {
        None
    } else {
        // A block minting anything but the vault's deposits is no block of this chain.
        block_from_inscription(inscription)
            .filter(|block| chain_state::vault::mints_backed(block, &inscription.steps))
    };
    ChannelEntry {
        msg: inscription.this_msg,
        parent: inscription.parent_msg,
        block,
        finally_absent_keys: BTreeSet::new(),
        final_slot,
    }
}

/// Every message-lineage entry a channel tx carries, in op order.
///
/// A config op is on the config lineage, not this one, so it is skipped.
pub(super) fn channel_entries(tx: &ChannelUpdateTx, channel_id: ChannelId) -> Vec<ChannelEntry> {
    match tx {
        ChannelUpdateTx::Inscription(info) => vec![channel_entry(info, None)],
        ChannelUpdateTx::Config(_) => Vec::new(),
        ChannelUpdateTx::Custom(signed_tx) => {
            logos_blockchain_zone_sdk::sequencer::channel_inscriptions(signed_tx, channel_id)
                .iter()
                .map(|info| channel_entry(info, None))
                .collect()
        }
    }
}
