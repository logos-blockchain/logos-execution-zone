use std::time::Duration;

use anyhow::Context as _;
use common::block::Block;
use kameo::actor::ActorRef;
use kameo_actors::broker::Broker;
use log::info;
use logos_blockchain_core::{
    mantle::{
        Op, OpProof, SignedMantleTx,
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
    Ed25519PublicKey,
    adapter::{Node as _, NodeHttpClient},
    node_types::{Inscription, Unverified, WalletFundRequestBody, WalletFundResponseBody},
    sequencer::{
        Event, FinalizedOp, FundingConfig, SequencerCheckpoint, SequencerConfig, WithdrawInputs,
        ZoneSequencer,
    },
};
use sequencer_actors_common::SendErrorExt as _;
use sequencer_stake_core::ChannelParams;

use crate::{
    Result,
    actor::{block_from_inscription, channel_blocks, released_notes},
    error::Error,
    protocol::{
        ChannelEvent, ChannelEventKind, ChannelId, ChannelUpdate, Ed25519Key, MsgId,
        PublishOutcome, PublisherEvent, WithdrawArg, ZkPublicKey,
    },
};

pub struct Publisher {
    node: NodeHttpClient,
    sequencer: ZoneSequencer<NodeHttpClient>,
    bedrock_signing_key: Ed25519Key,
    funding_pk: ZkPublicKey,
    priority_fee_percent: u64,
}

impl Publisher {
    pub async fn new(
        node: NodeHttpClient,
        channel_id: ChannelId,
        bedrock_signing_key: Ed25519Key,
        funding_pk: ZkPublicKey,
        priority_fee_percent: u64,
        initial_checkpoint: Option<SequencerCheckpoint>,
        resubmit_interval: Duration,
    ) -> Result<Self> {
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

        let mut sequencer = ZoneSequencer::init_with_config(
            channel_id,
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
            node,
            sequencer,
            bedrock_signing_key,
            funding_pk,
            priority_fee_percent,
        })
    }

    pub async fn step(
        &mut self,
        channel_id: ChannelId,
        broker_ref: &ActorRef<Broker<ChannelEvent>>,
    ) -> Result<()> {
        let event = self.sequencer.next_event().await;

        match event {
            Event::BlocksProcessed {
                checkpoint,
                channel_update,
                finalized,
            } => {
                let adopted = channel_update
                    .adopted
                    .iter()
                    .flat_map(|tx| channel_blocks(tx, channel_id))
                    .collect();
                let orphaned = channel_update
                    .orphaned
                    .iter()
                    .flat_map(|tx| channel_blocks(tx, channel_id))
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

                broker_ref
                    .tell(kameo_actors::broker::Publish {
                        topic: format!("channel/{channel_id}/publisher/update"),
                        message: ChannelEvent {
                            channel_id,
                            event: ChannelEventKind::Publisher(PublisherEvent::Update(Box::new(
                                ChannelUpdate {
                                    checkpoint,
                                    adopted,
                                    orphaned,
                                    finalized: finalized_blocks,
                                    deposits,
                                    withdrawals,
                                    undecodable,
                                },
                            ))),
                        },
                    })
                    .await
                    .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
            }
            Event::TurnNotification { notification } => {
                // TODO: This event is never emitted currently due to a bug in zone sdk.
                // However I hope that when this PR will be ready the bug will be fixed.
                info!(
                    "Turn update: our_turn={}, starting_slot={:?}, ends_at_slot={:?}",
                    notification.our_turn_to_write,
                    notification.starting_slot,
                    notification.ends_at_slot
                );

                broker_ref
                    .tell(kameo_actors::broker::Publish {
                        topic: format!("channel/{channel_id}/publisher/turn"),
                        message: ChannelEvent {
                            channel_id,
                            event: ChannelEventKind::Publisher(PublisherEvent::Turn {
                                our_turn_to_write: notification.our_turn_to_write,
                            }),
                        },
                    })
                    .await
                    .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
            }
            Event::Ready | Event::MempoolPending(_) => Ok(()),
        }
    }

    pub async fn create_channel(
        &mut self,
        channel_id: ChannelId,
        genesis: Block,
        keys: Vec<Ed25519PublicKey>,
        channel_params: ChannelParams,
    ) -> Result<PublishOutcome> {
        let own_key = self.bedrock_signing_key.public_key();
        if keys.first() != Some(&own_key) {
            return Err(Error::ChannelCreationRequiresOurKey);
        }

        let key_count = keys.len();
        let keys = Keys::try_from(keys).map_err(|err| Error::InvalidChannelKeyList(err.into()))?;

        let config_op = ChannelConfigOp {
            channel: channel_id,
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
            channel_id,
            inscription,
            parent: MsgId::root(),
            signer: own_key,
        };
        let msg_id = inscribe_op.id();

        let funded = fund_ops(
            &self.node,
            self.funding_pk,
            self.priority_fee_percent,
            [
                Op::ChannelConfig(config_op),
                Op::ChannelInscribe(inscribe_op),
            ],
        )
        .await?;
        let mantle_tx = funded.funded_tx;

        let signature = self
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

    pub async fn publish_block(
        &mut self,
        channel_id: ChannelId,
        block: Block,
        withdrawals: Vec<WithdrawArg>,
        parent: Option<MsgId>,
    ) -> Result<PublishOutcome> {
        let data = borsh::to_vec(&block).map_err(Error::BlockEncodingFailed)?;
        let inscription: Inscription = data.try_into().map_err(|_err| Error::BlockTooLarge)?;

        if let Some(parent) = parent {
            if !withdrawals.is_empty() {
                return Err(Error::CannotPublishBlockOnParentWithWithdrawals);
            }

            let inscribe_op = InscriptionOp {
                channel_id,
                inscription,
                parent,
                signer: self.bedrock_signing_key.public_key(),
            };

            let msg_id = inscribe_op.id();

            let funded = fund_ops(
                &self.node,
                self.funding_pk,
                self.priority_fee_percent,
                [Op::ChannelInscribe(inscribe_op)],
            )
            .await?;
            let mantle_tx = funded.funded_tx;

            let signature = self
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

    pub async fn change_channel_config(
        &mut self,
        new_keys: Vec<Ed25519PublicKey>,
        posting_timeframe: u32,
        posting_timeout: u32,
        configuration_threshold: u16,
        transfer_threshold: u16,
    ) -> Result<()> {
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
            checkpoint,
            released_notes: released_notes(&result.tx),
        })
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

/// Funds `ops` from the node's wallet, which appends a fee transfer (paid from
/// `funding_key`, change back to it) and returns its proof.
async fn fund_ops(
    node: &NodeHttpClient,
    funding_pk: ZkPublicKey,
    priority_fee_percent: u64,
    ops: impl IntoIterator<Item = Op>,
) -> Result<WalletFundResponseBody> {
    let tx_builder = MantleTxBuilder::new().extend_ops(ops)?;
    node.fund_tx(WalletFundRequestBody {
        tip: None,
        tx_builder,
        change_public_key: funding_pk,
        funding_public_keys: vec![funding_pk],
        max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
        priority_fee_percent,
    })
    .await
    .context("Failed to fund channel transaction")
    .map_err(Error::NodeRequestFailed)
}

/// Whether `checkpoint` records messages published to or observed on the channel.
fn has_channel_activity(checkpoint: &SequencerCheckpoint) -> bool {
    checkpoint.last_msg_id != MsgId::root() || !checkpoint.pending_txs.is_empty()
}
