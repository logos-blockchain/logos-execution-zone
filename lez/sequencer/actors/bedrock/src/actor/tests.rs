use std::{collections::HashMap, num::NonZero, time::Duration};

use common::{
    HashType,
    block::{Block, HashableBlockData},
};
use kameo::{
    Actor,
    actor::{ActorRef, Spawn as _},
    error::SendError,
    message::{Context, Message},
    request::PendingReply,
};
use logos_blockchain_zone_sdk::{
    Slot,
    core::{
        era::ForkDigest,
        mantle::{
            SignedOps,
            channel::Channels,
            ledger::{VerifiableOperation as _, verification_mode::StandardMode},
            ops::{
                Op, OpProof, SignedOperation,
                channel::{
                    ChannelId, MsgId, VerifiedChannelKeys,
                    config::ChannelConfigValidationContext,
                    inscribe::{Inscription, InscriptionOp},
                },
            },
            transactions::{
                MantleTxBuilder, OpProofs,
                hash::{TxHash, TxHashView},
                states::Unverified,
            },
        },
    },
    key_management_system_service::keys::{Ed25519Key, ZkPublicKey},
    node_types::HeaderId,
    sequencer::{ChannelUpdateTx, SequencerCheckpoint},
};
use sequencer_storage_actor::mock::MockStorageActor;
use tokio::sync::mpsc;

use super::{
    Args, BedrockActor, BlockSummary, NodeReader,
    channel::{self, channel_entries, genesis_config_op, genesis_config_proof},
    keep_newest_block_summaries,
};
use crate::{
    Result,
    error::Error,
    protocol::{
        ChannelEvent, ChannelEventFailed, ChannelEventKind, ChannelParams, ChannelUpdate,
        FollowChannel, PublishBlock, PublishOutcome, ViewChange,
    },
};

type TestBedrockActor = BedrockActor<MockStorageActor>;

/// Turns the followed channel into a publishing one, without waiting for zone-sdk to be ready.
struct StartPublishing;

impl Message<StartPublishing> for TestBedrockActor {
    type Reply = ();

    async fn handle(&mut self, _msg: StartPublishing, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(channel::Channel::Followed(followed)) = self.channel.take() else {
            panic!("the channel is followed");
        };
        self.channel = Some(channel::Channel::Publishing(followed.into_publishing(
            channel::PublishConfig {
                channel_signing_key: Ed25519Key::from_bytes(&[7; 32]),
                funding_pk: ZkPublicKey::zero(),
                priority_fee_percent: 0,
                resubmit_interval: Duration::from_secs(5),
                stale_refund_slots: 0,
            },
        )));
    }
}

/// Queues an empty update for the follower, as if zone-sdk reported one.
struct QueueUpdate;

impl Message<QueueUpdate> for TestBedrockActor {
    type Reply = ();

    async fn handle(&mut self, _msg: QueueUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        let update = ChannelUpdate {
            lib_slot: Slot::from(0),
            finalized_config: MsgId::root(),
            view: ViewChange::Extension(Vec::new()),
            finalized: Vec::new(),
            deposits: Vec::new(),
            pending_deposits: Vec::new(),
            withdrawals: Vec::new(),
            undecodable: Vec::new(),
            finalized_signers: Vec::new(),
        };
        let checkpoint = SequencerCheckpoint {
            last_msg_id: MsgId::root(),
            pending_txs: Vec::new(),
            lib: HeaderId::from([0; 32]),
            lib_slot: Slot::from(0),
            channel_notes: Vec::new(),
            finalized_config: MsgId::root(),
            funding: Vec::new(),
        };
        self.deliveries.push_update(update, checkpoint);
    }
}

/// A follower that, asked an update, puts a publish in the Bedrock actor's mailbox before it
/// replies, and hands the publish's pending reply to the test.
#[derive(Actor)]
struct PublishingFollower {
    bedrock: ActorRef<TestBedrockActor>,
    channel_id: ChannelId,
    publishes: mpsc::UnboundedSender<PendingReply<PublishBlock, Result<PublishOutcome>>>,
}

impl Message<ChannelEvent> for PublishingFollower {
    type Reply = std::result::Result<(), ChannelEventFailed>;

    async fn handle(
        &mut self,
        msg: ChannelEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if !matches!(msg.event, ChannelEventKind::Update(_)) {
            return Ok(());
        }
        let publish = self
            .bedrock
            .ask(PublishBlock {
                channel_id: self.channel_id,
                block: common::test_utils::produce_dummy_block(1, None, vec![]),
                withdrawals: Vec::new(),
                parent: None,
            })
            .enqueue()
            .await
            .expect("the Bedrock actor is running");
        self.publishes.send(publish).expect("the test is listening");
        Ok(())
    }
}

/// A tx wrapping `block` in one inscribe op on `channel`.
fn inscribing_tx(channel: ChannelId, block: &Block) -> SignedOps<Unverified, StandardMode> {
    let inscription = Inscription::new_unchecked(borsh::to_vec(block).expect("serialize"));
    let signer = Ed25519Key::generate(&mut rand::rngs::OsRng);
    let op = Op::ChannelInscribe(InscriptionOp {
        channel_id: channel,
        inscription,
        parent: MsgId::root(),
        signer: signer.public_key().into_unverified(),
    });
    let raw = MantleTxBuilder::new()
        .extend_ops([op])
        .expect("ops fit")
        .build(ForkDigest::new([0; 32]))
        .expect("tx builds");
    // Extraction never checks the proof, only that there is one per op.
    let proof = OpProof::Ed25519Sig(signer.sign_payload(&[0; 32]));
    SignedOps::from_parts(raw, OpProofs::from([proof])).expect("one proof per op")
}

#[test]
fn a_custom_tx_yields_its_block() {
    let channel = ChannelId::from([1; 32]);
    let block = HashableBlockData {
        receipts: Vec::new(),
        block_id: 7,
        prev_block_hash: HashType([0; 32]),
        timestamp: 700,
        transactions: Vec::new(),
    }
    .into_pending_block();

    let custom = ChannelUpdateTx::Custom(inscribing_tx(channel, &block));
    let entries = channel_entries(&custom, channel);

    assert_eq!(entries.len(), 1, "the Custom tx carries one entry");
    let carried = entries[0]
        .block
        .as_ref()
        .expect("the entry carries a block");
    assert_eq!(carried.header.block_id, 7);
    assert_eq!(carried.header.hash, block.header.hash);
}

#[test]
fn a_config_tx_yields_nothing() {
    let channel = ChannelId::from([1; 32]);
    let raw = MantleTxBuilder::new()
        .build(ForkDigest::new([0; 32]))
        .expect("tx builds");
    let config = ChannelUpdateTx::Config(
        SignedOps::from_parts(raw, OpProofs::empty()).expect("no ops, no proofs"),
    );
    assert!(channel_entries(&config, channel).is_empty());
}

/// Bedrock verifies a channel-creating config op against a threshold of zero,
/// so the op we build must pass with the proof we pair it with. A proof holding
/// even our own signature sinks the whole creation tx, and with it the channel.
#[test]
fn the_genesis_config_op_and_its_proof_pass_bedrock_verification() {
    let keys = VerifiedChannelKeys::from(Ed25519Key::generate(&mut rand::rngs::OsRng).public_key());
    let op = genesis_config_op(
        ChannelId::from([1; 32]),
        keys,
        &ChannelParams {
            minimum_sequencer_stake: 0,
            posting_timeframe: 10,
            posting_timeout: 20,
            max_block_size: 1 << 20,
            finality_depth: 5,
        },
        NonZero::<u16>::MIN,
        NonZero::<u16>::MIN,
    )
    .expect("a one-key channel with thresholds of one is valid");
    let tx_hash_view = TxHashView::new(TxHash::from([7; 32]));

    let signed = SignedOperation::<_, Unverified, StandardMode>::new(op, genesis_config_proof())
        .into_preverified(&())
        .expect("the config is well formed");

    signed
        .verify(&ChannelConfigValidationContext {
            // An empty ledger: the channel this op creates does not exist yet.
            channels: &Channels::new(),
            tx_hash_view: &tx_hash_view,
        })
        .expect("Bedrock accepts the channel-creating config op");
}

#[test]
fn a_full_cache_keeps_the_newest_block_summaries_by_slot() {
    let summary = |n: u64, slot: u64| {
        let mut id = [0_u8; 32];
        id[..8].copy_from_slice(&n.to_le_bytes());
        BlockSummary {
            id: HeaderId::from(id),
            parent: HeaderId::from([0; 32]),
            slot,
            inscription_msgs: Vec::new(),
            config_keys: Vec::new(),
        }
    };
    let capacity = u64::try_from(NodeReader::CACHE_CAPACITY).unwrap();
    let cutoff = capacity.saturating_sub(u64::try_from(NodeReader::CACHE_KEPT).unwrap());
    // One block per slot, plus a fork block at the cutoff slot.
    let mut cache: HashMap<_, _> = (0..capacity)
        .map(|slot| summary(slot, slot))
        .chain([summary(capacity, cutoff)])
        .map(|block_summary| (block_summary.id, block_summary))
        .collect();

    keep_newest_block_summaries(&mut cache);

    assert_eq!(
        cache.len(),
        NodeReader::CACHE_KEPT.saturating_add(1),
        "the newest summaries and the fork block at the cutoff slot should be kept"
    );
    assert!(
        cache
            .values()
            .all(|block_summary| block_summary.slot >= cutoff)
    );
}

/// The follower publishes only after it replied to the update, so the publish must not be refused
/// for that update, even when the reply and the publish reach the Bedrock actor together.
#[tokio::test]
async fn a_publish_sent_after_applying_an_update_is_not_refused_for_it() {
    let mut storage = MockStorageActor::default();
    storage
        .expect_handle_get_zone_checkpoint()
        .returning(|_msg, _ctx| Ok(None));
    storage
        .expect_handle_put_final_configs_bytes()
        .returning(|_msg, _ctx| Ok(()));
    storage
        .expect_handle_update_zone_checkpoint()
        .returning(|_msg, _ctx| Ok(()));

    let channel_id = ChannelId::from([1; 32]);
    // Nothing listens there, so a publish that is not refused fails reaching the node.
    let bedrock = TestBedrockActor::spawn(Args {
        node_url: "http://127.0.0.1:1".parse().expect("a valid URL"),
        basic_auth: None,
        channel_id,
        backfill_batch_slots: NonZero::new(100).expect("not zero"),
        storage_ref: MockStorageActor::spawn(storage),
    });
    let (publishes_tx, mut publishes) = mpsc::unbounded_channel();
    let follower = PublishingFollower::spawn(PublishingFollower {
        bedrock: bedrock.clone(),
        channel_id,
        publishes: publishes_tx,
    });
    bedrock
        .ask(FollowChannel {
            channel_id,
            recipient: follower.reply_recipient(),
        })
        .await
        .expect("the channel is followed");
    bedrock
        .ask(StartPublishing)
        .await
        .expect("the channel publishes");

    // Which of two ready inputs an unbiased select takes is random, so a single round could pass
    // by luck.
    for _ in 0..16 {
        bedrock
            .ask(QueueUpdate)
            .await
            .expect("the update is queued");
        let publish = publishes
            .recv()
            .await
            .expect("the follower publishes on every update");
        let err = publish.await.expect_err("the node is unreachable");
        assert!(
            matches!(err, SendError::HandlerError(Error::NodeRequestFailed(_))),
            "the publish must pass the moved check and only fail reaching the node, got {err:?}"
        );
    }
}
