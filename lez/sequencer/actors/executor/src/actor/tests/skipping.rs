//! A producer's turn while the head cannot execute the block past its tip.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use chain_state::{ChannelEntry, ProofStore};
use common::{
    HashType,
    block::{Block, BlockMeta, HashableBlockData},
    test_utils::produce_dummy_block,
    transaction::LeeTransaction,
};
use kameo::actor::{ActorRef, Spawn as _};
use lee::privacy_preserving_transaction::{Message, WitnessSet, circuit::Proof};
use sequencer_bedrock_actor::{
    mock::MockBedrockActor,
    protocol::{
        ChannelEvent, ChannelEventKind, ChannelSeq, ChannelUpdate, Checkpoint, HeaderId, MsgId,
        PublishOutcome, PublisherEvent, Slot, ViewChange,
    },
};
use sequencer_slasher_actor::protocol::{Approval, SetApprovalPublisher};
use sequencer_stake_core::ed25519_dalek::SigningKey;
use sequencer_storage_actor::mock::{CannedStore, MockStorageActor, SharedStore};
use tempfile::TempDir;
use tokio::{sync::mpsc, test};

use super::{
    empty_genesis, executor_args, mock_channel_params, prepare_mock_bedrock_on_genesis,
    spawn_bedrock_pool, stake_entries, stake_state, staked_sequencer_config,
};
use crate::{
    ExecutorActor,
    protocol::{ChannelId, ProduceBlock},
};

/// Slots after a private block within which another writer may skip it.
const SKIP_WINDOW: u32 = 10;
/// Two slots, so a producer waits one second for a missing proof.
const POSTING_TIMEOUT: u32 = 2;
/// The slot the block past the head tip finalized in.
const BLOCKER_SLOT: u64 = 5;
/// The hash the mock store gives genesis.
const GENESIS: HashType = HashType([0; 32]);

/// An executor on its turn, over a genesis that sets [`SKIP_WINDOW`] and [`POSTING_TIMEOUT`],
/// with the blocks it publishes, the store it settles them into and the offences it reports.
struct Producer {
    executor: ActorRef<ExecutorActor<MockStorageActor, MockBedrockActor>>,
    channel_id: ChannelId,
    proofs: ProofStore,
    published: mpsc::UnboundedReceiver<Block>,
    store: SharedStore,
    approvals: mpsc::Receiver<Approval>,
    own: [u8; 32],
    _home: TempDir,
}

impl Producer {
    async fn start() -> Self {
        let (mut config, home, sequencer_key) = staked_sequencer_config();
        config.block_create_timeout = Duration::from_secs(1);
        let state = stake_state(
            stake_entries(sequencer_key),
            sequencer_stake_core::ChannelParams {
                posting_timeout: POSTING_TIMEOUT,
                skip_window: SKIP_WINDOW,
                ..mock_channel_params()
            },
        );
        let genesis = empty_genesis();
        let store = CannedStore {
            final_snapshot: Some((state.clone(), BlockMeta::from(&genesis))),
            head_state: Some(state),
            blocks: BTreeMap::from([(genesis.header.block_id, genesis)]),
            ..CannedStore::default()
        }
        .share();

        let (published_tx, published) = mpsc::unbounded_channel();
        let args = Box::pin(executor_args(
            config,
            MockStorageActor::spawn(store.mock()),
            spawn_bedrock_pool(move |channel_id| {
                let mut bedrock = prepare_mock_bedrock_on_genesis(channel_id);
                bedrock
                    .expect_handle_get_accredited_keys()
                    .returning(|_msg, _ctx| Ok(None));
                let published_tx = published_tx.clone();
                bedrock
                    .expect_handle_publish_block()
                    .returning(move |msg, _ctx| {
                        let this_msg = MsgId::from(msg.block.header.hash.0);
                        let parent = msg.parent.unwrap_or_else(MsgId::root);
                        published_tx
                            .send(msg.block)
                            .expect("the test still listens");
                        Ok(PublishOutcome {
                            this_msg,
                            parent,
                            checkpoint: checkpoint(0),
                            seq: ChannelSeq::mocked(0),
                            released_notes: Vec::new(),
                        })
                    });
                bedrock
            }),
        ))
        .await;
        let (approvals_tx, approvals) = mpsc::channel(8);
        args.slasher_ref
            .tell(SetApprovalPublisher(approvals_tx))
            .await
            .expect("the slasher takes a publisher");
        let proofs = args.proofs.clone();
        let channel_id = args.config.bedrock_config.channel_id;
        let executor = ExecutorActor::spawn(args);
        executor
            .wait_for_startup_with_result(|res| res.map_err(|err| format!("{err:?}")))
            .await
            .expect("the executor starts");

        Self {
            executor,
            channel_id,
            proofs,
            published,
            store,
            approvals,
            own: sequencer_key.to_bytes(),
            _home: home,
        }
    }

    async fn follow(&self, update: ChannelUpdate) {
        self.executor
            .ask(ChannelEvent {
                channel_id: self.channel_id,
                event: ChannelEventKind::Publisher(Arc::new(PublisherEvent::Update(Box::new(
                    update,
                )))),
            })
            .await
            .expect("the executor follows the channel");
    }

    /// Our turn, which Bedrock reports started at `slot`.
    async fn turn_from(&self, slot: u64) {
        self.executor
            .ask(ChannelEvent {
                channel_id: self.channel_id,
                event: ChannelEventKind::Publisher(Arc::new(PublisherEvent::Turn {
                    our_turn_to_write: true,
                    starting_slot: Some(Slot::from(slot)),
                })),
            })
            .await
            .expect("the executor takes the turn");
    }

    /// The block one production tick published, if any.
    async fn produce(&mut self) -> Option<Block> {
        self.executor
            .ask(ProduceBlock)
            .await
            .expect("a production tick replies Ok");
        self.published.try_recv().ok()
    }

    /// The inscriptions reported since the last call.
    fn reported(&mut self) -> Vec<[u8; 32]> {
        std::iter::from_fn(|| self.approvals.try_recv().ok())
            .map(|approval| approval.offence.inscription)
            .collect()
    }
}

/// The key a peer with `seed` signs its inscriptions with.
fn peer(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

/// `block`'s channel entry, chained on `parent` and signed by `signer`, final at `slot` if any.
fn entry(block: &Block, parent: MsgId, signer: [u8; 32], slot: Option<u64>) -> ChannelEntry {
    ChannelEntry {
        msg: MsgId::from(block.header.hash.0),
        parent,
        signer: Some(signer),
        slot: slot.map(Slot::from),
        block: Some(block.digested()),
    }
}

/// A channel update moving the LIB to `lib_slot`, and nothing else.
fn update(lib_slot: u64) -> ChannelUpdate {
    ChannelUpdate {
        checkpoint: checkpoint(lib_slot),
        seq: ChannelSeq::mocked(lib_slot),
        view: ViewChange::Extension(Vec::new()),
        finalized: Vec::new(),
        deposits: Vec::new(),
        withdrawals: Vec::new(),
        undecodable: Vec::new(),
    }
}

fn checkpoint(lib_slot: u64) -> Checkpoint {
    Checkpoint {
        last_msg_id: MsgId::root(),
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(lib_slot),
        channel_notes: Vec::new(),
        finalized_config: MsgId::root(),
        funding: Vec::new(),
    }
}

/// A block of one private transaction proven by `proof`, which fails once its proof is present:
/// it lacks the fee and clock tail.
fn private_block(id: u64, prev: HashType, proof: Proof) -> Block {
    HashableBlockData {
        block_id: id,
        prev_block_hash: prev,
        timestamp: id.saturating_mul(100),
        transactions: vec![LeeTransaction::PrivacyPreserving(
            lee::PrivacyPreservingTransaction::new(
                Message::default(),
                WitnessSet::from_raw_parts(Vec::new(), proof),
            ),
        )],
        reverted: Vec::new(),
    }
    .into_pending_block()
}

#[test]
async fn a_turn_builds_on_an_executed_tip_without_a_slot_estimate() {
    let mut producer = Producer::start().await;
    let tip = produce_dummy_block(2, Some(GENESIS), Vec::new());
    producer
        .follow(ChannelUpdate {
            view: ViewChange::Extension(vec![entry(&tip, MsgId::root(), peer(1), None)]),
            ..update(0)
        })
        .await;

    let built = producer
        .produce()
        .await
        .expect("nothing past an executed tip holds production");
    assert_eq!(built.header.prev_block_hash, tip.header.hash);
}

#[test]
async fn a_turn_holds_on_a_peers_private_block_missing_its_proof() {
    let mut producer = Producer::start().await;
    let blocker = private_block(2, GENESIS, Proof::from_inner(vec![1]));
    producer
        .follow(ChannelUpdate {
            finalized: vec![entry(&blocker, MsgId::root(), peer(1), Some(BLOCKER_SLOT))],
            ..update(BLOCKER_SLOT)
        })
        .await;
    producer.turn_from(BLOCKER_SLOT + 1).await;

    assert!(
        producer.produce().await.is_none(),
        "the proof may still arrive"
    );
}

#[test]
async fn a_turn_skips_a_peers_failed_private_block_without_waiting() {
    let mut producer = Producer::start().await;
    let proof = Proof::from_inner(vec![1]);
    let blocker = private_block(2, GENESIS, proof.clone());
    producer.proofs.insert(&proof);
    producer
        .follow(ChannelUpdate {
            finalized: vec![entry(&blocker, MsgId::root(), peer(1), Some(BLOCKER_SLOT))],
            ..update(BLOCKER_SLOT)
        })
        .await;
    producer.turn_from(BLOCKER_SLOT + 1).await;

    let skip = producer
        .produce()
        .await
        .expect("no proof can make a failed block valid");
    assert_eq!(skip.header.prev_block_hash, blocker.header.prev_block_hash);
}

#[test]
async fn a_turn_builds_over_a_failed_block_of_ours_past_its_window_and_the_block_settles_unreported()
 {
    let mut producer = Producer::start().await;
    let proof = Proof::from_inner(vec![1]);
    let failed = private_block(2, GENESIS, proof.clone());
    let failed_entry = entry(&failed, MsgId::root(), producer.own, Some(BLOCKER_SLOT));
    producer.proofs.insert(&proof);
    producer
        .follow(ChannelUpdate {
            finalized: vec![failed_entry.clone()],
            ..update(BLOCKER_SLOT)
        })
        .await;
    let past_the_window = BLOCKER_SLOT + u64::from(SKIP_WINDOW) + 1;
    producer.turn_from(past_the_window).await;

    let built = producer
        .produce()
        .await
        .expect("a failed block past its window holds no turn");
    assert_eq!(built.header.prev_block_hash, failed.header.prev_block_hash);
    assert_eq!(built.header.block_id, failed.header.block_id);

    producer
        .follow(ChannelUpdate {
            finalized: vec![entry(
                &built,
                failed_entry.msg,
                producer.own,
                Some(past_the_window),
            )],
            ..update(past_the_window)
        })
        .await;
    assert_eq!(
        producer
            .store
            .lock()
            .final_snapshot
            .as_ref()
            .map(|(_, tip)| tip.hash),
        Some(built.header.hash),
        "the failed block leaves before the new one is placed on its parent"
    );
    let reported = producer.reported();
    assert!(reported.contains(&failed.header.hash.0));
    assert!(!reported.contains(&built.header.hash.0));
}
