use chain_state::test_utils::{lineage, private_transfer, with_private_sender};
use lee::V03State;
use sequencer_stake_core::ChannelParams;

use super::*;
use crate::block_store::settled_test_block;

const SKIP_WINDOW: u32 = 10;
const WRITER: [u8; 32] = [1; 32];
const PEER: [u8; 32] = [2; 32];

struct Channel {
    initial: V03State,
    genesis: Block,
    plain: Block,
    private: Block,
    proof: Proof,
    on_private: Block,
}

/// The tests' blocks, over a state with a funded private sender and a skip window: a plain and
/// a private block on genesis, and a block on the private one.
fn channel() -> Channel {
    let params = ChannelParams {
        minimum_sequencer_stake: system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE,
        posting_timeframe: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
        posting_timeout: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT,
        skip_window: SKIP_WINDOW,
        exit_delay: system_accounts::DEFAULT_SEQUENCER_EXIT_DELAY,
        max_block_size: system_accounts::DEFAULT_MAX_BLOCK_SIZE,
    };
    let initial = with_private_sender(
        testnet_initial_state::initial_state(false).with_public_accounts([
            common::test_utils::producer_seed(),
            (
                system_accounts::sequencer_stake_config_account_id(),
                system_accounts::sequencer_stake_config_account(Some(params), None),
            ),
        ]),
    );
    let mut state = initial.clone();
    let genesis = settled_test_block(&mut state, 1, None, vec![]);
    let plain = settled_test_block(&mut state.clone(), 2, Some(genesis.header.hash), vec![]);
    let transfer = private_transfer(&state);
    let proof = transfer.proof().expect("a private transfer was built").clone();
    let private = settled_test_block(&mut state, 2, Some(genesis.header.hash), vec![transfer]);
    let on_private = settled_test_block(&mut state, 3, Some(private.header.hash), vec![]);
    Channel {
        initial,
        genesis,
        plain,
        private,
        proof,
        on_private,
    }
}

/// An indexer over a store seeded with `initial`, fetching proofs from `sources`.
fn indexer(
    dir: &std::path::Path,
    initial: &V03State,
    sources: Vec<SequencerClient>,
) -> IndexerCore {
    let home = dir.join(format!("rocksdb-{}", ChannelId::from([1; 32])));
    drop(storage::indexer::RocksDBIO::open_or_create(&home, initial).expect("seed the store"));
    let mut core = unreachable_core(dir);
    core.proof_sources = sources;
    core
}

/// A pass folding `entries`, which complete every slot up to `lib`, and storing what settles.
async fn pass(core: &IndexerCore, ingest: &mut Ingest, entries: &[ChannelEntry], lib: u64) {
    ingest.unserved.clear();
    let (_, step) = core.advance(ingest, entries, Slot::from(lib)).await;
    assert!(matches!(step, Step::Done));
}

fn stored_hash(core: &IndexerCore, block_id: u64) -> Option<HashType> {
    core.store
        .get_block_at_id(block_id)
        .expect("the store reads")
        .map(|block| block.header.hash)
}

async fn holding_the_proof(channel: &Channel) -> (SequencerClient, ServerHandle) {
    proof_source(HashMap::from([(
        channel.proof.digest(),
        channel.proof.clone(),
    )]))
    .await
}

#[tokio::test]
async fn a_peers_cut_private_block_is_never_stored_and_its_replacement_is() {
    let dir = tempfile::tempdir().expect("tempdir");
    let channel = channel();
    let (source, _sequencer) = holding_the_proof(&channel).await;
    let core = indexer(dir.path(), &channel.initial, vec![source]);
    let mut ingest = core.resume().expect("the fold resumes from the store");
    let entries = lineage(&[
        (&channel.genesis, WRITER, 1),
        (&channel.private, WRITER, 2),
        (&channel.plain, PEER, 3),
    ]);

    pass(&core, &mut ingest, &entries[..1], 1).await;
    pass(&core, &mut ingest, &entries[1..2], 2).await;
    assert_eq!(
        ingest.chain.head_tip(),
        Some(Tip::from(&channel.private)),
        "the private block is hydrated and executed"
    );
    assert_eq!(stored_hash(&core, 2), None);

    pass(&core, &mut ingest, &entries[2..], 3).await;
    assert_eq!(stored_hash(&core, 2), Some(channel.plain.header.hash));
}

#[tokio::test]
async fn a_block_whose_proof_no_source_holds_is_not_stored_and_the_cursor_does_not_pass_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let channel = channel();
    let mut core = indexer(dir.path(), &channel.initial, Vec::new());
    let mut ingest = core.resume().expect("the fold resumes from the store");
    let entries = lineage(&[
        (&channel.genesis, WRITER, 1),
        (&channel.private, WRITER, 2),
        (&channel.on_private, WRITER, 3),
    ]);

    pass(&core, &mut ingest, &entries[..1], 1).await;
    pass(&core, &mut ingest, &entries[1..], 3).await;
    pass(&core, &mut ingest, &[], 100).await;
    assert_eq!(stored_hash(&core, 2), None);
    assert_eq!(
        core.store.get_zone_cursor().expect("the cursor reads"),
        Some((entries[0].msg, Slot::from(1))),
        "a restart re-reads the block"
    );

    let (source, _sequencer) = holding_the_proof(&channel).await;
    core.proof_sources = vec![source];
    pass(&core, &mut ingest, &[], 100).await;
    assert_eq!(
        stored_hash(&core, 2),
        Some(channel.private.header.hash),
        "the fold held the block until a source served its proof"
    );
    assert_eq!(stored_hash(&core, 3), Some(channel.on_private.header.hash));
}
