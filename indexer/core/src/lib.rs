use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use bedrock_client::HeaderId;
use common::block::{Block, HashableBlockData};
// ToDo: Remove after testnet
use common::{HashType, PINATA_BASE58};
use log::{error, info, warn};
use logos_blockchain_zone_sdk::indexer::{Cursor, ZoneIndexer};

use crate::{block_store::IndexerStore, config::IndexerConfig};

pub mod block_store;
pub mod config;

const POLL_BATCH_LIMIT: usize = 1000;
const CURSOR_FILE_NAME: &str = "zone_sdk_indexer_cursor.json";

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<ZoneIndexer>,
    pub config: IndexerConfig,
    pub store: IndexerStore,
}

impl IndexerCore {
    pub fn new(config: IndexerConfig) -> Result<Self> {
        let hashable_data = HashableBlockData {
            block_id: 1,
            transactions: vec![],
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
        };

        // Genesis creation is fine as it is,
        // because it will be overwritten by sequencer.
        // Therefore:
        // ToDo: remove key from indexer config, use some default.
        let signing_key = nssa::PrivateKey::try_new(config.signing_key).unwrap();
        let channel_genesis_msg_id = [0; 32];
        let start_block = hashable_data.into_pending_block(&signing_key, channel_genesis_msg_id);

        // This is a troubling moment, because changes in key protocol can
        // affect this. And indexer can not reliably ask this data from sequencer
        // because indexer must be independent from it.
        // ToDo: move initial state generation into common and use the same method
        // for indexer and sequencer. This way both services buit at same version
        // could be in sync.
        let initial_commitments: Vec<nssa_core::Commitment> = config
            .initial_commitments
            .iter()
            .map(|init_comm_data| {
                let npk = &init_comm_data.npk;

                let mut acc = init_comm_data.account.clone();

                acc.program_owner = nssa::program::Program::authenticated_transfer_program().id();

                nssa_core::Commitment::new(npk, &acc)
            })
            .collect();

        let init_accs: Vec<(nssa::AccountId, u128)> = config
            .initial_accounts
            .iter()
            .map(|acc_data| (acc_data.account_id, acc_data.balance))
            .collect();

        let mut state = nssa::V02State::new_with_genesis_accounts(&init_accs, &initial_commitments);

        // ToDo: Remove after testnet
        state.add_pinata_program(PINATA_BASE58.parse().unwrap());

        let home = config.home.join("rocksdb");

        let auth = config.bedrock_client_config.auth.clone().map(Into::into);
        let zone_indexer = ZoneIndexer::new(
            config.channel_id,
            config.bedrock_client_config.addr.clone(),
            auth,
        );

        Ok(Self {
            zone_indexer: Arc::new(zone_indexer),
            config,
            store: IndexerStore::open_db_with_genesis(&home, Some((start_block, state)))?,
        })
    }

    pub async fn subscribe_parse_block_stream(&self) -> impl futures::Stream<Item = Result<Block>> {
        async_stream::stream! {
            let mut cursor = load_cursor(&self.config.home)?;

            if cursor.is_some() {
                info!("Resuming zone-sdk indexer from persisted cursor");
            } else {
                info!("Starting zone-sdk indexer from the beginning");
            }

            loop {
                info!("Polling next_messages with cursor={cursor:?}");

                let poll_result = match self
                    .zone_indexer
                    .next_messages(cursor, POLL_BATCH_LIMIT)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("next_messages failed: {e}, retrying in {:?}", self.config.consensus_info_polling_interval);
                        tokio::time::sleep(self.config.consensus_info_polling_interval).await;
                        continue;
                    }
                };

                info!("next_messages returned {} messages, cursor={:?}", poll_result.messages.len(), poll_result.cursor);

                if poll_result.messages.is_empty() {
                    // Caught up to LIB, wait before polling again
                    tokio::time::sleep(self.config.consensus_info_polling_interval).await;
                    cursor = Some(poll_result.cursor);
                    continue;
                }

                for zone_block in &poll_result.messages {
                    let block: Block = borsh::from_slice(&zone_block.data)
                        .context("Failed to deserialize L2 block from zone-sdk")?;

                    info!("Indexed L2 block {}", block.header.block_id);

                    // TODO: Remove l1_header placeholder once storage layer
                    // no longer requires it. Zone-sdk handles L1 tracking internally.
                    let placeholder_l1_header = HeaderId::from([0u8; 32]);

                    if let Err(err) = self.store.put_block(block.clone(), placeholder_l1_header) {
                        error!("Failed to store block {}: {err:#}", block.header.block_id);
                    }

                    yield Ok(block);
                }

                cursor = Some(poll_result.cursor);
                save_cursor(&self.config.home, &poll_result.cursor)?;
            }
        }
    }
}

fn load_cursor(home: &Path) -> Result<Option<Cursor>> {
    let path = home.join(CURSOR_FILE_NAME);
    if path.exists() {
        let data = std::fs::read(&path).context("Failed to read indexer cursor file")?;
        let cursor: Cursor =
            serde_json::from_slice(&data).context("Failed to deserialize indexer cursor")?;
        info!("Loaded zone-sdk indexer cursor from {}", path.display());
        Ok(Some(cursor))
    } else {
        Ok(None)
    }
}

fn save_cursor(home: &Path, cursor: &Cursor) -> Result<()> {
    let path = home.join(CURSOR_FILE_NAME);
    let data = serde_json::to_vec(cursor).context("Failed to serialize indexer cursor")?;
    std::fs::write(&path, data).context("Failed to write indexer cursor file")?;
    Ok(())
}
