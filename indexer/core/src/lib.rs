use std::sync::Arc;

use anyhow::Result;
use common::block::{Block, HashableBlockData};
// ToDo: Remove after testnet
use common::{HashType, PINATA_BASE58};
use futures::StreamExt as _;
use log::{error, info, warn};
use logos_blockchain_core::header::HeaderId;
use logos_blockchain_zone_sdk::indexer::ZoneIndexer;

use crate::{block_store::IndexerStore, config::IndexerConfig};

pub mod block_store;
pub mod config;

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
            info!("Starting zone-sdk indexer using follow()");

            let follow_stream = match self.zone_indexer.follow().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to start zone-sdk follow stream: {e}");
                    return;
                }
            };

            let mut follow_stream = std::pin::pin!(follow_stream);

            while let Some(zone_block) = follow_stream.next().await {
                let block: Block = match borsh::from_slice(&zone_block.data) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to deserialize L2 block from zone-sdk: {e}");
                        continue;
                    }
                };

                info!("Indexed L2 block {}", block.header.block_id);

                // TODO: Remove l1_header placeholder once storage layer
                // no longer requires it. Zone-sdk handles L1 tracking internally.
                let placeholder_l1_header = HeaderId::from([0u8; 32]);

                if let Err(err) = self.store.put_block(block.clone(), placeholder_l1_header) {
                    error!("Failed to store block {}: {err:#}", block.header.block_id);
                }

                yield Ok(block);
            }

            warn!("zone-sdk follow stream ended");
        }
    }
}
