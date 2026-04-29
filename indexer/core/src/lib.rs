use std::sync::Arc;

use anyhow::Result;
use common::block::{Block, HashableBlockData};
// ToDo: Remove after testnet
use common::{HashType, PINATA_BASE58};
use futures::StreamExt as _;
use log::{error, info};
use logos_blockchain_core::header::HeaderId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
use nssa::V03State;
use testnet_initial_state::initial_state_testnet;

use crate::{block_store::IndexerStore, config::IndexerConfig};

// TODO: persist & restore cursor (e.g. in rocksdb) so restarts don't have to
// re-process the channel from the beginning. Mirrors the sequencer checkpoint
// TODO in `block_publisher.rs`.

pub mod block_store;
pub mod config;

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<ZoneIndexer<NodeHttpClient>>,
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
        let genesis_block = hashable_data.into_pending_block(&signing_key, channel_genesis_msg_id);

        let initial_private_accounts: Option<Vec<(nssa_core::Commitment, nssa_core::Nullifier)>> =
            config.initial_private_accounts.as_ref().map(|accounts| {
                accounts
                    .iter()
                    .map(|init_comm_data| {
                        let npk = &init_comm_data.npk;

                        let mut acc = init_comm_data.account.clone();

                        acc.program_owner =
                            nssa::program::Program::authenticated_transfer_program().id();

                        (
                            nssa_core::Commitment::new(npk, &acc),
                            nssa_core::Nullifier::for_account_initialization(npk),
                        )
                    })
                    .collect()
            });

        let init_accs: Option<Vec<(nssa::AccountId, u128)>> = config
            .initial_public_accounts
            .as_ref()
            .map(|initial_accounts| {
                initial_accounts
                    .iter()
                    .map(|acc_data| (acc_data.account_id, acc_data.balance))
                    .collect()
            });

        // If initial commitments or accounts are present in config, need to construct state from
        // them
        let state = if initial_private_accounts.is_some() || init_accs.is_some() {
            let mut state = V03State::new_with_genesis_accounts(
                &init_accs.unwrap_or_default(),
                initial_private_accounts.unwrap_or_default(),
                genesis_block.header.timestamp,
            );

            // ToDo: Remove after testnet
            state.add_pinata_program(PINATA_BASE58.parse().unwrap());

            state
        } else {
            initial_state_testnet()
        };

        let home = config.home.join("rocksdb");

        let basic_auth = config.bedrock_client_config.auth.clone().map(Into::into);
        let node = NodeHttpClient::new(
            CommonHttpClient::new(basic_auth),
            config.bedrock_client_config.addr.clone(),
        );
        let zone_indexer = ZoneIndexer::new(config.channel_id, node);

        Ok(Self {
            zone_indexer: Arc::new(zone_indexer),
            config,
            store: IndexerStore::open_db_with_genesis(&home, &genesis_block, &state)?,
        })
    }

    pub fn subscribe_parse_block_stream(&self) -> impl futures::Stream<Item = Result<Block>> + '_ {
        let poll_interval = self.config.consensus_info_polling_interval;

        async_stream::stream! {
            // In-memory only; not persisted across restarts (see top-of-file TODO).
            let mut cursor = None;

            info!("Starting indexer from beginning of channel");

            loop {
                let stream = match self.zone_indexer.next_messages(cursor).await {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Failed to start zone-sdk next_messages stream: {err}");
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };
                let mut stream = std::pin::pin!(stream);

                while let Some((msg, slot)) = stream.next().await {
                    let zone_block = match msg {
                        ZoneMessage::Block(b) => b,
                        // Non-block messages don't carry a cursor position; the
                        // next ZoneBlock advances past them implicitly.
                        ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => continue,
                    };

                    let block: Block = match borsh::from_slice(&zone_block.data) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Failed to deserialize L2 block from zone-sdk: {e}");
                            cursor = Some((zone_block.id, slot));
                            continue;
                        }
                    };

                    info!("Indexed L2 block {}", block.header.block_id);

                    // TODO: Remove l1_header placeholder once storage layer
                    // no longer requires it. Zone-sdk handles L1 tracking internally.
                    let placeholder_l1_header = HeaderId::from([0_u8; 32]);
                    if let Err(err) = self.store.put_block(block.clone(), placeholder_l1_header).await {
                        error!("Failed to store block {}: {err:#}", block.header.block_id);
                    }

                    cursor = Some((zone_block.id, slot));
                    yield Ok(block);
                }

                // Stream ended (caught up to LIB). Sleep then poll again.
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}
