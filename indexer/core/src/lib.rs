use std::collections::VecDeque;

use anyhow::Result;
use bedrock_client::{BedrockClient, HeaderId};
use common::block::{Block, HashableBlockData};
// ToDo: Remove after testnet
use common::{HashType, PINATA_BASE58};
use log::{debug, error, info};
use logos_blockchain_core::mantle::{
    Op, SignedMantleTx,
    ops::channel::{ChannelId, inscribe::InscriptionOp},
};

use crate::{block_store::IndexerStore, config::IndexerConfig};

pub mod block_store;
pub mod config;

#[derive(Clone)]
pub struct IndexerCore {
    pub bedrock_client: BedrockClient,
    pub config: IndexerConfig,
    pub store: IndexerStore,
}

#[derive(Clone)]
/// This struct represents one L1 block data fetched from backfilling
pub struct BackfillBlockData {
    l2_blocks: Vec<Block>,
    l1_header: HeaderId,
}

#[derive(Clone)]
/// This struct represents data fetched fom backfilling in one iteration
pub struct BackfillData {
    block_data: VecDeque<BackfillBlockData>,
    curr_fin_l1_lib_header: HeaderId,
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

        Ok(Self {
            bedrock_client: BedrockClient::new(
                config.bedrock_client_config.backoff,
                config.bedrock_client_config.addr.clone(),
                config.bedrock_client_config.auth.clone(),
            )?,
            config,
            store: IndexerStore::open_db_with_genesis(&home, Some((start_block, state)))?,
        })
    }

    pub async fn subscribe_parse_block_stream(&self) -> impl futures::Stream<Item = Result<Block>> {
        async_stream::stream! {
            info!("Searching for initial header");

            let last_l1_lib_header = self.store.last_observed_l1_lib_header()?;

            let mut prev_last_l1_lib_header = match last_l1_lib_header {
                Some(last_l1_lib_header) => {
                    info!("Last l1 lib header found: {last_l1_lib_header}");
                    last_l1_lib_header
                },
                None => {
                    info!("Last l1 lib header not found in DB");
                    info!("Searching for the start of a channel");

                    let BackfillData {
                        block_data: start_buff,
                        curr_fin_l1_lib_header: last_l1_lib_header,
                    } = self.search_for_channel_start().await?;

                    for BackfillBlockData {
                        l2_blocks: l2_block_vec,
                        l1_header,
                    } in start_buff {
                        let mut l2_blocks_parsed_ids: Vec<_> = l2_block_vec.iter().map(|block| block.header.block_id).collect();
                        l2_blocks_parsed_ids.sort();
                        info!("Parsed {} L2 blocks with ids {:?}", l2_block_vec.len(), l2_blocks_parsed_ids);

                        for l2_block in l2_block_vec {
                            self.store.put_block(l2_block.clone(), l1_header)?;

                            yield Ok(l2_block);
                        }
                    }

                    last_l1_lib_header
                },
            };

            info!("Searching for initial header finished");

            info!("Starting backfilling from {prev_last_l1_lib_header}");

            loop {
                let BackfillData {
                    block_data: buff,
                    curr_fin_l1_lib_header,
                } = self
                    .backfill_to_last_l1_lib_header_id(prev_last_l1_lib_header, &self.config.channel_id)
                    .await
                    .inspect_err(|err| error!("Failed to backfill to last l1 lib header id with err {err:#?}"))?;

                prev_last_l1_lib_header = curr_fin_l1_lib_header;

                for BackfillBlockData {
                    l2_blocks: l2_block_vec,
                    l1_header: header,
                } in buff {
                    let mut l2_blocks_parsed_ids: Vec<_> = l2_block_vec.iter().map(|block| block.header.block_id).collect();
                    l2_blocks_parsed_ids.sort();
                    info!("Parsed {} L2 blocks with ids {:?}", l2_block_vec.len(), l2_blocks_parsed_ids);

                    for l2_block in l2_block_vec {
                        self.store.put_block(l2_block.clone(), header)?;

                        yield Ok(l2_block);
                    }
                }
            }
        }
    }

    async fn get_lib(&self) -> Result<HeaderId> {
        Ok(self.bedrock_client.get_consensus_info().await?.lib)
    }

    async fn get_next_lib(&self, prev_lib: HeaderId) -> Result<HeaderId> {
        loop {
            let next_lib = self.get_lib().await?;
            if next_lib != prev_lib {
                break Ok(next_lib);
            } else {
                info!(
                    "Wait {:?} to not spam the node",
                    self.config.consensus_info_polling_interval
                );
                tokio::time::sleep(self.config.consensus_info_polling_interval).await;
            }
        }
    }

    /// WARNING: depending on channel state,
    /// may take indefinite amount of time
    pub async fn search_for_channel_start(&self) -> Result<BackfillData> {
        let mut curr_last_l1_lib_header = self.get_lib().await?;
        let mut backfill_start = curr_last_l1_lib_header;
        // ToDo: How to get root?
        let mut backfill_limit = HeaderId::from([0; 32]);
        // ToDo: Not scalable, initial buffer should be stored in DB to not run out of memory
        // Don't want to complicate DB even more right now.
        let mut block_buffer = VecDeque::new();

        'outer: loop {
            let mut cycle_header = curr_last_l1_lib_header;

            loop {
                let cycle_block =
                    if let Some(block) = self.bedrock_client.get_block_by_id(cycle_header).await? {
                        block
                    } else {
                        // First run can reach root easily
                        // so here we are optimistic about L1
                        // failing to get parent.
                        break;
                    };

                // It would be better to have id, but block does not have it, so slot will do.
                info!(
                    "INITIAL SEARCH: Observed L1 block at slot {}",
                    cycle_block.header().slot().into_inner()
                );
                debug!(
                    "INITIAL SEARCH: This block header is {}",
                    cycle_block.header().id()
                );
                debug!(
                    "INITIAL SEARCH: This block parent is {}",
                    cycle_block.header().parent()
                );

                let (l2_block_vec, l1_header) =
                    parse_block_owned(&cycle_block, &self.config.channel_id);

                info!("Parsed {} L2 blocks", l2_block_vec.len());

                if !l2_block_vec.is_empty() {
                    block_buffer.push_front(BackfillBlockData {
                        l2_blocks: l2_block_vec.clone(),
                        l1_header,
                    });
                }

                if let Some(first_l2_block) = l2_block_vec.first()
                    && first_l2_block.header.block_id == 1
                {
                    info!("INITIAL_SEARCH: Found channel start");
                    break 'outer;
                }

                // Step back to parent
                let parent = cycle_block.header().parent();

                if parent == backfill_limit {
                    break;
                }

                cycle_header = parent;
            }

            info!("INITIAL_SEARCH: Reached backfill limit, refetching last l1 lib header");

            block_buffer.clear();
            backfill_limit = backfill_start;
            curr_last_l1_lib_header = self.get_next_lib(curr_last_l1_lib_header).await?;
            backfill_start = curr_last_l1_lib_header;
        }

        Ok(BackfillData {
            block_data: block_buffer,
            curr_fin_l1_lib_header: curr_last_l1_lib_header,
        })
    }

    pub async fn backfill_to_last_l1_lib_header_id(
        &self,
        last_fin_l1_lib_header: HeaderId,
        channel_id: &ChannelId,
    ) -> Result<BackfillData> {
        let curr_fin_l1_lib_header = self.get_next_lib(last_fin_l1_lib_header).await?;
        // ToDo: Not scalable, buffer should be stored in DB to not run out of memory
        // Don't want to complicate DB even more right now.
        let mut block_buffer = VecDeque::new();

        let mut cycle_header = curr_fin_l1_lib_header;
        loop {
            let Some(cycle_block) = self.bedrock_client.get_block_by_id(cycle_header).await? else {
                return Err(anyhow::anyhow!("Parent not found"));
            };

            if cycle_block.header().id() == last_fin_l1_lib_header {
                break;
            } else {
                // Step back to parent
                cycle_header = cycle_block.header().parent();
            }

            // It would be better to have id, but block does not have it, so slot will do.
            info!(
                "Observed L1 block at slot {}",
                cycle_block.header().slot().into_inner()
            );

            let (l2_block_vec, l1_header) = parse_block_owned(&cycle_block, channel_id);

            info!("Parsed {} L2 blocks", l2_block_vec.len());

            if !l2_block_vec.is_empty() {
                block_buffer.push_front(BackfillBlockData {
                    l2_blocks: l2_block_vec,
                    l1_header,
                });
            }
        }

        Ok(BackfillData {
            block_data: block_buffer,
            curr_fin_l1_lib_header,
        })
    }
}

fn parse_block_owned(
    l1_block: &bedrock_client::Block<SignedMantleTx>,
    decoded_channel_id: &ChannelId,
) -> (Vec<Block>, HeaderId) {
    (
        l1_block
            .transactions()
            .flat_map(|tx| {
                tx.mantle_tx.ops.iter().filter_map(|op| match op {
                    Op::ChannelInscribe(InscriptionOp {
                        channel_id,
                        inscription,
                        ..
                    }) if channel_id == decoded_channel_id => {
                        borsh::from_slice::<Block>(inscription)
                            .inspect_err(|err| {
                                error!("Failed to deserialize our inscription with err: {err:#?}")
                            })
                            .ok()
                    }
                    _ => None,
                })
            })
            .collect(),
        l1_block.header().id(),
    )
}
