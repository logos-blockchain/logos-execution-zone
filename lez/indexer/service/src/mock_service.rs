#![expect(
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::integer_division_remainder_used,
    reason = "Mock service uses intentional casts and format patterns for test data generation"
)]
use std::{collections::HashMap, sync::Arc, time::Duration};

use indexer_service_protocol::{
    Account, AccountId, BedrockStatus, Block, BlockBody, BlockHeader, BlockId, Commitment,
    CommitmentSetDigest, Data, EncryptedAccountData, EventRecord, EventSubscriptionFilter,
    GetEventsFilter, HashType, IndexerStatus, IndexerSyncState, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, PrivateAction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, ProgramId, PublicActionWithID, PublicMessage, PublicTransaction,
    Selector, Signature, Transaction, ValidityWindow, WitnessSet,
};
use jsonrpsee::{
    core::{SubscriptionResult, async_trait},
    types::ErrorObjectOwned,
};
use tokio::sync::{RwLock, broadcast};

use crate::service::{
    EventQuery, matches_subscription_filter, plan_query, unknown_transaction_error,
};

const MOCK_GENESIS_TIMESTAMP_MS: u64 = 1_704_067_200_000;
const MOCK_BLOCK_INTERVAL_MS: u64 = 30_000;

struct MockState {
    blocks: Vec<Block>,
    accounts: HashMap<AccountId, Account>,
    account_ids: Vec<AccountId>,
    transactions: HashMap<HashType, (Transaction, BlockId)>,
}

/// A mock implementation of the `IndexerService` RPC for testing purposes.
pub struct MockIndexerService {
    state: Arc<RwLock<MockState>>,
    finalized_blocks_tx: broadcast::Sender<Block>,
}

impl MockIndexerService {
    fn spawn_block_generation_task(
        state: Arc<RwLock<MockState>>,
        finalized_blocks_tx: broadcast::Sender<Block>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                let new_block = {
                    let mut state = state.write().await;

                    let next_block_id = state
                        .blocks
                        .last()
                        .map_or(1, |block| block.header.block_id.saturating_add(1));
                    let prev_hash = state
                        .blocks
                        .last()
                        .map_or(HashType([0_u8; 32]), |block| block.header.hash);
                    let timestamp = state.blocks.last().map_or(
                        MOCK_GENESIS_TIMESTAMP_MS + MOCK_BLOCK_INTERVAL_MS,
                        |block| {
                            block
                                .header
                                .timestamp
                                .saturating_add(MOCK_BLOCK_INTERVAL_MS)
                        },
                    );

                    let block = build_mock_block(
                        next_block_id,
                        prev_hash,
                        timestamp,
                        &state.account_ids,
                        BedrockStatus::Finalized,
                    );

                    index_block_transactions(&mut state.transactions, &block);
                    state.blocks.push(block.clone());

                    block
                };

                let _res = finalized_blocks_tx.send(new_block);
            }
        });
    }

    #[must_use]
    pub fn new_with_mock_blocks() -> Self {
        let mut blocks = Vec::new();
        let mut accounts = HashMap::new();
        let mut transactions = HashMap::new();

        // Create some mock accounts
        let account_ids: Vec<AccountId> = (0..5)
            .map(|i| {
                let mut value = [0_u8; 32];
                value[0] = i;
                AccountId { value }
            })
            .collect();

        for (i, account_id) in account_ids.iter().enumerate() {
            accounts.insert(
                *account_id,
                Account {
                    program_owner: AccountId {
                        value: [i as u8; 32],
                    },
                    balance: 1000 * (i as u128 + 1),
                    data: Data(vec![0xaa, 0xbb, 0xcc]),
                    nonce: i as u128,
                },
            );
        }

        // Create 100 blocks with transactions
        let mut prev_hash = HashType([0_u8; 32]);

        for block_id in 1..=100 {
            let block = build_mock_block(
                block_id,
                prev_hash,
                MOCK_GENESIS_TIMESTAMP_MS + (block_id * MOCK_BLOCK_INTERVAL_MS),
                &account_ids,
                match block_id {
                    0..=5 => BedrockStatus::Finalized,
                    6..=8 => BedrockStatus::Safe,
                    _ => BedrockStatus::Pending,
                },
            );

            index_block_transactions(&mut transactions, &block);

            prev_hash = block.header.hash;
            blocks.push(block);
        }

        let state = Arc::new(RwLock::new(MockState {
            blocks,
            accounts,
            account_ids,
            transactions,
        }));

        let (finalized_blocks_tx, _) = broadcast::channel(32);

        Self::spawn_block_generation_task(Arc::clone(&state), finalized_blocks_tx.clone());

        Self {
            state,
            finalized_blocks_tx,
        }
    }
}

#[async_trait]
impl indexer_service_rpc::RpcServer for MockIndexerService {
    async fn subscribe_to_finalized_blocks(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        let initial_finalized_blocks: Vec<Block> = {
            let state = self.state.read().await;
            state
                .blocks
                .iter()
                .filter(|b| b.bedrock_status == BedrockStatus::Finalized)
                .cloned()
                .collect()
        };

        for block in &initial_finalized_blocks {
            let json = serde_json::value::to_raw_value(block).unwrap();
            sink.send(json).await?;
        }

        let mut receiver = self.finalized_blocks_tx.subscribe();
        loop {
            match receiver.recv().await {
                Ok(block) => {
                    let json = serde_json::value::to_raw_value(&block).unwrap();
                    sink.send(json).await?;
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }

        Ok(())
    }

    async fn subscribe_to_events(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
        filter: EventSubscriptionFilter,
    ) -> SubscriptionResult {
        let sink = subscription_sink.accept().await?;

        // One canned event per generated block, matching `get_events`' shape.
        let mut receiver = self.finalized_blocks_tx.subscribe();
        loop {
            match receiver.recv().await {
                Ok(block) => {
                    let Some(record) = mock_event_record(&block) else {
                        continue;
                    };
                    if matches_subscription_filter(&record, &filter) {
                        let json = serde_json::value::to_raw_value(&record).unwrap();
                        sink.send(json).await?;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }

        Ok(())
    }

    async fn get_last_finalized_block_id(&self) -> Result<Option<BlockId>, ErrorObjectOwned> {
        Ok(self
            .state
            .read()
            .await
            .blocks
            .iter()
            .rev()
            .find(|block| block.bedrock_status == BedrockStatus::Finalized)
            .map(|block| block.header.block_id))
    }

    async fn get_block_by_id(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned> {
        Ok(self
            .state
            .read()
            .await
            .blocks
            .iter()
            .find(|b| b.header.block_id == block_id)
            .cloned())
    }

    async fn get_block_by_hash(
        &self,
        block_hash: HashType,
    ) -> Result<Option<Block>, ErrorObjectOwned> {
        Ok(self
            .state
            .read()
            .await
            .blocks
            .iter()
            .find(|b| b.header.hash == block_hash)
            .cloned())
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        self.state
            .read()
            .await
            .accounts
            .get(&account_id)
            .cloned()
            .ok_or_else(|| ErrorObjectOwned::owned(-32001, "Account not found", None::<()>))
    }

    async fn get_account_at_block(
        &self,
        account_id: AccountId,
        _block_id: BlockId,
    ) -> Result<Account, ErrorObjectOwned> {
        // Mock service does not track historical state; returns current state regardless of
        // block_id.
        self.state
            .read()
            .await
            .accounts
            .get(&account_id)
            .cloned()
            .ok_or_else(|| ErrorObjectOwned::owned(-32001, "Account not found", None::<()>))
    }

    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<Transaction>, ErrorObjectOwned> {
        Ok(self
            .state
            .read()
            .await
            .transactions
            .get(&tx_hash)
            .map(|(tx, _)| tx.clone()))
    }

    async fn get_blocks(
        &self,
        before: Option<BlockId>,
        limit: u64,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        let state = self.state.read().await;

        let start_id = before.map_or_else(
            || state.blocks.len(),
            |id| usize::try_from(id.saturating_sub(1)).expect("u64 should fit in usize"),
        );

        let result = (1..=start_id)
            .rev()
            .take(limit as usize)
            .map_while(|block_id| state.blocks.get(block_id - 1).cloned())
            .collect();

        Ok(result)
    }

    async fn get_transactions_by_account(
        &self,
        account_id: AccountId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Transaction>, ErrorObjectOwned> {
        let mut account_txs: Vec<(Transaction, BlockId)> = {
            let state = self.state.read().await;
            state
                .transactions
                .values()
                .filter(|(tx, _)| match tx {
                    Transaction::Public(pub_tx) => pub_tx.message.account_ids.contains(&account_id),
                    Transaction::PrivacyPreserving(priv_tx) => priv_tx
                        .message
                        .public_actions
                        .iter()
                        .any(|action| action.account_id == account_id),
                    Transaction::ProgramDeployment(_) => false,
                })
                .cloned()
                .collect()
        };

        // Sort by block ID descending (most recent first)
        account_txs.sort_by_key(|(_, block_id)| std::cmp::Reverse(*block_id));

        let start = offset as usize;
        if start >= account_txs.len() {
            return Ok(Vec::new());
        }

        let end = (start + limit as usize).min(account_txs.len());

        Ok(account_txs[start..end]
            .iter()
            .map(|(tx, _)| tx.clone())
            .collect())
    }

    async fn get_events(
        &self,
        filter: GetEventsFilter,
    ) -> Result<Vec<EventRecord>, ErrorObjectOwned> {
        // Resolution goes through the production planner so the mock enforces the same
        // contract as the real service.
        let state = self.state.read().await;
        let tip = state.blocks.last().map_or(0, |block| block.header.block_id);
        let records = state.blocks.iter().filter_map(mock_event_record);

        let records: Vec<EventRecord> = match plan_query(&filter, tip)? {
            EventQuery::ByTxHash(tx_hash) => {
                if !state.transactions.contains_key(&tx_hash) {
                    return Err(unknown_transaction_error());
                }
                records.filter(|record| tx_hash == record.tx_hash).collect()
            }
            EventQuery::ByRange {
                from_block,
                to_block,
            } => records
                .filter(|record| record.block_id >= from_block && record.block_id <= to_block)
                .collect(),
        };

        Ok(records
            .into_iter()
            .filter(|record| record.matches_fields(filter.program_id, filter.selector))
            .collect())
    }

    async fn get_status(&self) -> Result<IndexerStatus, ErrorObjectOwned> {
        let indexed_block_id = self
            .state
            .read()
            .await
            .blocks
            .iter()
            .rev()
            .find(|block| block.bedrock_status == BedrockStatus::Finalized)
            .map(|block| block.header.block_id);
        Ok(IndexerStatus {
            state: IndexerSyncState::CaughtUp,
            last_error: None,
            indexed_block_id,
            stall_reason: None,
            cross_zone_halt: None,
            cross_zone_peers: Vec::new(),
        })
    }

    async fn healthcheck(&self) -> Result<(), ErrorObjectOwned> {
        Ok(())
    }
}

// One canned event per block: the first transaction emits one event from a fixed program.
fn mock_event_record(block: &Block) -> Option<EventRecord> {
    let tx = block.body.transactions.first()?;
    Some(EventRecord {
        block_id: block.header.block_id,
        tx_index: 0,
        tx_hash: *tx.hash(),
        program_id: ProgramId([7_u32; 8]),
        selector: Selector([1_u8; 8]),
        data: vec![block.header.block_id as u8; 4],
    })
}

fn mock_public_tx(
    tx_hash: HashType,
    block_id: BlockId,
    tx_idx: u64,
    account_ids: &[AccountId],
) -> Transaction {
    Transaction::Public(PublicTransaction {
        hash: tx_hash,
        message: PublicMessage {
            program_account_id: AccountId { value: [1_u8; 32] },
            account_ids: vec![
                account_ids[tx_idx as usize % account_ids.len()],
                account_ids[(tx_idx as usize + 1) % account_ids.len()],
            ],
            nonces: vec![block_id as u128, (block_id + 1) as u128],
            instruction_data: vec![1, 2, 3, 4],
        },
        witness_set: WitnessSet {
            signatures_and_public_keys: vec![],
            proof: None,
        },
    })
}

fn mock_privacy_preserving_tx(
    tx_hash: HashType,
    block_id: BlockId,
    tx_idx: u64,
    account_ids: &[AccountId],
) -> Transaction {
    Transaction::PrivacyPreserving(PrivacyPreservingTransaction {
        hash: tx_hash,
        message: PrivacyPreservingMessage {
            public_actions: vec![PublicActionWithID {
                account_id: account_ids[tx_idx as usize % account_ids.len()],
                post_state: Account {
                    program_owner: AccountId { value: [1_u8; 32] },
                    balance: 500,
                    data: Data(vec![0xdd, 0xee]),
                    nonce: block_id as u128,
                },
            }],
            nonces: vec![block_id as u128],
            private_actions: vec![PrivateAction {
                nullifier: indexer_service_protocol::Nullifier([tx_idx as u8; 32]),
                root: CommitmentSetDigest([0xff; 32]),
                commitment: Commitment([block_id as u8; 32]),
                encrypted_post_state: EncryptedAccountData {
                    ciphertext: indexer_service_protocol::Ciphertext(vec![0x01, 0x02, 0x03, 0x04]),
                    epk: indexer_service_protocol::EphemeralPublicKey(vec![0xaa; 32]),
                    view_tag: 42,
                },
            }],
            block_validity_window: ValidityWindow((None, None)),
            timestamp_validity_window: ValidityWindow((None, None)),
        },
        witness_set: WitnessSet {
            signatures_and_public_keys: vec![],
            proof: Some(indexer_service_protocol::Proof(vec![0; 32])),
        },
    })
}

fn mock_program_deployment_tx(tx_hash: HashType) -> Transaction {
    Transaction::ProgramDeployment(ProgramDeploymentTransaction {
        hash: tx_hash,
        message: ProgramDeploymentMessage {
            bytecode: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        },
    })
}

fn build_mock_block(
    block_id: BlockId,
    prev_hash: HashType,
    timestamp: u64,
    account_ids: &[AccountId],
    bedrock_status: BedrockStatus,
) -> Block {
    let block_hash = {
        let mut hash = [0_u8; 32];
        hash[0] = block_id as u8;
        hash[1] = 0xff;
        HashType(hash)
    };

    let num_txs = 2 + (block_id % 3);
    let mut block_transactions = Vec::new();

    for tx_idx in 0..num_txs {
        let tx_hash = {
            let mut hash = [0_u8; 32];
            hash[0] = block_id as u8;
            hash[1] = tx_idx as u8;
            HashType(hash)
        };

        let tx = match (block_id + tx_idx) % 5 {
            0 | 1 => mock_public_tx(tx_hash, block_id, tx_idx, account_ids),
            2 | 3 => mock_privacy_preserving_tx(tx_hash, block_id, tx_idx, account_ids),
            _ => mock_program_deployment_tx(tx_hash),
        };

        block_transactions.push(tx);
    }

    Block {
        header: BlockHeader {
            block_id,
            prev_block_hash: prev_hash,
            hash: block_hash,
            timestamp,
            signature: Signature([0_u8; 64]),
        },
        body: BlockBody {
            transactions: block_transactions,
        },
        bedrock_status,
    }
}

fn index_block_transactions(
    transactions: &mut HashMap<HashType, (Transaction, BlockId)>,
    block: &Block,
) {
    for tx in &block.body.transactions {
        let tx_hash = match tx {
            Transaction::Public(public_tx) => public_tx.hash,
            Transaction::PrivacyPreserving(private_tx) => private_tx.hash,
            Transaction::ProgramDeployment(deployment_tx) => deployment_tx.hash,
        };
        transactions.insert(tx_hash, (tx.clone(), block.header.block_id));
    }
}

#[cfg(test)]
mod tests {
    use indexer_service_rpc::RpcServer as _;

    use super::*;

    #[tokio::test]
    async fn get_events_returns_records_in_block_order() {
        let service = MockIndexerService::new_with_mock_blocks();
        let records = service
            .get_events(GetEventsFilter {
                from_block: Some(1),
                ..GetEventsFilter::default()
            })
            .await
            .unwrap();
        let block_ids: Vec<BlockId> = records.iter().map(|record| record.block_id).collect();
        assert!(block_ids.len() > 1);
        assert!(block_ids.is_sorted_by(|a, b| a < b));
    }

    #[tokio::test]
    async fn tx_hash_lookup_applies_field_filters() {
        let service = MockIndexerService::new_with_mock_blocks();
        let tx_hash = {
            let state = service.state.read().await;
            *state.blocks[0].body.transactions[0].hash()
        };
        let matching = GetEventsFilter {
            tx_hash: Some(tx_hash),
            program_id: Some(ProgramId([7_u32; 8])),
            ..GetEventsFilter::default()
        };
        let hit = service.get_events(matching).await.unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].tx_hash, tx_hash);

        let mismatched = GetEventsFilter {
            tx_hash: Some(tx_hash),
            program_id: Some(ProgramId([8_u32; 8])),
            ..GetEventsFilter::default()
        };
        let miss = service.get_events(mismatched).await.unwrap();
        assert!(miss.is_empty());
    }

    #[tokio::test]
    async fn a_known_tx_without_events_returns_empty() {
        let service = MockIndexerService::new_with_mock_blocks();
        // Every transaction is indexed, but only the first of each block gets an
        // event record.
        let tx_hash = {
            let state = service.state.read().await;
            *state.blocks[0].body.transactions[1].hash()
        };
        let records = service
            .get_events(GetEventsFilter {
                tx_hash: Some(tx_hash),
                ..GetEventsFilter::default()
            })
            .await
            .unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn an_unknown_tx_hash_is_rejected() {
        let service = MockIndexerService::new_with_mock_blocks();
        let err = service
            .get_events(GetEventsFilter {
                tx_hash: Some(HashType([0xEE; 32])),
                ..GetEventsFilter::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.message(), "UnknownTransaction");
    }
}
