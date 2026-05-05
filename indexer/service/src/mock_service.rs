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
    CommitmentSetDigest, Data, EncryptedAccountData, HashType, MantleMsgId,
    PrivacyPreservingMessage, PrivacyPreservingTransaction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, ProgramId, PublicMessage, PublicTransaction, Signature,
    Transaction, ValidityWindow, WitnessSet,
};
use jsonrpsee::{
    core::{SubscriptionResult, async_trait},
    types::ErrorObjectOwned,
};
use tokio::sync::{RwLock, broadcast};

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
                    program_owner: ProgramId([i as u32; 8]),
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
                    Transaction::PrivacyPreserving(priv_tx) => {
                        priv_tx.message.public_account_ids.contains(&account_id)
                    }
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

    async fn healthcheck(&self) -> Result<(), ErrorObjectOwned> {
        Ok(())
    }
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

    // Create 2-4 transactions per block (mix of Public, PrivacyPreserving, and ProgramDeployment)
    let num_txs = 2 + (block_id % 3);
    let mut block_transactions = Vec::new();

    for tx_idx in 0..num_txs {
        let tx_hash = {
            let mut hash = [0_u8; 32];
            hash[0] = block_id as u8;
            hash[1] = tx_idx as u8;
            HashType(hash)
        };

        // Vary transaction types: Public, PrivacyPreserving, or ProgramDeployment
        let tx = match (block_id + tx_idx) % 5 {
            // Public transactions (most common)
            0 | 1 => Transaction::Public(PublicTransaction {
                hash: tx_hash,
                message: PublicMessage {
                    program_id: ProgramId([1_u32; 8]),
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
            }),
            // PrivacyPreserving transactions
            2 | 3 => Transaction::PrivacyPreserving(PrivacyPreservingTransaction {
                hash: tx_hash,
                message: PrivacyPreservingMessage {
                    public_account_ids: vec![account_ids[tx_idx as usize % account_ids.len()]],
                    nonces: vec![block_id as u128],
                    public_post_states: vec![Account {
                        program_owner: ProgramId([1_u32; 8]),
                        balance: 500,
                        data: Data(vec![0xdd, 0xee]),
                        nonce: block_id as u128,
                    }],
                    encrypted_private_post_states: vec![EncryptedAccountData {
                        ciphertext: indexer_service_protocol::Ciphertext(vec![
                            0x01, 0x02, 0x03, 0x04,
                        ]),
                        epk: indexer_service_protocol::EphemeralPublicKey(vec![0xaa; 32]),
                        view_tag: 42,
                    }],
                    new_commitments: vec![Commitment([block_id as u8; 32])],
                    new_nullifiers: vec![(
                        indexer_service_protocol::Nullifier([tx_idx as u8; 32]),
                        CommitmentSetDigest([0xff; 32]),
                    )],
                    block_validity_window: ValidityWindow((None, None)),
                    timestamp_validity_window: ValidityWindow((None, None)),
                },
                witness_set: WitnessSet {
                    signatures_and_public_keys: vec![],
                    proof: Some(indexer_service_protocol::Proof(vec![0; 32])),
                },
            }),
            // ProgramDeployment transactions (rare)
            _ => Transaction::ProgramDeployment(ProgramDeploymentTransaction {
                hash: tx_hash,
                message: ProgramDeploymentMessage {
                    bytecode: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00], /* WASM magic
                                                                                     * number */
                },
            }),
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
        bedrock_parent_id: MantleMsgId([0; 32]),
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
