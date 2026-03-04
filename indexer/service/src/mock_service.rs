use std::collections::HashMap;

use indexer_service_protocol::{
    Account, AccountId, BedrockStatus, Block, BlockBody, BlockHeader, BlockId, Commitment,
    CommitmentSetDigest, Data, EncryptedAccountData, HashType, MantleMsgId,
    PrivacyPreservingMessage, PrivacyPreservingTransaction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, ProgramId, PublicMessage, PublicTransaction, Signature,
    Transaction, WitnessSet,
};
use jsonrpsee::{core::SubscriptionResult, types::ErrorObjectOwned};

/// A mock implementation of the IndexerService RPC for testing purposes.
pub struct MockIndexerService {
    blocks: Vec<Block>,
    accounts: HashMap<AccountId, Account>,
    transactions: HashMap<HashType, (Transaction, BlockId)>,
}

impl MockIndexerService {
    pub fn new_with_mock_blocks() -> Self {
        let mut blocks = Vec::new();
        let mut accounts = HashMap::new();
        let mut transactions = HashMap::new();

        // Create some mock accounts
        let account_ids: Vec<AccountId> = (0..5)
            .map(|i| {
                let mut value = [0u8; 32];
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
        let mut prev_hash = HashType([0u8; 32]);

        for block_id in 1..=100 {
            let block_hash = {
                let mut hash = [0u8; 32];
                hash[0] = block_id as u8;
                hash[1] = 0xff;
                HashType(hash)
            };

            // Create 2-4 transactions per block (mix of Public, PrivacyPreserving, and
            // ProgramDeployment)
            let num_txs = 2 + (block_id % 3);
            let mut block_transactions = Vec::new();

            for tx_idx in 0..num_txs {
                let tx_hash = {
                    let mut hash = [0u8; 32];
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
                            program_id: ProgramId([1u32; 8]),
                            account_ids: vec![
                                account_ids[tx_idx as usize % account_ids.len()],
                                account_ids[(tx_idx as usize + 1) % account_ids.len()],
                            ],
                            nonces: vec![block_id as u128, (block_id + 1) as u128],
                            instruction_data: vec![1, 2, 3, 4],
                        },
                        witness_set: WitnessSet {
                            signatures_and_public_keys: vec![],
                            proof: indexer_service_protocol::Proof(vec![0; 32]),
                        },
                    }),
                    // PrivacyPreserving transactions
                    2 | 3 => Transaction::PrivacyPreserving(PrivacyPreservingTransaction {
                        hash: tx_hash,
                        message: PrivacyPreservingMessage {
                            public_account_ids: vec![
                                account_ids[tx_idx as usize % account_ids.len()],
                            ],
                            nonces: vec![block_id as u128],
                            public_post_states: vec![Account {
                                program_owner: ProgramId([1u32; 8]),
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
                        },
                        witness_set: WitnessSet {
                            signatures_and_public_keys: vec![],
                            proof: indexer_service_protocol::Proof(vec![0; 32]),
                        },
                    }),
                    // ProgramDeployment transactions (rare)
                    _ => Transaction::ProgramDeployment(ProgramDeploymentTransaction {
                        hash: tx_hash,
                        message: ProgramDeploymentMessage {
                            bytecode: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00], /* WASM magic number */
                        },
                    }),
                };

                transactions.insert(tx_hash, (tx.clone(), block_id));
                block_transactions.push(tx);
            }

            let block = Block {
                header: BlockHeader {
                    block_id,
                    prev_block_hash: prev_hash,
                    hash: block_hash,
                    timestamp: 1704067200000 + (block_id * 12000), // ~12 seconds per block
                    signature: Signature([0u8; 64]),
                },
                body: BlockBody {
                    transactions: block_transactions,
                },
                bedrock_status: match block_id {
                    0..=5 => BedrockStatus::Finalized,
                    6..=8 => BedrockStatus::Safe,
                    _ => BedrockStatus::Pending,
                },
                bedrock_parent_id: MantleMsgId([0; 32]),
            };

            prev_hash = block_hash;
            blocks.push(block);
        }

        Self {
            blocks,
            accounts,
            transactions,
        }
    }
}

#[async_trait::async_trait]
impl indexer_service_rpc::RpcServer for MockIndexerService {
    async fn subscribe_to_finalized_blocks(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        for block in self
            .blocks
            .iter()
            .filter(|b| b.bedrock_status == BedrockStatus::Finalized)
        {
            let json = serde_json::value::to_raw_value(block).unwrap();
            sink.send(json).await?;
        }
        Ok(())
    }

    async fn get_last_finalized_block_id(&self) -> Result<BlockId, ErrorObjectOwned> {
        self.blocks
            .last()
            .map(|bl| bl.header.block_id)
            .ok_or_else(|| {
                ErrorObjectOwned::owned(-32001, "Last block not found".to_string(), None::<()>)
            })
    }

    async fn get_block_by_id(&self, block_id: BlockId) -> Result<Block, ErrorObjectOwned> {
        self.blocks
            .iter()
            .find(|b| b.header.block_id == block_id)
            .cloned()
            .ok_or_else(|| {
                ErrorObjectOwned::owned(
                    -32001,
                    format!("Block with ID {} not found", block_id),
                    None::<()>,
                )
            })
    }

    async fn get_block_by_hash(&self, block_hash: HashType) -> Result<Block, ErrorObjectOwned> {
        self.blocks
            .iter()
            .find(|b| b.header.hash == block_hash)
            .cloned()
            .ok_or_else(|| ErrorObjectOwned::owned(-32001, "Block with hash not found", None::<()>))
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        self.accounts
            .get(&account_id)
            .cloned()
            .ok_or_else(|| ErrorObjectOwned::owned(-32001, "Account not found", None::<()>))
    }

    async fn get_transaction(&self, tx_hash: HashType) -> Result<Transaction, ErrorObjectOwned> {
        self.transactions
            .get(&tx_hash)
            .map(|(tx, _)| tx.clone())
            .ok_or_else(|| ErrorObjectOwned::owned(-32001, "Transaction not found", None::<()>))
    }

    async fn get_blocks(
        &self,
        before: Option<u64>,
        limit: u32,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        let start_id = before.map_or_else(|| self.blocks.len() as u64, |id| id.saturating_sub(1));

        let result = (1..=start_id)
            .rev()
            .take(limit as usize)
            .map_while(|block_id| self.blocks.get(block_id as usize - 1).cloned())
            .collect();

        Ok(result)
    }

    async fn get_transactions_by_account(
        &self,
        account_id: AccountId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Transaction>, ErrorObjectOwned> {
        let mut account_txs: Vec<_> = self
            .transactions
            .values()
            .filter(|(tx, _)| match tx {
                Transaction::Public(pub_tx) => pub_tx.message.account_ids.contains(&account_id),
                Transaction::PrivacyPreserving(priv_tx) => {
                    priv_tx.message.public_account_ids.contains(&account_id)
                }
                Transaction::ProgramDeployment(_) => false,
            })
            .collect();

        // Sort by block ID descending (most recent first)
        account_txs.sort_by_key(|b| std::cmp::Reverse(b.1));

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
