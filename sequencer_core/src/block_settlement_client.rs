use anyhow::{Context, Result};
use bedrock_client::BedrockClient;
pub use common::block::Block;
pub use logos_blockchain_core::mantle::{MantleTx, SignedMantleTx, ops::channel::MsgId};
use logos_blockchain_core::mantle::{
    Op, OpProof, Transaction, TxHash, ledger,
    ops::channel::{ChannelId, inscribe::InscriptionOp},
};
pub use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_key_management_system_service::keys::Ed25519PublicKey;

use crate::config::BedrockConfig;

#[expect(async_fn_in_trait, reason = "We don't care about Send/Sync here")]
pub trait BlockSettlementClientTrait: Clone {
    //// Create a new client.
    fn new(config: &BedrockConfig, bedrock_signing_key: Ed25519Key) -> Result<Self>;

    /// Get the bedrock channel ID used by this client.
    fn bedrock_channel_id(&self) -> ChannelId;

    /// Get the bedrock signing key used by this client.
    fn bedrock_signing_key(&self) -> &Ed25519Key;

    /// Post a transaction to the node.
    async fn submit_inscribe_tx_to_bedrock(&self, tx: SignedMantleTx) -> Result<()>;

    /// Create and sign a transaction for inscribing data.
    fn create_inscribe_tx(&self, block: &Block) -> Result<(SignedMantleTx, MsgId)> {
        let inscription_data = borsh::to_vec(block)?;
        log::debug!(
            "The size of the block {} is {} bytes",
            block.header.block_id,
            inscription_data.len()
        );
        let verifying_key_bytes = self.bedrock_signing_key().public_key().to_bytes();
        let verifying_key =
            Ed25519PublicKey::from_bytes(&verifying_key_bytes).expect("valid ed25519 public key");

        let inscribe_op = InscriptionOp {
            channel_id: self.bedrock_channel_id(),
            inscription: inscription_data,
            parent: block.bedrock_parent_id.into(),
            signer: verifying_key,
        };
        let inscribe_op_id = inscribe_op.id();

        let ledger_tx = ledger::Tx::new(vec![], vec![]);

        let inscribe_tx = MantleTx {
            ops: vec![Op::ChannelInscribe(inscribe_op)],
            ledger_tx,
            // Altruistic test config
            storage_gas_price: 0,
            execution_gas_price: 0,
        };

        let tx_hash = inscribe_tx.hash();
        let signature_bytes = self
            .bedrock_signing_key()
            .sign_payload(tx_hash.as_signing_bytes().as_ref())
            .to_bytes();
        let signature =
            logos_blockchain_key_management_system_service::keys::Ed25519Signature::from_bytes(
                &signature_bytes,
            );

        let signed_mantle_tx = SignedMantleTx {
            ops_proofs: vec![OpProof::Ed25519Sig(signature)],
            ledger_tx_proof: empty_ledger_signature(&tx_hash),
            mantle_tx: inscribe_tx,
        };
        Ok((signed_mantle_tx, inscribe_op_id))
    }
}

/// A component that posts block data to logos blockchain
#[derive(Clone)]
pub struct BlockSettlementClient {
    bedrock_client: BedrockClient,
    bedrock_signing_key: Ed25519Key,
    bedrock_channel_id: ChannelId,
}

impl BlockSettlementClientTrait for BlockSettlementClient {
    fn new(config: &BedrockConfig, bedrock_signing_key: Ed25519Key) -> Result<Self> {
        let bedrock_client =
            BedrockClient::new(config.backoff, config.node_url.clone(), config.auth.clone())
                .context("Failed to initialize bedrock client")?;
        Ok(Self {
            bedrock_client,
            bedrock_signing_key,
            bedrock_channel_id: config.channel_id,
        })
    }

    async fn submit_inscribe_tx_to_bedrock(&self, tx: SignedMantleTx) -> Result<()> {
        let (parent_id, msg_id) = match tx.mantle_tx.ops.first() {
            Some(Op::ChannelInscribe(inscribe)) => (inscribe.parent, inscribe.id()),
            _ => panic!("Expected ChannelInscribe op"),
        };
        self.bedrock_client
            .post_transaction(tx)
            .await
            .context("Failed to post transaction to Bedrock after retries")?
            .context("Failed to post transaction to Bedrock with non-retryable error")?;

        log::debug!("Posted block to Bedrock with parent id {parent_id:?} and msg id: {msg_id:?}");

        Ok(())
    }

    fn bedrock_channel_id(&self) -> ChannelId {
        self.bedrock_channel_id
    }

    fn bedrock_signing_key(&self) -> &Ed25519Key {
        &self.bedrock_signing_key
    }
}

fn empty_ledger_signature(
    tx_hash: &TxHash,
) -> logos_blockchain_key_management_system_service::keys::ZkSignature {
    logos_blockchain_key_management_system_service::keys::ZkKey::multi_sign(&[], tx_hash.as_ref())
        .expect("multi-sign with empty key set works")
}
