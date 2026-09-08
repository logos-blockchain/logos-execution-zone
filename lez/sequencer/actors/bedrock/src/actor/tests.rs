use common::{
    HashType,
    block::{Block, HashableBlockData},
    test_utils::sequencer_sign_key_for_testing,
};
use logos_blockchain_core::mantle::{
    ops::{
        Op,
        channel::{
            ChannelId, MsgId,
            inscribe::{Inscription, InscriptionOp},
        },
    },
    transactions::{MantleTxBuilder, OpsProofs, SignedMantleTx, states::Unverified},
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::ChannelUpdateTx;

use super::channel_blocks;

/// A tx wrapping `block` in one inscribe op on `channel`.
fn inscribing_tx(channel: ChannelId, block: &Block) -> SignedMantleTx<Unverified> {
    let inscription: Inscription = borsh::to_vec(block).expect("serialize").try_into().unwrap();
    let op = Op::ChannelInscribe(InscriptionOp {
        channel_id: channel,
        inscription,
        parent: MsgId::root(),
        signer: Ed25519Key::generate(&mut rand::rngs::OsRng).public_key(),
    });
    let raw = MantleTxBuilder::new()
        .extend_ops([op])
        .expect("ops fit")
        .build()
        .expect("tx builds");
    SignedMantleTx::new(raw, OpsProofs::empty())
}

#[test]
fn a_custom_tx_yields_its_block() {
    let channel = ChannelId::from([1; 32]);
    let block = HashableBlockData {
        block_id: 7,
        prev_block_hash: HashType([0; 32]),
        timestamp: 700,
        transactions: Vec::new(),
    }
    .into_pending_block(&sequencer_sign_key_for_testing());

    let custom = ChannelUpdateTx::Custom(inscribing_tx(channel, &block));
    let blocks = channel_blocks(&custom, channel);

    assert_eq!(blocks.len(), 1, "the Custom tx carries one block");
    assert_eq!(blocks[0].header.block_id, 7);
    assert_eq!(blocks[0].header.hash, block.header.hash);
}

#[test]
fn a_config_tx_yields_nothing() {
    let channel = ChannelId::from([1; 32]);
    let raw = MantleTxBuilder::new().build().expect("tx builds");
    let config = ChannelUpdateTx::Config(SignedMantleTx::new(raw, OpsProofs::empty()));
    assert!(channel_blocks(&config, channel).is_empty());
}
