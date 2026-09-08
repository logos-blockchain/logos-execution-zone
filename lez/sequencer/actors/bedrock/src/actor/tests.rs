use common::{
    HashType,
    block::{Block, HashableBlockData},
    test_utils::sequencer_sign_key_for_testing,
};
use logos_blockchain_core::mantle::{
    SignedOps,
    ledger::verification_mode::StandardMode,
    ops::{
        Op, OpProof,
        channel::{
            ChannelId, MsgId,
            inscribe::{Inscription, InscriptionOp},
        },
    },
    transactions::{MantleTxBuilder, OpProofs, states::Unverified},
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::ChannelUpdateTx;

use super::channel_blocks;

/// A tx wrapping `block` in one inscribe op on `channel`.
fn inscribing_tx(channel: ChannelId, block: &Block) -> SignedOps<Unverified, StandardMode> {
    let inscription: Inscription = borsh::to_vec(block).expect("serialize").try_into().unwrap();
    let signer = Ed25519Key::generate(&mut rand::rngs::OsRng);
    let op = Op::ChannelInscribe(InscriptionOp {
        channel_id: channel,
        inscription,
        parent: MsgId::root(),
        signer: signer.public_key(),
    });
    let raw = MantleTxBuilder::new()
        .extend_ops([op])
        .expect("ops fit")
        .build()
        .expect("tx builds");
    // Extraction never checks the proof, only that there is one per op.
    let proof = OpProof::Ed25519Sig(signer.sign_payload(&[0; 32]));
    SignedOps::from_parts(raw, OpProofs::from([proof])).expect("one proof per op")
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
    let config = ChannelUpdateTx::Config(
        SignedOps::from_parts(raw, OpProofs::empty()).expect("no ops, no proofs"),
    );
    assert!(channel_blocks(&config, channel).is_empty());
}
