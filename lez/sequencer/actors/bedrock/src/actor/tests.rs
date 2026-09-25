use common::{
    HashType,
    block::{Block, HashableBlockData},
    test_utils::sequencer_sign_key_for_testing,
};
use logos_blockchain_core::mantle::{
    SignedOps,
    channel::Channels,
    ledger::{VerifiableOperation as _, verification_mode::StandardMode},
    ops::{
        Op, OpProof, SignedOperation,
        channel::{
            ChannelId, MsgId, VerifiedChannelKeys,
            config::ChannelConfigValidationContext,
            inscribe::{Inscription, InscriptionOp},
        },
    },
    transactions::{
        MantleTxBuilder, OpProofs,
        hash::{TxHash, TxHashView},
        states::Unverified,
    },
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::ChannelUpdateTx;

use super::channel_entries;
use crate::protocol::ChannelParams;

/// A tx wrapping `block` in one inscribe op on `channel`.
fn inscribing_tx(channel: ChannelId, block: &Block) -> SignedOps<Unverified, StandardMode> {
    let inscription: Inscription = borsh::to_vec(block).expect("serialize").try_into().unwrap();
    let signer = Ed25519Key::generate(&mut rand::rngs::OsRng);
    let op = Op::ChannelInscribe(InscriptionOp {
        channel_id: channel,
        inscription,
        parent: MsgId::root(),
        signer: signer.public_key().into_unverified(),
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
    let entries = channel_entries(&custom, channel);

    assert_eq!(entries.len(), 1, "the Custom tx carries one entry");
    let carried = entries[0]
        .block
        .as_ref()
        .expect("the entry carries a block");
    assert_eq!(carried.header.block_id, 7);
    assert_eq!(carried.header.hash, block.header.hash);
}

#[test]
fn a_config_tx_yields_nothing() {
    let channel = ChannelId::from([1; 32]);
    let raw = MantleTxBuilder::new().build().expect("tx builds");
    let config = ChannelUpdateTx::Config(
        SignedOps::from_parts(raw, OpProofs::empty()).expect("no ops, no proofs"),
    );
    assert!(channel_entries(&config, channel).is_empty());
}

/// Bedrock verifies a channel-creating config op against a threshold of zero,
/// so the op we build must pass with the proof we pair it with. A proof holding
/// even our own signature sinks the whole creation tx, and with it the channel.
#[test]
fn the_genesis_config_op_and_its_proof_pass_bedrock_verification() {
    let keys = VerifiedChannelKeys::from(Ed25519Key::generate(&mut rand::rngs::OsRng).public_key());
    let op = super::genesis_config_op(
        ChannelId::from([1; 32]),
        keys,
        &ChannelParams {
            minimum_sequencer_stake: 0,
            posting_timeframe: 10,
            posting_timeout: 20,
            exit_delay: 10,
        },
        1,
    );
    let tx_hash_view = TxHashView::new(TxHash::from([7; 32]));

    let signed = SignedOperation::<_, Unverified, StandardMode>::new(
        op,
        super::genesis_config_proof().expect("the proof is well formed"),
    )
    .into_preverified(&())
    .expect("the config is well formed");

    signed
        .verify(&ChannelConfigValidationContext {
            // An empty ledger: the channel this op creates does not exist yet.
            channels: &Channels::new(),
            tx_hash_view: &tx_hash_view,
        })
        .expect("Bedrock accepts the channel-creating config op");
}
