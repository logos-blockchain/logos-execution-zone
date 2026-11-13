//! Chain-builder helpers shared by the watcher's and verifier's tests, so both
//! sides exercise the acceptance policy against identically built peer chains.

use common::{
    block::Block,
    test_utils::{produce_dummy_block, produce_dummy_block_with_outbound},
    transaction::LeeTransaction,
};
use cross_zone_inbox_core::ZoneId;
use lee::GENESIS_BLOCK_ID;
use lee_core::account::Actor;
use ping_core::{ping_record_pda, receiver_config_account_id, sender_config_account_id};

/// The peer's hash-linked chain from its genesis up to and including `last`,
/// each block carrying the transactions `txs_at(block_id)` returns. Empty when
/// `last` is below [`GENESIS_BLOCK_ID`].
pub fn linked_chain_to(last: u64, txs_at: impl Fn(u64) -> Vec<LeeTransaction>) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    for block_id in GENESIS_BLOCK_ID..=last {
        let prev = blocks.last().map(|block| block.header.hash);
        blocks.push(produce_dummy_block(block_id, prev, txs_at(block_id)));
    }
    blocks
}

/// The outbound message of a ping aimed at this zone's `ping_receiver`,
/// declaring the actors its delivery reaches.
#[must_use]
pub fn ping_outbound(target_zone: ZoneId, payload: &[u8]) -> lee::OutboundMessage {
    let receiver_id = programs::ping_receiver_account_id();
    let sender_id = programs::ping_sender_account_id();
    lee::OutboundMessage {
        from: Actor::new(sender_config_account_id(sender_id), sender_id),
        zone: target_zone,
        to: Actor::new(receiver_id, receiver_id),
        message: payload.to_vec(),
        accounts: vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(ping_record_pda(receiver_id), receiver_id),
        ],
    }
}

/// The peer's hash-linked chain whose blocks declare `outbound_at(block_id)`.
#[must_use]
pub fn linked_chain_with_outbound(
    last: u64,
    outbound_at: impl Fn(u64) -> Vec<lee::OutboundMessage>,
) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    for block_id in GENESIS_BLOCK_ID..=last {
        let prev = blocks.last().map(|block| block.header.hash);
        blocks.push(produce_dummy_block_with_outbound(
            block_id,
            prev,
            outbound_at(block_id),
        ));
    }
    blocks
}
