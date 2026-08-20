//! Chain-builder helpers shared by the watcher's and verifier's tests, so both
//! sides exercise the acceptance policy against identically built peer chains.

use common::{block::Block, test_utils::produce_dummy_block, transaction::LeeTransaction};
use cross_zone_inbox_core::ZoneId;
use lee::{
    GENESIS_BLOCK_ID, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use lee_core::program::ProgramId;
use ping_core::{SenderInstruction, ping_record_pda, receiver_config_account_id};

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

/// A `ping_sender` emission aimed at `target_zone` and `target_program_id`,
/// carrying `payload`. The sender lets its caller name any target, which is why
/// routes pin the pair rather than the target alone.
#[must_use]
pub fn ping_emission(
    target_zone: ZoneId,
    target_program_id: ProgramId,
    payload: &[u8],
) -> LeeTransaction {
    let receiver_id = programs::ping_receiver().id();
    let send = SenderInstruction::Send {
        target_zone,
        target_program_id,
        target_accounts: vec![
            receiver_config_account_id(receiver_id).into_value(),
            ping_record_pda(receiver_id).into_value(),
        ],
        payload: payload.to_vec(),
        ordinal: 0,
    };
    let message = Message::try_new(programs::ping_sender().id(), vec![], vec![], send)
        .expect("emission serializes");
    LeeTransaction::Public(PublicTransaction::new(
        message,
        WitnessSet::from_raw_parts(vec![]),
    ))
}
