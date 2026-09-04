//! Wire format for gossip messages.

use borsh::{BorshDeserialize, BorshSerialize};
use common::transaction::LeeTransaction;

/// One gossip payload; the Borsh discriminant tags the variant.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum GossipMessage {
    Transaction(LeeTransaction),
    SlashApproval(SlashApprovalMessage),
}

/// One sequencer's signature over an offence, for peers to collect.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SlashApprovalMessage {
    pub offender: [u8; 32],
    pub inscription: [u8; 32],
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}
