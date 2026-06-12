use serde::{Deserialize, Serialize};

use crate::{BlockId, Timestamp, message::Message};

/// Output committed to the journal by the sequencer aggregator circuit.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct SequencerAggregatorOutput {
    pub block_id: BlockId,
    pub timestamp: Timestamp,
    pub messages: Vec<Message>,
}
