//! Conversions between [`protocol`] and [`entities`] types.

use crate::{actor::entities, protocol};

impl From<crate::actor::db::Error> for crate::error::Error {
    fn from(error: crate::actor::db::Error) -> Self {
        Self::DatabaseError(anyhow::anyhow!(error))
    }
}

impl From<protocol::ZoneAnchorRecord> for entities::ZoneAnchor {
    fn from(anchor: protocol::ZoneAnchorRecord) -> Self {
        Self {
            slot: anchor.slot,
            block_id: anchor.block_id,
            hash: anchor.hash,
        }
    }
}

impl From<entities::ZoneAnchor> for protocol::ZoneAnchorRecord {
    fn from(anchor: entities::ZoneAnchor) -> Self {
        Self {
            slot: anchor.slot,
            block_id: anchor.block_id,
            hash: anchor.hash,
        }
    }
}

impl From<protocol::PendingDepositEventRecord> for entities::PendingDeposit {
    fn from(record: protocol::PendingDepositEventRecord) -> Self {
        Self {
            deposit_op_id: record.deposit_op_id,
            source_tx_hash: record.source_tx_hash,
            amount: record.amount,
            metadata: record.metadata,
        }
    }
}

impl From<entities::PendingDeposit> for protocol::PendingDepositEventRecord {
    fn from(event: entities::PendingDeposit) -> Self {
        Self {
            deposit_op_id: event.deposit_op_id,
            source_tx_hash: event.source_tx_hash,
            amount: event.amount,
            metadata: event.metadata,
        }
    }
}

impl From<protocol::WithdrawalReconciliationKey> for entities::WithdrawalReconciliationKey {
    fn from(value: protocol::WithdrawalReconciliationKey) -> Self {
        Self {
            released_note_id: value.released_note_id,
        }
    }
}

impl From<entities::WithdrawalReconciliationKey> for protocol::WithdrawalReconciliationKey {
    fn from(value: entities::WithdrawalReconciliationKey) -> Self {
        Self {
            released_note_id: value.released_note_id,
        }
    }
}
