use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::HashType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TxStatus {
    Pending,
    Included { block_id: u64 },
    Rejected { reason: String },
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    pub tx_hash: HashType,
    pub status: TxStatus,
    pub timestamp_ms: Option<u64>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RejectedTxRecord {
    pub reason: String,
    pub timestamp_ms: u64,
    pub block_height: u64,
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejected_tx_record_borsh_roundtrip() {
        use super::RejectedTxRecord;
        let record = RejectedTxRecord {
            reason: "nonce mismatch".to_owned(),
            timestamp_ms: 1_700_000_000_000,
            block_height: 42,
        };
        let encoded = borsh::to_vec(&record).unwrap();
        let decoded: RejectedTxRecord = borsh::from_slice(&encoded).unwrap();
        assert_eq!(record.reason, decoded.reason);
        assert_eq!(record.timestamp_ms, decoded.timestamp_ms);
        assert_eq!(record.block_height, decoded.block_height);
    }

    #[test]
    fn tx_status_serde_roundtrip() {
        use super::TxStatus;
        let status = TxStatus::Rejected { reason: "bad sig".to_owned() };
        let json = serde_json::to_string(&status).unwrap();
        let back: TxStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, TxStatus::Rejected { .. }));
    }
}
