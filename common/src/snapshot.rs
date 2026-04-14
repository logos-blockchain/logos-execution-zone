use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::BlockId;
use serde::{Deserialize, Serialize};

/// A point-in-time snapshot of the sequencer's execution state, returned by the
/// `get_state_snapshot` RPC method and consumed by fork-mode startup.
///
/// `state_bytes` is an opaque Borsh-serialized `V03State`; callers that need to
/// deserialize it must depend on `nssa` directly.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct StateSnapshot {
    /// Borsh-serialized `V03State` — opaque to keep `common` independent of `nssa`.
    pub state_bytes: Vec<u8>,
    /// Chain height at the moment the snapshot was taken.
    pub block_id: BlockId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borsh_roundtrip() {
        let snapshot = StateSnapshot { state_bytes: vec![1, 2, 3, 4], block_id: 42 };
        let encoded = borsh::to_vec(&snapshot).unwrap();
        let decoded: StateSnapshot = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.block_id, 42);
        assert_eq!(decoded.state_bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn serde_roundtrip() {
        let snapshot = StateSnapshot { state_bytes: vec![0xff, 0x00], block_id: 7 };
        let json = serde_json::to_string(&snapshot).unwrap();
        let decoded: StateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.block_id, 7);
        assert_eq!(decoded.state_bytes, [0xff, 0x00]);
    }
}
