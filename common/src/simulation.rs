use nssa::{Account, AccountId};
use nssa_core::{Commitment, Nullifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub error: Option<String>,
    pub accounts_modified: Vec<(AccountId, Account)>,
    pub nullifiers_created: Vec<Nullifier>,
    pub commitments_created: Vec<Commitment>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn simulation_result_serde_roundtrip() {
        use super::SimulationResult;
        let result = SimulationResult {
            success: true,
            error: None,
            accounts_modified: vec![],
            nullifiers_created: vec![],
            commitments_created: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: SimulationResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert!(back.error.is_none());
    }
}
