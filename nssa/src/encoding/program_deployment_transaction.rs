use crate::{ProgramDeploymentTransaction, error::NssaError};

impl ProgramDeploymentTransaction {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NssaError> {
        Ok(borsh::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ProgramDeploymentTransaction, program_deployment_transaction::Message};

    #[test]
    fn roundtrip() {
        let message = Message::new(vec![0xca, 0xfe, 0xca, 0xfe, 0x01, 0x02, 0x03]);
        let tx = ProgramDeploymentTransaction::new(message);
        let bytes = tx.to_bytes();
        let tx_from_bytes = ProgramDeploymentTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }
}
