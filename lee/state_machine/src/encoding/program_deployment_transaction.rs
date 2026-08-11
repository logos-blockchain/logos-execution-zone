use crate::{
    ProgramDeploymentTransaction, error::LeeError, program_deployment_transaction::Message,
};

impl Message {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }
}

impl ProgramDeploymentTransaction {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LeeError> {
        Ok(borsh::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AccountId, PrivateKey, ProgramDeploymentTransaction, fees::FeeFields,
        program_deployment_transaction::Message, public_transaction::WitnessSet,
    };

    #[test]
    fn roundtrip() {
        let message = Message::new_feeless(vec![0xca, 0xfe, 0xca, 0xfe, 0x01, 0x02, 0x03]);
        let tx = ProgramDeploymentTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
        let bytes = tx.to_bytes();
        let tx_from_bytes = ProgramDeploymentTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }

    /// Nonzero fee fields, a witness and a fee witness all survive
    /// serialize -> deserialize -> hash unchanged.
    #[test]
    fn roundtrip_with_fee_fields_and_witnesses() {
        let signer = PrivateKey::try_new([3; 32]).unwrap();
        let sponsor = PrivateKey::try_new([4; 32]).unwrap();
        let message = Message::new(
            vec![0x7F, 0x45, 0x4C, 0x46],
            FeeFields::new(AccountId::new([9; 32]), 21_000, 7, 1_000_000),
        );
        let witness_set =
            WitnessSet::for_message(&message, &[&signer]).with_fee_signer(&message, &sponsor);
        let tx = ProgramDeploymentTransaction::new(message, witness_set);

        let tx_from_bytes = ProgramDeploymentTransaction::from_bytes(&tx.to_bytes()).unwrap();
        assert_eq!(tx, tx_from_bytes);
        assert_eq!(tx.hash(), tx_from_bytes.hash());
        assert_eq!(tx.message().hash(), tx_from_bytes.message().hash());
        assert_eq!(tx_from_bytes.message().fees().gas_limit, 21_000);
        assert!(tx_from_bytes.witness_set().fee_witness().is_some());
    }
}
