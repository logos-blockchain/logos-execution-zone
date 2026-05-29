use lee_core::{
    NullifierPublicKey, SharedSecretKey,
    encryption::{EphemeralPublicKey, ViewingPublicKey},
};
use secret_holders::{PrivateKeyHolder, SecretSpendingKey, SeedHolder};
use serde::{Deserialize, Serialize};

pub mod ephemeral_key_holder;
pub mod group_key_holder;
pub mod key_tree;
pub mod secret_holders;

pub type PublicAccountSigningKey = [u8; 32];

/// Private account keychain.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyChain {
    pub secret_spending_key: SecretSpendingKey,
    pub private_key_holder: PrivateKeyHolder,
    pub nullifier_public_key: NullifierPublicKey,
    pub viewing_public_key: ViewingPublicKey,
}

impl KeyChain {
    #[must_use]
    pub fn new_os_random() -> Self {
        // Currently dropping SeedHolder at the end of initialization.
        // Now entirely sure if we need it in the future.
        let seed_holder = SeedHolder::new_os_random();
        let secret_spending_key = seed_holder.produce_top_secret_key_holder();

        let private_key_holder = secret_spending_key.produce_private_key_holder(None);

        let nullifier_public_key = private_key_holder.generate_nullifier_public_key();
        let viewing_public_key = private_key_holder.generate_viewing_public_key();

        Self {
            secret_spending_key,
            private_key_holder,
            nullifier_public_key,
            viewing_public_key,
        }
    }

    #[must_use]
    pub fn new_mnemonic(passphrase: &str) -> (Self, bip39::Mnemonic) {
        // Currently dropping SeedHolder at the end of initialization.
        // Not entirely sure if we need it in the future.
        let (seed_holder, mnemonic) = SeedHolder::new_mnemonic(passphrase);
        let secret_spending_key = seed_holder.produce_top_secret_key_holder();

        let private_key_holder = secret_spending_key.produce_private_key_holder(None);

        let nullifier_public_key = private_key_holder.generate_nullifier_public_key();
        let viewing_public_key = private_key_holder.generate_viewing_public_key();

        (
            Self {
                secret_spending_key,
                private_key_holder,
                nullifier_public_key,
                viewing_public_key,
            },
            mnemonic,
        )
    }

    #[must_use]
    pub fn calculate_shared_secret_receiver(
        &self,
        ephemeral_public_key_sender: &EphemeralPublicKey,
    ) -> Option<SharedSecretKey> {
        let vsk = &self.private_key_holder.viewing_secret_key;
        SharedSecretKey::decapsulate(ephemeral_public_key_sender, &vsk.d, &vsk.z)
    }
}

#[cfg(test)]
mod tests {
    use base58::ToBase58 as _;

    use super::*;
    use crate::key_management::{
        ephemeral_key_holder::EphemeralKeyHolder, key_tree::KeyTreePrivate,
    };

    #[test]
    fn new_os_random() {
        // Ensure that a new KeyChain instance can be created without errors.
        let account_id_key_holder = KeyChain::new_os_random();

        // Check that key holder fields are initialized with expected types
        assert_ne!(
            account_id_key_holder.nullifier_public_key.as_ref(),
            &[0_u8; 32]
        );
    }

    #[test]
    fn calculate_shared_secret_receiver() {
        let account_id_key_holder = KeyChain::new_os_random();

        // Create a proper KEM ciphertext by encapsulating toward this key chain's VPK.
        let (_, epk) = SharedSecretKey::encapsulate(&account_id_key_holder.viewing_public_key);

        let _shared_secret = account_id_key_holder.calculate_shared_secret_receiver(&epk);
    }

    #[test]
    fn calculate_shared_secret_receiver_returns_none_for_malformed_epk() {
        let key_chain = KeyChain::new_os_random();

        let short_epk = EphemeralPublicKey(vec![42_u8; 100]);
        assert!(
            key_chain
                .calculate_shared_secret_receiver(&short_epk)
                .is_none(),
            "short EphemeralPublicKey must return None"
        );

        let long_epk = EphemeralPublicKey(vec![42_u8; 1089]);
        assert!(
            key_chain
                .calculate_shared_secret_receiver(&long_epk)
                .is_none(),
            "long EphemeralPublicKey must return None"
        );
    }

    #[test]
    fn key_generation_test() {
        let seed_holder = SeedHolder::new_os_random();
        let top_secret_key_holder = seed_holder.produce_top_secret_key_holder();

        let utxo_secret_key_holder = top_secret_key_holder.produce_private_key_holder(None);

        let nullifier_public_key = utxo_secret_key_holder.generate_nullifier_public_key();
        let viewing_public_key = utxo_secret_key_holder.generate_viewing_public_key();

        let pub_account_signing_key = lee::PrivateKey::new_os_random();

        let public_key = lee::PublicKey::new_from_private_key(&pub_account_signing_key);

        let account = lee::AccountId::from(&public_key);

        println!("======Prerequisites======");
        println!();

        println!("======Holders======");
        println!();

        println!("{seed_holder:?}");
        println!("{top_secret_key_holder:?}");
        println!("{utxo_secret_key_holder:?}");
        println!();

        println!("======Public data======");
        println!();
        println!("Account {:?}", account.value().to_base58());
        println!(
            "Nulifier public key {:?}",
            hex::encode(nullifier_public_key.to_byte_array())
        );
        println!(
            "Viewing public key {:?}",
            hex::encode(viewing_public_key.to_bytes())
        );
    }

    fn account_with_chain_index_2_for_tests() -> KeyChain {
        let seed = SeedHolder::new_os_random();
        let mut key_tree_private = KeyTreePrivate::new(&seed);

        // /0
        key_tree_private.generate_new_node_layered().unwrap();
        // /1
        key_tree_private.generate_new_node_layered().unwrap();
        // /0/0
        key_tree_private.generate_new_node_layered().unwrap();
        // /2
        let second_chain_index = key_tree_private.generate_new_node_layered().unwrap();

        key_tree_private
            .key_map
            .get(&second_chain_index)
            .expect("Node was just inserted")
            .value
            .0
            .clone()
    }

    #[test]
    fn non_trivial_chain_index() {
        let keys = account_with_chain_index_2_for_tests();

        let eph_key_holder = EphemeralKeyHolder::new(&keys.viewing_public_key);

        let key_sender = eph_key_holder.calculate_shared_secret_sender();
        let key_receiver =
            keys.calculate_shared_secret_receiver(eph_key_holder.ephemeral_public_key());

        assert_eq!(key_sender.0, key_receiver.unwrap().0);
    }
}
