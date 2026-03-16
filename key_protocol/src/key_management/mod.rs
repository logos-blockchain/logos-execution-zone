use nssa_core::{
    NullifierPublicKey, SharedSecretKey,
    encryption::{EphemeralPublicKey, ViewingPublicKey},
};
use secret_holders::{PrivateKeyHolder, SecretSpendingKey, SeedHolder};
use serde::{Deserialize, Serialize};

pub type PublicAccountSigningKey = [u8; 32];

pub mod ephemeral_key_holder;
pub mod key_tree;
pub mod secret_holders;

#[derive(Serialize, Deserialize, Clone, Debug)]
/// Entrypoint to key management
pub struct KeyChain {
    pub secret_spending_key: SecretSpendingKey,
    pub private_key_holder: PrivateKeyHolder,
    pub nullifer_public_key: NullifierPublicKey,
    pub viewing_public_key: ViewingPublicKey,
}

impl KeyChain {
    pub fn new_os_random() -> Self {
        // Currently dropping SeedHolder at the end of initialization.
        // Now entirely sure if we need it in the future.
        let seed_holder = SeedHolder::new_os_random();
        let secret_spending_key = seed_holder.produce_top_secret_key_holder();

        let private_key_holder = secret_spending_key.produce_private_key_holder(None);

        let nullifer_public_key = private_key_holder.generate_nullifier_public_key();
        let viewing_public_key = private_key_holder.generate_viewing_public_key();

        Self {
            secret_spending_key,
            private_key_holder,
            nullifer_public_key,
            viewing_public_key,
        }
    }

    pub fn new_mnemonic(passphrase: String) -> Self {
        // Currently dropping SeedHolder at the end of initialization.
        // Not entirely sure if we need it in the future.
        let seed_holder = SeedHolder::new_mnemonic(passphrase);
        let secret_spending_key = seed_holder.produce_top_secret_key_holder();

        let private_key_holder = secret_spending_key.produce_private_key_holder(None);

        let nullifer_public_key = private_key_holder.generate_nullifier_public_key();
        let viewing_public_key = private_key_holder.generate_viewing_public_key();

        Self {
            secret_spending_key,
            private_key_holder,
            nullifer_public_key,
            viewing_public_key,
        }
    }

    pub fn calculate_shared_secret_receiver(
        &self,
        ephemeral_public_key_sender: EphemeralPublicKey,
        index: Option<u32>,
    ) -> SharedSecretKey {
        SharedSecretKey::new(
            &self.secret_spending_key.generate_viewing_secret_key(index),
            &ephemeral_public_key_sender,
        )
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::OsRng;
    use base58::ToBase58;
    use k256::{AffinePoint, elliptic_curve::group::GroupEncoding};
    use rand::RngCore;

    use super::*;
    use crate::key_management::{
        ephemeral_key_holder::EphemeralKeyHolder, key_tree::KeyTreePrivate,
    };

    #[test]
    fn test_new_os_random() {
        // Ensure that a new KeyChain instance can be created without errors.
        let account_id_key_holder = KeyChain::new_os_random();

        // Check that key holder fields are initialized with expected types
        assert_ne!(
            account_id_key_holder.nullifer_public_key.as_ref(),
            &[0u8; 32]
        );
    }

    #[test]
    fn test_calculate_shared_secret_receiver() {
        let account_id_key_holder = KeyChain::new_os_random();

        // Generate a random ephemeral public key sender
        let mut scalar = [0; 32];
        OsRng.fill_bytes(&mut scalar);
        let ephemeral_public_key_sender = EphemeralPublicKey::from_scalar(scalar);

        // Calculate shared secret
        let _shared_secret = account_id_key_holder
            .calculate_shared_secret_receiver(ephemeral_public_key_sender, None);
    }

    #[test]
    fn key_generation_test() {
        let seed_holder = SeedHolder::new_os_random();
        let top_secret_key_holder = seed_holder.produce_top_secret_key_holder();

        let utxo_secret_key_holder = top_secret_key_holder.produce_private_key_holder(None);

        let nullifer_public_key = utxo_secret_key_holder.generate_nullifier_public_key();
        let viewing_public_key = utxo_secret_key_holder.generate_viewing_public_key();

        let pub_account_signing_key = nssa::PrivateKey::new_os_random();

        let public_key = nssa::PublicKey::new_from_private_key(&pub_account_signing_key);

        let account = nssa::AccountId::from(&public_key);

        println!("======Prerequisites======");
        println!();

        println!(
            "Group generator {:?}",
            hex::encode(AffinePoint::GENERATOR.to_bytes())
        );
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
            hex::encode(nullifer_public_key.to_byte_array())
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
        let (second_child_id, _) = key_tree_private.generate_new_node_layered().unwrap();

        key_tree_private
            .get_node(second_child_id)
            .unwrap()
            .value
            .0
            .clone()
    }

    #[test]
    fn test_non_trivial_chain_index() {
        let keys = account_with_chain_index_2_for_tests();

        let eph_key_holder = EphemeralKeyHolder::new(&keys.nullifer_public_key);

        let key_sender = eph_key_holder.calculate_shared_secret_sender(&keys.viewing_public_key);
        let key_receiver = keys.calculate_shared_secret_receiver(
            eph_key_holder.generate_ephemeral_public_key(),
            Some(2),
        );

        assert_eq!(key_sender.0, key_receiver.0);
    }
}
