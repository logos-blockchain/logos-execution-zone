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
    use crate::key_management::ephemeral_key_holder::EphemeralKeyHolder;

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
        let key_chain_raw = r#"
            {
              "secret_spending_key": [
                208,
                155,
                82,
                128,
                101,
                206,
                20,
                95,
                241,
                147,
                159,
                231,
                207,
                78,
                152,
                28,
                114,
                111,
                61,
                69,
                254,
                51,
                242,
                28,
                28,
                195,
                170,
                242,
                160,
                24,
                47,
                189
              ],
              "private_key_holder": {
                "nullifier_secret_key": [
                  142,
                  76,
                  154,
                  157,
                  42,
                  40,
                  174,
                  199,
                  151,
                  63,
                  2,
                  216,
                  52,
                  103,
                  81,
                  42,
                  200,
                  177,
                  189,
                  49,
                  81,
                  39,
                  166,
                  139,
                  203,
                  154,
                  156,
                  166,
                  88,
                  159,
                  11,
                  151
                ],
                "viewing_secret_key": [
                  122,
                  94,
                  159,
                  21,
                  28,
                  49,
                  169,
                  79,
                  12,
                  156,
                  171,
                  90,
                  41,
                  216,
                  203,
                  75,
                  251,
                  192,
                  204,
                  217,
                  18,
                  49,
                  28,
                  219,
                  213,
                  147,
                  244,
                  194,
                  205,
                  237,
                  134,
                  36
                ]
              },
              "nullifer_public_key": [
                235,
                24,
                62,
                99,
                243,
                236,
                137,
                35,
                153,
                149,
                6,
                10,
                118,
                239,
                117,
                188,
                64,
                8,
                33,
                52,
                220,
                231,
                11,
                39,
                180,
                117,
                1,
                22,
                62,
                199,
                164,
                169
              ],
              "viewing_public_key": [
                2,
                253,
                204,
                5,
                212,
                86,
                249,
                156,
                132,
                143,
                1,
                172,
                80,
                61,
                18,
                185,
                233,
                36,
                221,
                58,
                64,
                110,
                89,
                242,
                202,
                230,
                154,
                66,
                45,
                252,
                138,
                174,
                37
              ]
            }
        "#;

        serde_json::from_str(key_chain_raw).unwrap()
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
