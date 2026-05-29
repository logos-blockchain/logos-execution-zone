use common::PINATA_BASE58;
use key_protocol::key_management::{
    KeyChain,
    key_tree::chain_index::ChainIndex,
    secret_holders::{PrivateKeyHolder, SecretSpendingKey, ViewingSecretKey},
};
use lee::{Account, AccountId, Data, PrivateKey, PublicKey, V03State};
use lee_core::{NullifierPublicKey, encryption::ViewingPublicKey};
use serde::{Deserialize, Serialize};

const PRIVATE_KEY_PUB_ACC_A: [u8; 32] = [
    16, 162, 106, 154, 236, 125, 52, 184, 35, 100, 238, 174, 69, 197, 41, 77, 187, 10, 118, 75, 0,
    11, 148, 238, 185, 181, 133, 17, 220, 72, 124, 77,
];

const PRIVATE_KEY_PUB_ACC_B: [u8; 32] = [
    113, 121, 64, 177, 204, 85, 229, 214, 178, 6, 109, 191, 29, 154, 63, 38, 242, 18, 244, 219, 8,
    208, 35, 136, 23, 127, 207, 237, 216, 169, 190, 27,
];

const SSK_PRIV_ACC_A: [u8; 32] = [
    93, 13, 190, 240, 250, 33, 108, 195, 176, 40, 144, 61, 4, 28, 58, 112, 53, 161, 42, 238, 155,
    27, 23, 176, 208, 121, 15, 229, 165, 180, 99, 143,
];

const SSK_PRIV_ACC_B: [u8; 32] = [
    48, 175, 124, 10, 230, 240, 166, 14, 249, 254, 157, 226, 208, 124, 122, 177, 203, 139, 192,
    180, 43, 120, 55, 151, 50, 21, 113, 22, 254, 83, 148, 56,
];

const NSK_PRIV_ACC_A: [u8; 32] = [
    25, 21, 186, 59, 180, 224, 101, 64, 163, 208, 228, 43, 13, 185, 100, 123, 156, 47, 80, 179, 72,
    51, 115, 11, 180, 99, 21, 201, 48, 194, 118, 144,
];

const NSK_PRIV_ACC_B: [u8; 32] = [
    99, 82, 190, 140, 234, 10, 61, 163, 15, 211, 179, 54, 70, 166, 87, 5, 182, 68, 117, 244, 217,
    23, 99, 9, 4, 177, 230, 125, 109, 91, 160, 30,
];

const VSK_D_PRIV_ACC_A: [u8; 32] = [
    255, 250, 140, 26, 222, 223, 174, 95, 132, 108, 124, 88, 30, 247, 82, 72, 52, 70, 84, 139, 241,
    187, 41, 163, 19, 231, 232, 122, 225, 55, 134, 184,
];

const VSK_Z_PRIV_ACC_A: [u8; 32] = [
    225, 24, 98, 78, 31, 203, 175, 248, 213, 17, 133, 207, 10, 135, 132, 151, 59, 184, 5, 81, 28,
    238, 137, 62, 233, 227, 99, 17, 236, 159, 244, 63,
];

const VSK_D_PRIV_ACC_B: [u8; 32] = [
    128, 85, 85, 103, 226, 218, 119, 56, 60, 252, 31, 113, 232, 215, 156, 2, 159, 247, 156, 192,
    12, 178, 229, 236, 255, 120, 146, 211, 169, 117, 153, 180,
];

const VSK_Z_PRIV_ACC_B: [u8; 32] = [
    165, 80, 169, 87, 248, 88, 167, 154, 27, 67, 131, 122, 50, 130, 111, 40, 164, 180, 204, 75,
    188, 140, 110, 132, 113, 133, 222, 8, 49, 123, 187, 18,
];

const NPK_PRIV_ACC_A: [u8; 32] = [
    167, 108, 50, 153, 74, 47, 151, 188, 140, 79, 195, 31, 181, 9, 40, 167, 201, 32, 175, 129, 45,
    245, 223, 193, 210, 170, 247, 128, 167, 140, 155, 129,
];

const NPK_PRIV_ACC_B: [u8; 32] = [
    32, 67, 72, 164, 106, 53, 66, 239, 141, 15, 52, 230, 136, 177, 2, 236, 207, 243, 134, 135, 210,
    143, 87, 232, 215, 128, 194, 120, 113, 224, 4, 165,
];

const DEFAULT_PROGRAM_OWNER: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

const PUB_ACC_A_INITIAL_BALANCE: u128 = 10000;
const PUB_ACC_B_INITIAL_BALANCE: u128 = 20000;

const PRIV_ACC_A_INITIAL_BALANCE: u128 = 10000;
const PRIV_ACC_B_INITIAL_BALANCE: u128 = 20000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAccountPublicInitialData {
    pub account_id: AccountId,
    pub balance: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateAccountPublicInitialData {
    pub npk: lee_core::NullifierPublicKey,
    pub account: lee_core::account::Account,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAccountPrivateInitialData {
    pub account_id: lee::AccountId,
    pub pub_sign_key: lee::PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAccountPrivateInitialData {
    pub account: lee_core::account::Account,
    pub key_chain: KeyChain,
    pub chain_index: Option<ChainIndex>,
    pub identifier: lee_core::Identifier,
}

impl PrivateAccountPrivateInitialData {
    #[must_use]
    pub fn account_id(&self) -> lee::AccountId {
        lee::AccountId::for_regular_private_account(
            &self.key_chain.nullifier_public_key,
            self.identifier,
        )
    }
}

#[must_use]
pub fn initial_pub_accounts_private_keys() -> Vec<PublicAccountPrivateInitialData> {
    let acc1_pub_sign_key = PrivateKey::try_new(PRIVATE_KEY_PUB_ACC_A).unwrap();

    let acc2_pub_sign_key = PrivateKey::try_new(PRIVATE_KEY_PUB_ACC_B).unwrap();

    vec![
        PublicAccountPrivateInitialData {
            account_id: AccountId::from(&PublicKey::new_from_private_key(&acc1_pub_sign_key)),
            pub_sign_key: acc1_pub_sign_key,
        },
        PublicAccountPrivateInitialData {
            account_id: AccountId::from(&PublicKey::new_from_private_key(&acc2_pub_sign_key)),
            pub_sign_key: acc2_pub_sign_key,
        },
    ]
}

#[must_use]
pub fn initial_priv_accounts_private_keys() -> Vec<PrivateAccountPrivateInitialData> {
    let key_chain_1 = KeyChain {
        secret_spending_key: SecretSpendingKey(SSK_PRIV_ACC_A),
        private_key_holder: PrivateKeyHolder {
            nullifier_secret_key: NSK_PRIV_ACC_A,
            viewing_secret_key: ViewingSecretKey::new(VSK_D_PRIV_ACC_A, VSK_Z_PRIV_ACC_A),
        },
        nullifier_public_key: NullifierPublicKey(NPK_PRIV_ACC_A),
        viewing_public_key: ViewingPublicKey::from_seed(&VSK_D_PRIV_ACC_A, &VSK_Z_PRIV_ACC_A),
    };

    let key_chain_2 = KeyChain {
        secret_spending_key: SecretSpendingKey(SSK_PRIV_ACC_B),
        private_key_holder: PrivateKeyHolder {
            nullifier_secret_key: NSK_PRIV_ACC_B,
            viewing_secret_key: ViewingSecretKey::new(VSK_D_PRIV_ACC_B, VSK_Z_PRIV_ACC_B),
        },
        nullifier_public_key: NullifierPublicKey(NPK_PRIV_ACC_B),
        viewing_public_key: ViewingPublicKey::from_seed(&VSK_D_PRIV_ACC_B, &VSK_Z_PRIV_ACC_B),
    };

    vec![
        PrivateAccountPrivateInitialData {
            account: Account {
                program_owner: DEFAULT_PROGRAM_OWNER,
                balance: PRIV_ACC_A_INITIAL_BALANCE,
                data: Data::default(),
                nonce: 0.into(),
            },
            key_chain: key_chain_1,
            chain_index: None,
            identifier: 0,
        },
        PrivateAccountPrivateInitialData {
            account: Account {
                program_owner: DEFAULT_PROGRAM_OWNER,
                balance: PRIV_ACC_B_INITIAL_BALANCE,
                data: Data::default(),
                nonce: 0.into(),
            },
            key_chain: key_chain_2,
            chain_index: None,
            identifier: 0,
        },
    ]
}

#[must_use]
pub fn initial_commitments() -> Vec<PrivateAccountPublicInitialData> {
    initial_priv_accounts_private_keys()
        .into_iter()
        .map(|data| PrivateAccountPublicInitialData {
            npk: data.key_chain.nullifier_public_key,
            account: data.account,
        })
        .collect()
}

#[must_use]
pub fn initial_accounts() -> Vec<PublicAccountPublicInitialData> {
    let initial_account_ids = initial_pub_accounts_private_keys()
        .into_iter()
        .map(|data| data.account_id)
        .collect::<Vec<_>>();

    vec![
        PublicAccountPublicInitialData {
            account_id: initial_account_ids[0],
            balance: PUB_ACC_A_INITIAL_BALANCE,
        },
        PublicAccountPublicInitialData {
            account_id: initial_account_ids[1],
            balance: PUB_ACC_B_INITIAL_BALANCE,
        },
    ]
}

#[must_use]
pub fn initial_state() -> V03State {
    let initial_private_accounts: Vec<(lee_core::Commitment, lee_core::Nullifier)> =
        initial_commitments()
            .iter()
            .map(|init_comm_data| {
                let npk = &init_comm_data.npk;
                let account_id = lee::AccountId::for_regular_private_account(npk, 0);

                let mut acc = init_comm_data.account.clone();

                acc.program_owner = lee::program::Program::authenticated_transfer_program().id();

                (
                    lee_core::Commitment::new(&account_id, &acc),
                    lee_core::Nullifier::for_account_initialization(&account_id),
                )
            })
            .collect();

    let init_accs: Vec<(lee::AccountId, u128)> = initial_accounts()
        .iter()
        .map(|acc_data| (acc_data.account_id, acc_data.balance))
        .collect();

    lee::V03State::new_with_genesis_accounts(&init_accs, initial_private_accounts, 0)
}

#[must_use]
pub fn initial_state_testnet() -> V03State {
    let mut state = initial_state();

    state.add_pinata_program(PINATA_BASE58.parse().unwrap());

    state
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    const PUB_ACC_A_TEXT_ADDR: &str = "6iArKUXxhUJqS7kCaPNhwMWt3ro71PDyBj7jwAyE2VQV";
    const PUB_ACC_B_TEXT_ADDR: &str = "7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo";

    const PRIV_ACC_A_TEXT_ADDR: &str = "4eGX3M3rgjHsme8n3sSp89af8JRZtYVTesbJjLqaX1VQ";
    const PRIV_ACC_B_TEXT_ADDR: &str = "3m6HQmCgmAvsxZtxAHPqqEqoBG4335fCG8TzxigyW7rE";

    #[test]
    fn pub_state_consistency() {
        let init_accs_private_data = initial_pub_accounts_private_keys();
        let init_accs_pub_data = initial_accounts();

        assert_eq!(
            init_accs_private_data[0].account_id,
            init_accs_pub_data[0].account_id
        );

        assert_eq!(
            init_accs_private_data[1].account_id,
            init_accs_pub_data[1].account_id
        );

        assert_eq!(
            init_accs_pub_data[0],
            PublicAccountPublicInitialData {
                account_id: AccountId::from_str(PUB_ACC_A_TEXT_ADDR).unwrap(),
                balance: PUB_ACC_A_INITIAL_BALANCE,
            }
        );

        assert_eq!(
            init_accs_pub_data[1],
            PublicAccountPublicInitialData {
                account_id: AccountId::from_str(PUB_ACC_B_TEXT_ADDR).unwrap(),
                balance: PUB_ACC_B_INITIAL_BALANCE,
            }
        );
    }

    #[test]
    fn private_state_consistency() {
        let init_private_accs_keys = initial_priv_accounts_private_keys();
        let init_comms = initial_commitments();

        assert_eq!(
            init_private_accs_keys[0]
                .key_chain
                .secret_spending_key
                .produce_private_key_holder(None)
                .nullifier_secret_key,
            init_private_accs_keys[0]
                .key_chain
                .private_key_holder
                .nullifier_secret_key
        );
        assert_eq!(
            init_private_accs_keys[0]
                .key_chain
                .secret_spending_key
                .produce_private_key_holder(None)
                .viewing_secret_key,
            init_private_accs_keys[0]
                .key_chain
                .private_key_holder
                .viewing_secret_key
        );
        assert_eq!(
            init_private_accs_keys[0]
                .key_chain
                .private_key_holder
                .generate_nullifier_public_key(),
            init_private_accs_keys[0].key_chain.nullifier_public_key
        );
        assert_eq!(
            init_private_accs_keys[0]
                .key_chain
                .private_key_holder
                .generate_viewing_public_key(),
            init_private_accs_keys[0].key_chain.viewing_public_key
        );

        assert_eq!(
            init_private_accs_keys[1]
                .key_chain
                .secret_spending_key
                .produce_private_key_holder(None)
                .nullifier_secret_key,
            init_private_accs_keys[1]
                .key_chain
                .private_key_holder
                .nullifier_secret_key
        );
        assert_eq!(
            init_private_accs_keys[1]
                .key_chain
                .secret_spending_key
                .produce_private_key_holder(None)
                .viewing_secret_key,
            init_private_accs_keys[1]
                .key_chain
                .private_key_holder
                .viewing_secret_key
        );
        assert_eq!(
            init_private_accs_keys[1]
                .key_chain
                .private_key_holder
                .generate_nullifier_public_key(),
            init_private_accs_keys[1].key_chain.nullifier_public_key
        );
        assert_eq!(
            init_private_accs_keys[1]
                .key_chain
                .private_key_holder
                .generate_viewing_public_key(),
            init_private_accs_keys[1].key_chain.viewing_public_key
        );

        assert_eq!(
            init_private_accs_keys[0].account_id().to_string(),
            PRIV_ACC_A_TEXT_ADDR
        );
        assert_eq!(
            init_private_accs_keys[1].account_id().to_string(),
            PRIV_ACC_B_TEXT_ADDR
        );

        assert_eq!(
            init_private_accs_keys[0].key_chain.nullifier_public_key,
            init_comms[0].npk
        );
        assert_eq!(
            init_private_accs_keys[1].key_chain.nullifier_public_key,
            init_comms[1].npk
        );

        assert_eq!(
            init_comms[0],
            PrivateAccountPublicInitialData {
                npk: NullifierPublicKey(NPK_PRIV_ACC_A),
                account: Account {
                    program_owner: DEFAULT_PROGRAM_OWNER,
                    balance: PRIV_ACC_A_INITIAL_BALANCE,
                    data: Data::default(),
                    nonce: 0.into(),
                },
            }
        );

        assert_eq!(
            init_comms[1],
            PrivateAccountPublicInitialData {
                npk: NullifierPublicKey(NPK_PRIV_ACC_B),
                account: Account {
                    program_owner: DEFAULT_PROGRAM_OWNER,
                    balance: PRIV_ACC_B_INITIAL_BALANCE,
                    data: Data::default(),
                    nonce: 0.into(),
                },
            }
        );
    }
}
