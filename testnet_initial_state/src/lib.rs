use common::PINATA_BASE58;
use key_protocol::key_management::{
    KeyChain,
    secret_holders::{PrivateKeyHolder, SecretSpendingKey},
};
use nssa::{Account, AccountId, Data, PrivateKey, PublicKey, V03State};
use nssa_core::{NullifierPublicKey, encryption::shared_key_derivation::Secp256k1Point};
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

const VSK_PRIV_ACC_A: [u8; 32] = [
    5, 85, 114, 119, 141, 187, 202, 170, 122, 253, 198, 81, 150, 8, 155, 21, 192, 65, 24, 124, 116,
    98, 110, 106, 137, 90, 165, 239, 80, 13, 222, 30,
];

const VSK_PRIV_ACC_B: [u8; 32] = [
    205, 32, 76, 251, 255, 236, 96, 119, 61, 111, 65, 100, 75, 218, 12, 22, 17, 170, 55, 226, 21,
    154, 161, 34, 208, 74, 27, 1, 119, 13, 88, 128,
];

const VPK_PRIV_ACC_A: [u8; 33] = [
    2, 210, 206, 38, 213, 4, 182, 198, 220, 47, 93, 148, 61, 84, 148, 250, 158, 45, 8, 81, 48, 80,
    46, 230, 87, 210, 47, 204, 76, 58, 214, 167, 81,
];

const VPK_PRIV_ACC_B: [u8; 33] = [
    2, 79, 110, 46, 203, 29, 206, 205, 18, 86, 27, 189, 104, 103, 113, 181, 110, 53, 78, 172, 11,
    171, 190, 18, 126, 214, 81, 77, 192, 154, 58, 195, 238,
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
    pub npk: nssa_core::NullifierPublicKey,
    pub account: nssa_core::account::Account,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAccountPrivateInitialData {
    pub account_id: nssa::AccountId,
    pub pub_sign_key: nssa::PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAccountPrivateInitialData {
    pub account_id: nssa::AccountId,
    pub account: nssa_core::account::Account,
    pub key_chain: KeyChain,
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
            viewing_secret_key: VSK_PRIV_ACC_A,
        },
        nullifier_public_key: NullifierPublicKey(NPK_PRIV_ACC_A),
        viewing_public_key: Secp256k1Point(VPK_PRIV_ACC_A.to_vec()),
    };

    let key_chain_2 = KeyChain {
        secret_spending_key: SecretSpendingKey(SSK_PRIV_ACC_B),
        private_key_holder: PrivateKeyHolder {
            nullifier_secret_key: NSK_PRIV_ACC_B,
            viewing_secret_key: VSK_PRIV_ACC_B,
        },
        nullifier_public_key: NullifierPublicKey(NPK_PRIV_ACC_B),
        viewing_public_key: Secp256k1Point(VPK_PRIV_ACC_B.to_vec()),
    };

    vec![
        PrivateAccountPrivateInitialData {
            account_id: AccountId::from(&key_chain_1.nullifier_public_key),
            account: Account {
                program_owner: DEFAULT_PROGRAM_OWNER,
                balance: PRIV_ACC_A_INITIAL_BALANCE,
                data: Data::default(),
                nonce: 0.into(),
            },
            key_chain: key_chain_1,
        },
        PrivateAccountPrivateInitialData {
            account_id: AccountId::from(&key_chain_2.nullifier_public_key),
            account: Account {
                program_owner: DEFAULT_PROGRAM_OWNER,
                balance: PRIV_ACC_B_INITIAL_BALANCE,
                data: Data::default(),
                nonce: 0.into(),
            },
            key_chain: key_chain_2,
        },
    ]
}

#[must_use]
pub fn initial_commitments() -> Vec<PrivateAccountPublicInitialData> {
    initial_priv_accounts_private_keys()
        .into_iter()
        .map(|data| PrivateAccountPublicInitialData {
            npk: data.key_chain.nullifier_public_key.clone(),
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
    let initial_commitments: Vec<nssa_core::Commitment> = initial_commitments()
        .iter()
        .map(|init_comm_data| {
            let npk = &init_comm_data.npk;

            let mut acc = init_comm_data.account.clone();

            acc.program_owner = nssa::program::Program::authenticated_transfer_program().id();

            nssa_core::Commitment::new(npk, &acc)
        })
        .collect();

    let init_accs: Vec<(nssa::AccountId, u128)> = initial_accounts()
        .iter()
        .map(|acc_data| (acc_data.account_id, acc_data.balance))
        .collect();

    nssa::V03State::new_with_genesis_accounts(&init_accs, &initial_commitments)
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

    const PRIV_ACC_A_TEXT_ADDR: &str = "5ya25h4Xc9GAmrGB2WrTEnEWtQKJwRwQx3Xfo2tucNcE";
    const PRIV_ACC_B_TEXT_ADDR: &str = "E8HwiTyQe4H9HK7icTvn95HQMnzx49mP9A2ddtMLpNaN";

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
            init_private_accs_keys[0].account_id.to_string(),
            PRIV_ACC_A_TEXT_ADDR
        );
        assert_eq!(
            init_private_accs_keys[1].account_id.to_string(),
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
