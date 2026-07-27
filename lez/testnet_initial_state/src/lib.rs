use std::collections::HashMap;

use key_protocol::key_management::{
    KeyChain,
    key_tree::chain_index::ChainIndex,
    secret_holders::{PrivateKeyHolder, SecretSpendingKey, ViewingSecretKey},
};
use lee::{Account, AccountId, Data, PrivateKey, PublicKey, V03State, program::Program};
use lee_core::{NullifierPublicKey, derive_nullifier_secret_key, encryption::ViewingPublicKey};
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

const VSK_D_PRIV_ACC_A: [u8; 32] = [
    4, 118, 187, 42, 14, 254, 144, 150, 125, 176, 205, 240, 109, 81, 234, 177, 244, 236, 108, 71,
    107, 10, 107, 169, 95, 134, 75, 193, 213, 57, 81, 218,
];

const VSK_Z_PRIV_ACC_A: [u8; 32] = [
    117, 29, 113, 136, 175, 148, 38, 38, 110, 220, 157, 155, 245, 13, 239, 244, 106, 126, 188, 90,
    204, 28, 82, 70, 200, 16, 219, 33, 43, 210, 125, 239,
];

const VSK_D_PRIV_ACC_B: [u8; 32] = [
    100, 59, 111, 232, 245, 32, 102, 179, 205, 119, 145, 238, 9, 235, 62, 38, 55, 252, 179, 217,
    219, 211, 6, 188, 85, 160, 68, 54, 61, 114, 102, 81,
];

const VSK_Z_PRIV_ACC_B: [u8; 32] = [
    123, 246, 87, 46, 116, 95, 39, 122, 251, 71, 207, 144, 70, 227, 120, 27, 98, 59, 67, 247, 209,
    194, 110, 231, 250, 247, 205, 243, 31, 142, 104, 208,
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
    pub vpk: lee_core::encryption::ViewingPublicKey,
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
            &self.key_chain.viewing_public_key,
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
            account_id: AccountId::for_public_key(
                PublicKey::new_from_private_key(&acc1_pub_sign_key).value(),
            ),
            pub_sign_key: acc1_pub_sign_key,
        },
        PublicAccountPrivateInitialData {
            account_id: AccountId::for_public_key(
                PublicKey::new_from_private_key(&acc2_pub_sign_key).value(),
            ),
            pub_sign_key: acc2_pub_sign_key,
        },
    ]
}

fn initial_priv_accounts_private_keys() -> Vec<PrivateAccountPrivateInitialData> {
    let ask_a = SecretSpendingKey(SSK_PRIV_ACC_A).generate_authorization_secret_key(None);
    let nsk_a = derive_nullifier_secret_key(&ask_a);
    let key_chain_1 = KeyChain {
        secret_spending_key: SecretSpendingKey(SSK_PRIV_ACC_A),
        private_key_holder: PrivateKeyHolder {
            nullifier_secret_key: nsk_a,
            authorization_secret_key: ask_a,
            viewing_secret_key: ViewingSecretKey::new(VSK_D_PRIV_ACC_A, VSK_Z_PRIV_ACC_A),
        },
        nullifier_public_key: NullifierPublicKey::from(&nsk_a),
        viewing_public_key: ViewingPublicKey::from_seed(&VSK_D_PRIV_ACC_A, &VSK_Z_PRIV_ACC_A),
    };

    let ask_b = SecretSpendingKey(SSK_PRIV_ACC_B).generate_authorization_secret_key(None);
    let nsk_b = derive_nullifier_secret_key(&ask_b);
    let key_chain_2 = KeyChain {
        secret_spending_key: SecretSpendingKey(SSK_PRIV_ACC_B),
        private_key_holder: PrivateKeyHolder {
            nullifier_secret_key: nsk_b,
            authorization_secret_key: ask_b,
            viewing_secret_key: ViewingSecretKey::new(VSK_D_PRIV_ACC_B, VSK_Z_PRIV_ACC_B),
        },
        nullifier_public_key: NullifierPublicKey::from(&nsk_b),
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

fn initial_commitments() -> Vec<PrivateAccountPublicInitialData> {
    initial_priv_accounts_private_keys()
        .into_iter()
        .map(|data| PrivateAccountPublicInitialData {
            npk: data.key_chain.nullifier_public_key,
            vpk: data.key_chain.viewing_public_key.clone(),
            account: data.account,
        })
        .collect()
}

fn initial_private_accounts() -> Vec<(lee_core::Commitment, lee_core::Nullifier)> {
    initial_commitments()
        .iter()
        .map(|init_comm_data| {
            let npk = &init_comm_data.npk;
            let account_id =
                lee::AccountId::for_regular_private_account(npk, &init_comm_data.vpk, 0);

            let mut acc = init_comm_data.account.clone();

            acc.program_owner = programs::authenticated_transfer().id();

            (
                lee_core::Commitment::new(&account_id, &acc),
                lee_core::Nullifier::for_account_initialization(&account_id),
            )
        })
        .collect()
}

#[must_use]
pub fn initial_public_user_accounts() -> Vec<PublicAccountPublicInitialData> {
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

fn initial_public_accounts() -> HashMap<AccountId, Account> {
    initial_public_user_accounts()
        .iter()
        .map(|acc_data| {
            (
                acc_data.account_id,
                Account {
                    program_owner: programs::authenticated_transfer().id(),
                    balance: acc_data.balance,
                    ..Default::default()
                },
            )
        })
        .chain([
            (
                system_accounts::faucet_account_id(),
                system_accounts::faucet_account(),
            ),
            (
                system_accounts::bridge_account_id(),
                system_accounts::bridge_account(),
            ),
        ])
        .chain(
            system_accounts::clock_account_ids()
                .into_iter()
                .map(|clock_id| (clock_id, system_accounts::clock_account())),
        )
        .chain(std::iter::once(wrapped_token_config_account()))
        .collect()
}

/// The wrapped-token config account.
///
/// Seeded so the `wrapped_token` guest can pin its authorized minter (the
/// cross-zone inbox) without importing the inbox id. Fixed for every zone, so it
/// lives in the shared initial state.
fn wrapped_token_config_account() -> (AccountId, Account) {
    let wrapped_token_id = programs::wrapped_token().id();
    (
        wrapped_token_core::config_account_id(wrapped_token_id),
        Account {
            program_owner: wrapped_token_id,
            data: wrapped_token_core::minter_bytes(programs::cross_zone_inbox().id())
                .to_vec()
                .try_into()
                .expect("minter id fits in account data"),
            ..Default::default()
        },
    )
}

fn initial_programs() -> Vec<Program> {
    vec![
        programs::authenticated_transfer(),
        programs::token(),
        programs::amm(),
        programs::clock(),
        programs::ata(),
        programs::vault(),
        programs::faucet(),
        programs::bridge(),
        programs::cross_zone_outbox(),
        programs::cross_zone_inbox(),
        programs::ping_sender(),
        programs::ping_receiver(),
        programs::bridge_lock(),
        programs::wrapped_token(),
    ]
}

#[must_use]
pub fn initial_state() -> V03State {
    lee::V03State::new()
        .with_public_accounts(initial_public_accounts())
        .with_private_accounts(initial_private_accounts())
        .with_programs(initial_programs())
}

#[must_use]
pub fn initial_state_testnet() -> V03State {
    let mut initial_public_accounts = initial_public_accounts();
    initial_public_accounts.insert(
        system_accounts::pinata_account_id(),
        system_accounts::pinata_account(),
    );

    let mut programs = initial_programs();
    programs.push(programs::pinata());

    V03State::new()
        .with_public_accounts(initial_public_accounts)
        .with_private_accounts(initial_private_accounts())
        .with_programs(programs)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    const PUB_ACC_A_TEXT_ADDR: &str = "6iArKUXxhUJqS7kCaPNhwMWt3ro71PDyBj7jwAyE2VQV";
    const PUB_ACC_B_TEXT_ADDR: &str = "7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo";

    const PRIV_ACC_A_TEXT_ADDR: &str = "GSx3EttJzQqhFPibttxguyhKXkiD4DJmA2dMmuszEmFv";
    const PRIV_ACC_B_TEXT_ADDR: &str = "Dec1rT4DynCafh6k5pmywLGUU16RpxcxCdrSVYq8ukaN";

    #[test]
    fn pub_state_consistency() {
        let init_accs_private_data = initial_pub_accounts_private_keys();
        let init_accs_pub_data = initial_public_user_accounts();

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

        // nsk and npk are derived from each key chain's own ask, so asserting they equal that
        // derivation cannot fail; the pinned text addresses are the drift canary instead.
        for ((keys, comm), (expected_addr, expected_balance)) in
            init_private_accs_keys.iter().zip(&init_comms).zip([
                (PRIV_ACC_A_TEXT_ADDR, PRIV_ACC_A_INITIAL_BALANCE),
                (PRIV_ACC_B_TEXT_ADDR, PRIV_ACC_B_INITIAL_BALANCE),
            ])
        {
            let key_chain = &keys.key_chain;

            assert_eq!(
                key_chain
                    .secret_spending_key
                    .produce_private_key_holder(None)
                    .viewing_secret_key,
                key_chain.private_key_holder.viewing_secret_key
            );
            assert_eq!(
                key_chain.private_key_holder.generate_viewing_public_key(),
                key_chain.viewing_public_key
            );
            assert_eq!(keys.account_id().to_string(), expected_addr);
            assert_eq!(
                *comm,
                PrivateAccountPublicInitialData {
                    npk: key_chain.nullifier_public_key,
                    vpk: key_chain.viewing_public_key.clone(),
                    account: Account {
                        program_owner: DEFAULT_PROGRAM_OWNER,
                        balance: expected_balance,
                        data: Data::default(),
                        nonce: 0.into(),
                    },
                }
            );
        }
    }

    #[test]
    fn genesis_system_accounts_have_expected_contents() {
        // System-account IDs must be distinct and non-default, and the genesis
        // faucet/bridge accounts must carry their expected field values.  Catches
        // mutations that replace `system_faucet_account`/`system_bridge_account`
        // with `Default::default()`, delete their `balance`/`program_owner`
        // fields, or replace `system_bridge_account_id` with `Default::default()`.
        let faucet_id = system_accounts::faucet_account_id();
        let bridge_id = system_accounts::bridge_account_id();
        assert_ne!(bridge_id, AccountId::default());
        assert_ne!(faucet_id, bridge_id);

        let state = initial_state();
        let default_owner = Account::default().program_owner;

        let faucet = state.get_account_by_id(faucet_id);
        assert_eq!(faucet.balance, u128::MAX, "faucet must hold u128::MAX");
        assert_ne!(
            faucet.program_owner, default_owner,
            "faucet must have a non-default program_owner"
        );

        let bridge = state.get_account_by_id(bridge_id);
        assert_ne!(
            bridge.program_owner, default_owner,
            "bridge must have a non-default program_owner"
        );
    }
}
