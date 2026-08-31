use std::collections::HashMap;

use key_protocol::key_management::{
    KeyChain, key_tree::chain_index::ChainIndex, secret_holders::SecretSpendingKey,
};
use lee::{Account, AccountId, Data, PrivateKey, PublicKey, V03State, program::Program};
use lee_core::program::DEFAULT_PROGRAM_OWNER;
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

// LGO-scale balances (10^9 atomic units per LGO): once transactions pay real
// fees, the pre-fee 10_000/20_000 could not afford a single reservation.
const PUB_ACC_A_INITIAL_BALANCE: u128 = 10_000_000_000_000;
const PUB_ACC_B_INITIAL_BALANCE: u128 = 20_000_000_000_000;

const PRIV_ACC_A_INITIAL_BALANCE: u128 = 10_000_000_000_000;
const PRIV_ACC_B_INITIAL_BALANCE: u128 = 20_000_000_000_000;

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
            account_id: AccountId::from(&PublicKey::new_from_private_key(&acc1_pub_sign_key)),
            pub_sign_key: acc1_pub_sign_key,
        },
        PublicAccountPrivateInitialData {
            account_id: AccountId::from(&PublicKey::new_from_private_key(&acc2_pub_sign_key)),
            pub_sign_key: acc2_pub_sign_key,
        },
    ]
}

fn key_chain_from_ssk(ssk: [u8; 32]) -> KeyChain {
    let secret_spending_key = SecretSpendingKey(ssk);
    let private_key_holder = secret_spending_key.produce_private_key_holder(None);
    let nullifier_public_key = private_key_holder.generate_nullifier_public_key();
    let viewing_public_key = private_key_holder.generate_viewing_public_key();

    KeyChain {
        secret_spending_key,
        private_key_holder,
        nullifier_public_key,
        viewing_public_key,
    }
}

fn initial_priv_accounts_private_keys() -> Vec<PrivateAccountPrivateInitialData> {
    let key_chain_1 = key_chain_from_ssk(SSK_PRIV_ACC_A);
    let key_chain_2 = key_chain_from_ssk(SSK_PRIV_ACC_B);

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

            acc.program_owner = programs::authenticated_transfer().id().into();

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
                    program_owner: programs::authenticated_transfer().id().into(),
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
        .chain([(
            system_accounts::sequencer_stake_config_account_id(),
            system_accounts::sequencer_stake_config_account(),
        )])
        .chain([
            (
                system_accounts::fee_state_account_id(),
                system_accounts::fee_state_account(),
            ),
            (
                system_accounts::fee_escrow_account_id(),
                system_accounts::fee_account(),
            ),
            (
                system_accounts::fee_inbox_account_id(),
                system_accounts::fee_account(),
            ),
        ])
        .collect()
}

fn initial_programs(cross_zone: bool) -> Vec<Program> {
    let mut programs = vec![
        programs::authenticated_transfer(),
        programs::token(),
        programs::amm(),
        programs::clock(),
        programs::fee(),
        programs::ata(),
        programs::vault(),
        programs::faucet(),
        programs::bridge(),
        programs::sequencer_stake(),
    ];
    if cross_zone {
        // Builtins baked into every node (genesis-block ELFs would exceed the
        // inscription size limit); registered only on cross_zone zones, fixed at
        // genesis.
        programs.extend([
            programs::cross_zone_inbox(),
            programs::cross_zone_outbox(),
            programs::ping_sender(),
            programs::ping_receiver(),
            programs::bridge_lock(),
            programs::wrapped_token(),
        ]);
    }
    programs
}

/// The pre-genesis state. `cross_zone` selects whether the six cross-zone
/// builtins are registered; ids are content-derived, so only membership
/// changes. Not defaulted: every caller states the choice.
#[must_use]
pub fn initial_state(cross_zone: bool) -> V03State {
    lee::V03State::new()
        .with_public_accounts(initial_public_accounts())
        .with_private_accounts(initial_private_accounts())
        .with_programs(initial_programs(cross_zone))
}

#[must_use]
pub fn initial_state_testnet(cross_zone: bool) -> V03State {
    let mut initial_public_accounts = initial_public_accounts();
    initial_public_accounts.insert(
        system_accounts::pinata_account_id(),
        system_accounts::pinata_account(),
    );

    let mut programs = initial_programs(cross_zone);
    programs.push(programs::pinata());

    V03State::new()
        .with_public_accounts(initial_public_accounts)
        .with_private_accounts(initial_private_accounts())
        .with_programs(programs)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use key_protocol::key_management::secret_holders::ViewingSecretKey;

    use super::*;

    const VSK_D_PRIV_ACC_A: [u8; 32] = [
        37, 79, 203, 133, 143, 28, 149, 228, 53, 195, 241, 240, 40, 28, 11, 81, 126, 209, 253, 79,
        167, 213, 4, 162, 9, 183, 132, 78, 248, 92, 134, 198,
    ];

    const VSK_Z_PRIV_ACC_A: [u8; 32] = [
        197, 94, 192, 175, 68, 106, 201, 229, 125, 33, 51, 144, 81, 154, 230, 37, 209, 230, 150,
        29, 73, 203, 166, 56, 65, 178, 205, 15, 101, 81, 111, 150,
    ];

    const VSK_D_PRIV_ACC_B: [u8; 32] = [
        221, 28, 168, 185, 246, 234, 210, 245, 219, 3, 116, 190, 178, 31, 49, 79, 246, 147, 101,
        161, 120, 32, 218, 191, 23, 209, 8, 38, 184, 92, 104, 177,
    ];

    const VSK_Z_PRIV_ACC_B: [u8; 32] = [
        167, 68, 2, 131, 197, 10, 239, 237, 52, 80, 87, 51, 21, 153, 205, 222, 117, 159, 204, 16,
        66, 136, 209, 158, 243, 254, 168, 14, 19, 222, 8, 97,
    ];

    const PUB_ACC_A_TEXT_ADDR: &str = "6iArKUXxhUJqS7kCaPNhwMWt3ro71PDyBj7jwAyE2VQV";
    const PUB_ACC_B_TEXT_ADDR: &str = "7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo";

    const PRIV_ACC_A_TEXT_ADDR: &str = "As5oeEYgbwFwHCB8xCnRJA5uQV1eYCcU86Pfir3D29fX";
    const PRIV_ACC_B_TEXT_ADDR: &str = "GhB15jD2Yig2h2SnDXqxsZii1B3EhnmSucvwodfXKhAa";

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

        // `nsk`/`npk` carry no constants of their own: the key chains derive from `SSK_*`, and the
        // two address canaries below pin H(PREFIX || npk || vpk || identifier), so drift anywhere
        // in ask -> nsk -> npk or in vsk -> vpk moves one of them. Nothing is left unpinned.
        // `VSK_*` stays pinned separately because it is the last value on the vsk -> vpk leg that
        // a test can compare directly.
        assert_eq!(
            init_private_accs_keys[0]
                .key_chain
                .private_key_holder
                .viewing_secret_key,
            ViewingSecretKey::new(VSK_D_PRIV_ACC_A, VSK_Z_PRIV_ACC_A)
        );
        assert_eq!(
            init_private_accs_keys[1]
                .key_chain
                .private_key_holder
                .viewing_secret_key,
            ViewingSecretKey::new(VSK_D_PRIV_ACC_B, VSK_Z_PRIV_ACC_B)
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
                npk: init_private_accs_keys[0].key_chain.nullifier_public_key,
                vpk: init_private_accs_keys[0]
                    .key_chain
                    .viewing_public_key
                    .clone(),
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
                npk: init_private_accs_keys[1].key_chain.nullifier_public_key,
                vpk: init_private_accs_keys[1]
                    .key_chain
                    .viewing_public_key
                    .clone(),
                account: Account {
                    program_owner: DEFAULT_PROGRAM_OWNER,
                    balance: PRIV_ACC_B_INITIAL_BALANCE,
                    data: Data::default(),
                    nonce: 0.into(),
                },
            }
        );
    }

    #[test]
    fn genesis_fee_accounts_are_registered_and_owned() {
        let state = initial_state();
        let fee_program_id = programs::fee().id();

        let ids = system_accounts::fee_account_ids();
        // state, escrow, inbox — all distinct, all non-default.
        for (i, id) in ids.iter().enumerate() {
            assert_ne!(*id, AccountId::default());
            for other in &ids[i + 1..] {
                assert_ne!(id, other);
            }
            let account = state.get_account_by_id(*id);
            assert_eq!(account.program_owner, fee_program_id.into());
            assert_eq!(account.balance, 0);
        }

        // The fee-state account carries the genesis market state; escrow and
        // inbox start empty.
        let fee_state = fee_core::state::FeeState::from_bytes(
            &state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .into_inner(),
        );
        assert_eq!(fee_state, fee_core::state::FeeState::genesis());
        for empty_id in [
            system_accounts::fee_escrow_account_id(),
            system_accounts::fee_inbox_account_id(),
        ] {
            assert!(
                state
                    .get_account_by_id(empty_id)
                    .data
                    .into_inner()
                    .is_empty()
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

        let state = initial_state(true);
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

    /// Gating changes membership only: no other program moves.
    #[test]
    fn cross_zone_builtins_register_only_when_declared() {
        let cross_zone_ids = [
            programs::cross_zone_inbox().id(),
            programs::cross_zone_outbox().id(),
            programs::ping_sender().id(),
            programs::ping_receiver().id(),
            programs::bridge_lock().id(),
            programs::wrapped_token().id(),
        ];
        let with = initial_state(true);
        let without = initial_state(false);
        for id in cross_zone_ids {
            assert!(with.get_program(id).is_some(), "registered when declared");
            assert!(
                without.get_program(id).is_none(),
                "absent when not declared"
            );
        }
        assert!(without.get_program(programs::faucet().id()).is_some());
    }
}
