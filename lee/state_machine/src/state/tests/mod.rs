#![expect(
    clippy::arithmetic_side_effects,
    clippy::shadow_unrelated,
    reason = "We don't care about it in tests"
)]

use std::collections::HashMap;

use lee_core::{
    AuthorizationSecretKey, BlockId, Commitment, DUMMY_COMMITMENT_HASH, InputAccountIdentity,
    Nullifier, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, Timestamp,
    WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, Nonce, data::Data},
    encryption::ViewingPublicKey,
    program::{
        BlockValidityWindow, ExecutionValidationError, MAX_NUMBER_CHAINED_CALLS, PdaSeed,
        ProgramId, TimestampValidityWindow, WrappedBalanceSum,
    },
};

use crate::{
    PublicKey, PublicTransaction, V03State,
    error::{InvalidProgramBehaviorError, LeeError},
    execute_and_prove,
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction, circuit::ProgramWithDependencies, message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
    public_transaction,
    signature::PrivateKey,
};

mod authenticated_transfer;
mod changer_claimer;
mod circuit;
mod claiming;
mod flash_swap;
mod genesis;
mod privacy_preserving;
mod public_program_rules;
mod validity_window;

impl V03State {
    /// Include test programs in the builtin programs map.
    #[must_use]
    pub fn with_test_programs(mut self) -> Self {
        self.insert_program(crate::test_methods::simple_balance_transfer());
        self.insert_program(crate::test_methods::nonce_changer());
        self.insert_program(crate::test_methods::extra_output());
        self.insert_program(crate::test_methods::missing_output());
        self.insert_program(crate::test_methods::dropped_account());
        self.insert_program(crate::test_methods::program_owner_changer());
        self.insert_program(crate::test_methods::data_changer());
        self.insert_program(crate::test_methods::minter());
        self.insert_program(crate::test_methods::burner());
        self.insert_program(crate::test_methods::auth_asserting_noop());
        self.insert_program(crate::test_methods::private_pda_delegator());
        self.insert_program(crate::test_methods::pda_claimer());
        self.insert_program(crate::test_methods::two_pda_claimer());
        self.insert_program(crate::test_methods::noop());
        self.insert_program(crate::test_methods::chain_caller());
        self.insert_program(crate::test_methods::modified_transfer_program());
        self.insert_program(crate::test_methods::malicious_authorization_changer());
        self.insert_program(crate::test_methods::validity_window());
        self.insert_program(crate::test_methods::flash_swap_initiator());
        self.insert_program(crate::test_methods::flash_swap_callback());
        self.insert_program(crate::test_methods::malicious_self_program_id());
        self.insert_program(crate::test_methods::malicious_caller_program_id());
        self.insert_program(crate::test_methods::pda_spend_proxy());
        self.insert_program(crate::test_methods::claimer());
        self.insert_program(crate::test_methods::changer_claimer());
        self.insert_program(crate::test_methods::validity_window_chain_caller());
        self.insert_program(crate::test_methods::simple_transfer_proxy());
        self.insert_program(crate::test_methods::malicious_injector());
        self.insert_program(crate::test_methods::malicious_launderer());
        self.insert_program(crate::test_methods::modified_transfer_program());
        self
    }

    #[must_use]
    pub fn with_non_default_accounts_but_default_program_owners(mut self) -> Self {
        let account_with_default_values_except_balance = Account {
            balance: 100,
            ..Account::default()
        };
        let account_with_default_values_except_nonce = Account {
            nonce: Nonce(37),
            ..Account::default()
        };
        let account_with_default_values_except_data = Account {
            data: vec![0xca, 0xfe].try_into().unwrap(),
            ..Account::default()
        };
        self.force_insert_account(
            AccountId::new([255; 32]),
            account_with_default_values_except_balance,
        );
        self.force_insert_account(
            AccountId::new([254; 32]),
            account_with_default_values_except_nonce,
        );
        self.force_insert_account(
            AccountId::new([253; 32]),
            account_with_default_values_except_data,
        );
        self
    }

    #[must_use]
    pub fn with_account_owned_by_burner_program(mut self) -> Self {
        let account = Account {
            program_owner: crate::test_methods::burner().id(),
            balance: 100,
            ..Default::default()
        };
        self.force_insert_account(AccountId::new([252; 32]), account);
        self
    }

    #[must_use]
    pub fn with_private_account(mut self, keys: &TestPrivateKeys, account: &Account) -> Self {
        let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);
        let commitment = Commitment::new(&account_id, account);
        self.private_state.0.extend(&[commitment]);
        self
    }
}

pub struct TestPublicKeys {
    pub signing_key: PrivateKey,
}

impl TestPublicKeys {
    pub fn account_id(&self) -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(&self.signing_key))
    }
}

pub struct TestPrivateKeys {
    pub ask: AuthorizationSecretKey,
    pub d: [u8; 32],
    pub z: [u8; 32],
}

impl TestPrivateKeys {
    pub fn nsk(&self) -> NullifierSecretKey {
        (&self.ask).into()
    }

    pub fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }

    pub fn vpk(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&self.d, &self.z)
    }
}

// ── Flash Swap types (mirrors of guest types for host-side serialisation) ──

#[derive(serde::Serialize, serde::Deserialize)]
struct CallbackInstruction {
    return_funds: bool,
    token_program_id: ProgramId,
    amount: u128,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum FlashSwapInstruction {
    Initiate {
        token_program_id: ProgramId,
        callback_program_id: ProgramId,
        amount_out: u128,
        callback_instruction_data: Vec<u32>,
    },
    InvariantCheck {
        min_vault_balance: u128,
    },
}

fn public_state_from_balances(initial_data: &[(AccountId, u128)]) -> HashMap<AccountId, Account> {
    initial_data
        .iter()
        .copied()
        .map(|(account_id, balance)| {
            (
                account_id,
                Account {
                    program_owner: crate::test_methods::simple_balance_transfer().id(),
                    balance,
                    ..Account::default()
                },
            )
        })
        .collect()
}

fn transfer_transaction(
    from: AccountId,
    from_key: &PrivateKey,
    from_nonce: u128,
    to: AccountId,
    to_key: &PrivateKey,
    to_nonce: u128,
    balance: u128,
) -> PublicTransaction {
    let account_ids = vec![from, to];
    let nonces = vec![Nonce(from_nonce), Nonce(to_nonce)];
    let program_id = crate::test_methods::simple_balance_transfer().id();
    let message =
        public_transaction::Message::try_new(program_id, account_ids, nonces, balance).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[from_key, to_key]);
    PublicTransaction::new(message, witness_set)
}

fn build_flash_swap_tx(
    initiator: &Program,
    vault_id: AccountId,
    receiver_id: AccountId,
    instruction: FlashSwapInstruction,
) -> PublicTransaction {
    let message = public_transaction::Message::try_new(
        initiator.id(),
        vec![vault_id, receiver_id],
        vec![], // no signers — vault is PDA-authorised
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

fn test_public_account_keys_1() -> TestPublicKeys {
    TestPublicKeys {
        signing_key: PrivateKey::try_new([37; 32]).unwrap(),
    }
}

fn test_public_account_keys_2() -> TestPublicKeys {
    TestPublicKeys {
        signing_key: PrivateKey::try_new([38; 32]).unwrap(),
    }
}

pub fn test_private_account_keys_1() -> TestPrivateKeys {
    TestPrivateKeys {
        ask: AuthorizationSecretKey([13; 32]),
        d: [31; 32],
        z: [32; 32],
    }
}

pub fn test_private_account_keys_2() -> TestPrivateKeys {
    TestPrivateKeys {
        ask: AuthorizationSecretKey([38; 32]),
        d: [83; 32],
        z: [84; 32],
    }
}

fn shielded_balance_transfer_for_tests(
    sender_keys: &TestPublicKeys,
    recipient_keys: &TestPrivateKeys,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let sender = AccountWithMetadata::new(
        state.get_account_by_id(sender_keys.account_id()),
        true,
        sender_keys.account_id(),
    );

    let sender_nonce = sender.account.nonce;

    let recipient = AccountWithMetadata::new(
        Account::default(),
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
        vec![sender, recipient],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular,
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &crate::test_methods::simple_balance_transfer().into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![sender_nonce], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_keys.signing_key]);
    PrivacyPreservingTransaction::new(message, witness_set)
}

fn private_balance_transfer_for_tests(
    sender_keys: &TestPrivateKeys,
    sender_private_account: &Account,
    recipient_keys: &TestPrivateKeys,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_account_id, sender_private_account);
    let sender_pre = AccountWithMetadata::new(
        sender_private_account.clone(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let recipient_pre = AccountWithMetadata::new(
        Account::default(),
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular,
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: state
                        .get_proof_for_commitment(&sender_commitment)
                        .expect("sender's commitment must be in state"),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular,
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[]);

    PrivacyPreservingTransaction::new(message, witness_set)
}

fn deshielded_balance_transfer_for_tests(
    sender_keys: &TestPrivateKeys,
    sender_private_account: &Account,
    recipient_account_id: &AccountId,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_account_id, sender_private_account);
    let sender_pre = AccountWithMetadata::new(
        sender_private_account.clone(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let recipient_pre = AccountWithMetadata::new(
        state.get_account_by_id(*recipient_account_id),
        false,
        *recipient_account_id,
    );

    let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular,
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: state
                        .get_proof_for_commitment(&sender_commitment)
                        .expect("sender's commitment must be in state"),
                },
            }),
            InputAccountIdentity::Public,
        ],
        &program.into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[]);

    PrivacyPreservingTransaction::new(message, witness_set)
}

fn valid_private_transfer_tx_and_state() -> (V03State, PrivacyPreservingTransaction) {
    let sender_keys = test_private_account_keys_1();
    let sender_private_account = Account {
        program_owner: crate::test_methods::simple_balance_transfer().id(),
        balance: 100,
        nonce: Nonce(0xdead_beef),
        ..Account::default()
    };
    let recipient_keys = test_private_account_keys_2();
    let state = V03State::new().with_private_account(&sender_keys, &sender_private_account);
    let tx = private_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys,
        37,
        &state,
    );
    (state, tx)
}
