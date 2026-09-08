#![expect(
    clippy::arithmetic_side_effects,
    clippy::shadow_unrelated,
    reason = "We don't care about it in tests"
)]

use std::collections::HashMap;

use lee_core::{
    AuthorizationSecretKey, BlockId, Commitment, DUMMY_COMMITMENT_HASH, Identifier,
    MembershipProof, Nullifier, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateWitness, Timestamp, WitnessKind,
    account::{Account, AccountId, AccountInput, Balance, Nonce, ProgramShardSelector, data::Data},
    encryption::ViewingPublicKey,
    program::{
        BlockValidityWindow, ExecutionValidationError, InstructionData, MAX_NUMBER_CHAINED_CALLS,
        PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramEvent, ProgramHeader, ProgramId, ProgramSegment,
        TimestampValidityWindow, TransactionEvent,
    },
};

use crate::{
    ProvingInput, PublicKey, PublicTransaction, V03State,
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
mod chained_calls;
mod circuit;
mod deploy;
mod events;
mod flash_swap;
mod genesis;
mod privacy_preserving;
mod public_program_rules;
mod validity_window;

impl V03State {
    /// Include test programs in the builtin programs map.
    #[must_use]
    pub fn with_test_programs(mut self) -> Self {
        self.insert_program(&crate::test_methods::simple_balance_transfer());
        self.insert_program(&crate::test_methods::dropped_account());
        self.insert_program(&crate::test_methods::data_changer());
        self.insert_program(&crate::test_methods::foreign_shard_writer());
        self.insert_program(&crate::test_methods::minter());
        self.insert_program(&crate::test_methods::burner());
        self.insert_program(&crate::test_methods::auth_asserting_noop());
        self.insert_program(&crate::test_methods::private_pda_delegator());
        self.insert_program(&crate::test_methods::noop());
        self.insert_program(&crate::test_methods::chain_caller());
        self.insert_program(&crate::test_methods::non_delegating_forwarder());
        self.insert_program(&crate::test_methods::event_emitter());
        self.insert_program(&crate::test_methods::validity_window());
        self.insert_program(&crate::test_methods::flash_swap_initiator());
        self.insert_program(&crate::test_methods::flash_swap_callback());
        self.insert_program(&crate::test_methods::malicious_self_program_id());
        self.insert_program(&crate::test_methods::malicious_caller_program_id());
        self.insert_program(&crate::test_methods::pda_spend_proxy());
        self.insert_program(&crate::test_methods::validity_window_chain_caller());
        self.insert_program(&crate::test_methods::simple_transfer_proxy());
        self.insert_program(&crate::test_methods::references_undeclared_account());
        self.insert_program(&crate::test_methods::injects_undeclared_pre_state());
        self.insert_program(&crate::test_methods::reordering_transfer());
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

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct CallbackInstruction {
    return_funds: bool,
    token_program_id: AccountId,
    amount: u128,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum FlashSwapInstruction {
    Initiate {
        token_program_id: AccountId,
        callback_program_id: AccountId,
        amount_out: u128,
        callback_instruction_data: Vec<u8>,
    },
    InvariantCheck {
        min_vault_balance: u128,
    },
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct EmitterInstruction {
    events: Vec<ProgramEvent>,
    chain: Vec<(AccountId, InstructionData)>,
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
    let shard_selectors = vec![
        ProgramShardSelector::balance_only(from),
        ProgramShardSelector::balance_only(to),
    ];
    let nonces = vec![Nonce(from_nonce), Nonce(to_nonce)];
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let message =
        public_transaction::Message::try_new(program_id, shard_selectors, nonces, balance).unwrap();
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
        initiator.id().into(),
        vec![
            ProgramShardSelector::balance_only(vault_id),
            ProgramShardSelector::balance_only(receiver_id),
        ],
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

/// Init-lifecycle private-PDA witness for `keys`, the shape every PDA circuit test starts from.
pub fn init_pda_witness(
    keys: &TestPrivateKeys,
    identifier: Identifier,
    binding: (AccountId, PdaSeed),
    account: Account,
) -> PrivateWitness {
    PrivateWitness {
        account,
        vpk: keys.vpk(),
        random_seed: [0; 32],
        identifier,
        kind: WitnessKind::Pda { binding },
        nullifier: NullifierWitness::Init {
            npk: keys.npk(),
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
    }
}

pub fn update_pda_witness(
    keys: &TestPrivateKeys,
    identifier: Identifier,
    binding: (AccountId, PdaSeed),
    account: Account,
    membership_proof: MembershipProof,
) -> PrivateWitness {
    PrivateWitness {
        account,
        vpk: keys.vpk(),
        random_seed: [0; 32],
        identifier,
        kind: WitnessKind::Pda { binding },
        nullifier: NullifierWitness::Update {
            view_tag: 0,
            nsk: keys.nsk(),
            membership_proof,
        },
    }
}

pub fn init_witness(
    keys: &TestPrivateKeys,
    identifier: Identifier,
    account: Account,
) -> PrivateWitness {
    PrivateWitness {
        account,
        vpk: keys.vpk(),
        random_seed: [0; 32],
        identifier,
        kind: WitnessKind::Regular {
            ask: Some(keys.ask),
        },
        nullifier: NullifierWitness::Init {
            npk: keys.npk(),
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
    }
}

pub fn update_witness(
    keys: &TestPrivateKeys,
    identifier: Identifier,
    account: Account,
    membership_proof: MembershipProof,
) -> PrivateWitness {
    PrivateWitness {
        account,
        vpk: keys.vpk(),
        random_seed: [0; 32],
        identifier,
        kind: WitnessKind::Regular {
            ask: Some(keys.ask),
        },
        nullifier: NullifierWitness::Update {
            view_tag: 0,
            nsk: keys.nsk(),
            membership_proof,
        },
    }
}

fn shielded_balance_transfer_for_tests(
    sender_keys: &TestPublicKeys,
    recipient_keys: &TestPrivateKeys,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let sender_id = sender_keys.account_id();
    let sender_account = state.get_account_by_id(sender_id);
    let sender_nonce = sender_account.nonce;
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            signers: [sender_id].into(),
            public_accounts: [(sender_id, sender_account)].into(),
            private_witnesses: vec![init_witness(recipient_keys, 0, Account::default())],
            instruction_data: Program::serialize_instruction(balance_to_move).unwrap(),
            ..Default::default()
        },
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
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_id, sender_private_account);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            private_witnesses: vec![
                update_witness(
                    sender_keys,
                    0,
                    sender_private_account.clone(),
                    state
                        .get_proof_for_commitment(&sender_commitment)
                        .expect("sender's commitment must be in state"),
                ),
                init_witness(recipient_keys, 0, Account::default()),
            ],
            instruction_data: Program::serialize_instruction(balance_to_move).unwrap(),
            ..Default::default()
        },
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
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_id, sender_private_account);

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(*recipient_account_id),
            ],
            public_accounts: [(
                *recipient_account_id,
                state.get_account_by_id(*recipient_account_id),
            )]
            .into(),
            private_witnesses: vec![update_witness(
                sender_keys,
                0,
                sender_private_account.clone(),
                state
                    .get_proof_for_commitment(&sender_commitment)
                    .expect("sender's commitment must be in state"),
            )],
            instruction_data: Program::serialize_instruction(balance_to_move).unwrap(),
            ..Default::default()
        },
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
        nonce: Nonce(0xdead_beef),
        ..Account::funded(100)
    };
    let recipient_keys = test_private_account_keys_2();
    let mut state = V03State::new().with_private_account(&sender_keys, &sender_private_account);
    state.insert_program(&crate::test_methods::simple_balance_transfer());
    let tx = private_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys,
        37,
        &state,
    );
    (state, tx)
}
