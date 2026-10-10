#![expect(
    clippy::arithmetic_side_effects,
    clippy::shadow_unrelated,
    reason = "We don't care about it in tests"
)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use borsh::BorshSerialize;
use lee_core::{
    AuthorizationSecretKey, BlockId, Commitment, DUMMY_COMMITMENT_HASH, DummyOutput,
    MembershipProof, MessageWitness, Nullifier, NullifierWitness, PrivacyPreservingCircuitOutput,
    PrivateWitness, RecipientEncryption, RegularKey, RootCall, Timestamp, WitnessKind,
    account::{Account, AccountId, Actor, ActorState, Balance, Nonce},
    execution_state::{Delivery, ExecutionError, TransactionEntry},
    native_token::{
        Message as NativeMessage, NATIVE_TOKEN_PROGRAM_ID, TransferError, encode_balance,
    },
    program::{
        BlockValidityWindow, Call, MessageEnvelope, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed,
        ProgramEvent, ProgramId, ProgramSegment, TimestampValidityWindow, TransactionEvent,
    },
};
use test_guest_core::{ForgeField, Script};

pub use crate::test_utils::{TestPrivateKeys, init_witness, no_seal, update_witness};
use crate::{
    ProvingInput, PublicAccountEvidence, PublicExecutionContext, PublicKey, PublicTransaction,
    SenderPresentation, Simulation, V03State,
    error::{InvalidProgramBehaviorError, LeeError},
    execute_and_prove, execute_and_prove_with_cross_messages,
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction,
        circuit::{ProgramCatalog, Proof},
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
    public_transaction,
    signature::PrivateKey,
    test_utils::signer_nonces,
};

mod chained_calls;
mod circuit;
mod deploy;
mod events;
mod flash_swap;
mod genesis;
mod native_transfer;
mod pending_messages;
mod privacy_preserving;
mod public_program_rules;
mod publications;
mod recovery_bindings;
mod sealed_messages;
mod validity_window;

// A second deployment of `scripted`: a distinct program for dispatch and PDA derivation.
pub const TWIN: AccountId = AccountId::new([0x5c; 32]);

impl V03State {
    #[must_use]
    pub fn with_test_programs(self) -> Self {
        self.with_programs([
            crate::test_methods::scripted(),
            crate::test_methods::forges_echo(),
            crate::test_methods::flash_swap_initiator(),
            crate::test_methods::flash_swap_callback(),
        ])
        .with_named_programs([(TWIN, crate::test_methods::scripted())])
    }

    #[must_use]
    pub fn with_private_account(mut self, keys: &TestPrivateKeys, account: &Account) -> Self {
        let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk());
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

// ── Flash Swap types (mirrors of guest types for host-side serialisation) ──

#[derive(borsh::BorshSerialize)]
struct CallbackMessage {
    return_funds: bool,
    amount: u128,
    vault: AccountId,
    receiver: AccountId,
}

#[derive(borsh::BorshSerialize)]
enum FlashSwapMessage {
    Initiate {
        vault: AccountId,
        receiver: AccountId,
        callback: Actor,
        amount_out: u128,
        vault_balance: u128,
        callback_message: Vec<u8>,
    },
}

pub fn scripted_id() -> AccountId {
    AccountId::from_builtin_program(crate::test_methods::scripted().id())
}

pub fn synthetic_program(program: Program) -> ProgramCatalog {
    ProgramCatalog::from([(AccountId::from_builtin_program(program.id()), program)])
}

pub fn scripted_programs() -> ProgramCatalog {
    ProgramCatalog::from([
        (scripted_id(), crate::test_methods::scripted()),
        (TWIN, crate::test_methods::scripted()),
    ])
}

pub const fn transfer(to: AccountId, amount: Balance) -> NativeMessage {
    NativeMessage::Transfer { to, amount }
}

pub fn credit(from: Actor, to: Actor, amount: Balance) -> Delivery<Actor> {
    Delivery {
        envelope: MessageEnvelope {
            from,
            to,
            message: borsh::to_vec(&NativeMessage::Credit(amount)).unwrap(),
        },
        inherited_authorizations: BTreeSet::new(),
        inherits_entry_authorizations: false,
        pda_seeds: BTreeSet::new(),
    }
}

pub fn self_sends(actor: Actor, depth: usize) -> Script {
    (0..depth).fold(Script::default(), |script, _| {
        Script::default().call(actor, &script)
    })
}

pub fn root(to: Actor, message: &impl BorshSerialize) -> TransactionEntry<MessageWitness> {
    TransactionEntry::Call(RootCall {
        to,
        message: borsh::to_vec(message).unwrap(),
    })
}

pub fn proving_input(root: TransactionEntry<MessageWitness>) -> ProvingInput {
    ProvingInput {
        root,
        context: PublicExecutionContext::default(),
        private_witnesses: Vec::new(),
        dummy_inputs: Vec::new(),
        ciphertext_padding: None,
        recoveries: Vec::new(),
        private_cast_promotions: BTreeSet::new(),
    }
}

// A proof binding `recoveries` whose public root runs `script`, touching no private account.
pub fn binding(
    script: &Script,
    recoveries: Vec<RecipientEncryption>,
) -> PrivacyPreservingTransaction {
    let keys = test_public_account_keys_1();
    let public = Actor::new(keys.account_id(), scripted_id());
    let (output, proof) = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![public], []),
            recoveries,
            ..proving_input(root(public, script))
        },
        &Simulation::default(),
        &scripted_programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Key(PublicKey::new_from_private_key(
            &keys.signing_key,
        ))],
        ..Message::from_circuit_output(BTreeMap::new(), output)
    };
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    PrivacyPreservingTransaction::new(message, witness_set)
}

pub fn public_tx(
    to: Actor,
    public_actors: Vec<Actor>,
    nonces: Vec<Nonce>,
    message: impl BorshSerialize,
    signers: &[&PrivateKey],
) -> PublicTransaction {
    let message = public_transaction::Message::try_new(
        to,
        public_actors,
        signer_nonces(signers, nonces),
        message,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, signers);
    PublicTransaction::new(message, witness_set)
}

pub fn private_tx(
    (output, proof): (PrivacyPreservingCircuitOutput, Proof),
    nonces: Vec<Nonce>,
    signers: &[&PrivateKey],
) -> PrivacyPreservingTransaction {
    let message = Message::from_circuit_output(signer_nonces(signers, nonces), output);
    let witness_set = WitnessSet::for_message(&message, proof, signers);
    PrivacyPreservingTransaction::new(message, witness_set)
}

pub fn execution_error<T: std::fmt::Debug>(result: Result<T, LeeError>) -> ExecutionError {
    match result {
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(error))) => {
            error
        }
        other => panic!("expected an execution-state rejection, got {other:?}"),
    }
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
    let sender = Actor::native_balance(from);
    let recipient = Actor::native_balance(to);
    public_tx(
        sender,
        vec![sender, recipient],
        vec![Nonce(from_nonce), Nonce(to_nonce)],
        transfer(recipient.account_id, balance),
        &[from_key, to_key],
    )
}

fn flash_swap_tx(
    vault_id: AccountId,
    receiver_id: AccountId,
    callback: Actor,
    message: &FlashSwapMessage,
) -> PublicTransaction {
    let initiator = Actor::new(
        vault_id,
        AccountId::from_builtin_program(crate::test_methods::flash_swap_initiator().id()),
    );
    // No signers: the vault is PDA-authorised.
    public_tx(
        initiator,
        vec![
            initiator,
            Actor::native_balance(vault_id),
            Actor::native_balance(receiver_id),
            callback,
        ],
        vec![],
        message,
        &[],
    )
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

/// Chains `elf` across as many force-inserted segments as it needs, returning every segment's
/// `AccountId` in link order (`[0]` is the first segment, for `first_segment`).
fn force_insert_segment_chain(state: &mut V03State, elf: &[u8], key_seed: u8) -> Vec<AccountId> {
    let user_elf = risc0_binfmt::ProgramBinary::decode(elf)
        .expect("elf must be a valid ProgramBinary")
        .user_elf
        .to_vec();
    let chunks: Vec<&[u8]> = user_elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    let segment_ids: Vec<AccountId> = (0..chunks.len())
        .map(|i| {
            let mut bytes = [key_seed; 32];
            bytes[1] = u8::try_from(i).expect("chunk count fits in a u8");
            AccountId::new(bytes)
        })
        .collect();
    for i in (0..chunks.len()).rev() {
        state.force_insert_account(
            segment_ids[i],
            Account::default().with_actor_state(
                PROGRAM_LOADER_ACCOUNT_ID,
                ActorState::from(
                    ProgramSegment {
                        bytecode: chunks[i].to_vec(),
                        next_segment: segment_ids.get(i + 1).copied(),
                    }
                    .to_bytes(),
                ),
            ),
        );
    }
    segment_ids
}

/// Init-lifecycle private-PDA witness for `keys`, the shape every PDA circuit test starts from.
pub fn init_pda_witness(keys: &TestPrivateKeys, binding: (AccountId, PdaSeed)) -> PrivateWitness {
    PrivateWitness {
        vpk: keys.vpk(),
        random_seed: [0; 32],
        kind: WitnessKind::Pda {
            nsk: keys.nsk(),
            binding,
        },
        nullifier: NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        openings: BTreeSet::new(),
    }
}

pub fn update_pda_witness(
    keys: &TestPrivateKeys,
    binding: (AccountId, PdaSeed),
    account: Account,
    membership_proof: MembershipProof,
) -> PrivateWitness {
    PrivateWitness {
        vpk: keys.vpk(),
        random_seed: [0; 32],
        kind: WitnessKind::Pda {
            nsk: keys.nsk(),
            binding,
        },
        nullifier: NullifierWitness::Update {
            account,
            membership_proof,
        },
        openings: BTreeSet::new(),
    }
}

fn shielded_balance_transfer_for_tests(
    sender_keys: &TestPublicKeys,
    recipient_keys: &TestPrivateKeys,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let sender_id = sender_keys.account_id();
    let sender = Actor::native_balance(sender_id);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk());

    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![sender], [sender_id]),
            private_witnesses: vec![init_witness(recipient_keys)],
            ..proving_input(root(sender, &transfer(recipient_id, balance_to_move)))
        },
        &Simulation {
            public_actor_states: [(sender, encode_balance(balance_to_move))].into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| true,
        no_seal,
    )
    .unwrap();

    private_tx(
        proven,
        vec![state.get_account_by_id(sender_id).nonce],
        &[&sender_keys.signing_key],
    )
}

fn private_balance_transfer_for_tests(
    sender_keys: &TestPrivateKeys,
    sender_private_account: &Account,
    recipient_keys: &TestPrivateKeys,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let sender_id = AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk());
    let sender_commitment = Commitment::new(&sender_id, sender_private_account);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk());

    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![
                update_witness(
                    sender_keys,
                    sender_private_account.clone(),
                    state
                        .get_proof_for_commitment(&sender_commitment)
                        .expect("sender's commitment must be in state"),
                ),
                init_witness(recipient_keys),
            ],
            ..proving_input(root(
                Actor::native_balance(sender_id),
                &transfer(recipient_id, balance_to_move),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| true,
        no_seal,
    )
    .unwrap();

    private_tx(proven, vec![], &[])
}

fn deshielded_balance_transfer_for_tests(
    sender_keys: &TestPrivateKeys,
    sender_private_account: &Account,
    recipient_account_id: &AccountId,
    balance_to_move: u128,
    state: &V03State,
) -> PrivacyPreservingTransaction {
    let sender_id = AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk());
    let sender_commitment = Commitment::new(&sender_id, sender_private_account);
    let recipient = Actor::native_balance(*recipient_account_id);

    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![recipient], []),
            private_witnesses: vec![update_witness(
                sender_keys,
                sender_private_account.clone(),
                state
                    .get_proof_for_commitment(&sender_commitment)
                    .expect("sender's commitment must be in state"),
            )],
            ..proving_input(root(
                Actor::native_balance(sender_id),
                &transfer(recipient.account_id, balance_to_move),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .unwrap();

    private_tx(proven, vec![], &[])
}

fn valid_private_transfer_tx_and_state() -> (V03State, PrivacyPreservingTransaction) {
    let sender_keys = test_private_account_keys_1();
    let sender_private_account = Account {
        nonce: Nonce(0xdead_beef),
        ..Account::funded(100)
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
