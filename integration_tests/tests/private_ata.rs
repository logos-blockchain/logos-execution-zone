#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

use associated_token_account_core::Instruction as AtaInstruction;
use key_protocol::key_management::KeyChain;
use lee::{
    AccountId, PrivacyPreservingTransaction, PrivateKey, PublicKey, PublicTransaction, V03State,
    ValidatedStateDiff,
    privacy_preserving_transaction::{
        circuit::{ProgramWithDependencies, execute_and_prove},
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
    public_transaction::{Message as PublicMessage, WitnessSet as PublicWitnessSet},
};
use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, InputAccountIdentity, Nullifier,
    NullifierWitness, PrivateAccountKind, PrivateWitness, SharedSecretKey, WitnessKind,
    account::{Account, AccountWithMetadata, Data},
    program::PdaSeed,
};
use token_core::{TokenDefinition, TokenHolding};

const DEFINITION_ID: AccountId = AccountId::new([7; 32]);
const TOTAL_SUPPLY: u128 = 1_000_000;

struct Note {
    keys: KeyChain,
    kind: PrivateAccountKind,
    account_id: AccountId,
    account: Account,
}

impl Note {
    fn new(keys: KeyChain, kind: PrivateAccountKind, account: Account) -> Self {
        let account_id = AccountId::for_private_account(
            &keys.nullifier_public_key,
            &keys.viewing_public_key,
            &kind,
        );
        Self {
            keys,
            kind,
            account_id,
            account,
        }
    }

    fn ata(keys: KeyChain, seed: PdaSeed, identifier: u128, balance: u128) -> Self {
        Self::new(
            keys,
            PrivateAccountKind::Pda {
                program_id: programs::ata().id(),
                seed,
                identifier,
            },
            holding(balance),
        )
    }

    fn regular(keys: KeyChain, identifier: u128, balance: u128) -> Self {
        Self::new(
            keys,
            PrivateAccountKind::Regular(identifier),
            holding(balance),
        )
    }

    const fn seed(&self) -> Option<PdaSeed> {
        match self.kind {
            PrivateAccountKind::Pda { seed, .. } => Some(seed),
            PrivateAccountKind::Regular(_) => None,
        }
    }

    const fn is_self_authorized(&self) -> bool {
        self.seed().is_none()
    }

    fn commitment(&self) -> Commitment {
        Commitment::new(&self.account_id, &self.account)
    }

    fn pre_state(&self) -> AccountWithMetadata {
        AccountWithMetadata::new(
            self.account.clone(),
            self.is_self_authorized(),
            self.account_id,
        )
    }

    fn witness(&self, state: &V03State) -> InputAccountIdentity {
        let nsk = self.keys.private_key_holder.nullifier_secret_key();
        InputAccountIdentity::Private(PrivateWitness {
            vpk: self.keys.viewing_public_key.clone(),
            random_seed: [0; 32],
            identifier: self.kind.identifier(),
            kind: match self.kind {
                PrivateAccountKind::Pda { .. } => WitnessKind::Pda { binding: None },
                PrivateAccountKind::Regular(_) => WitnessKind::Regular {
                    ask: Some(self.keys.private_key_holder.authorization_secret_key),
                },
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk,
                membership_proof: state
                    .get_proof_for_commitment(&self.commitment())
                    .expect("note commitment must be in state"),
            },
        })
    }
}

fn ata_program() -> ProgramWithDependencies {
    ProgramWithDependencies::new(
        programs::ata(),
        [(programs::token().id(), programs::token())].into(),
    )
}

fn definition_account() -> Account {
    Account {
        program_owner: programs::token().id(),
        balance: 0,
        data: Data::from(&TokenDefinition::Fungible {
            name: "TEST".to_owned(),
            total_supply: TOTAL_SUPPLY,
            metadata_id: None,
        }),
        nonce: lee_core::account::Nonce(0),
    }
}

fn holding(balance: u128) -> Account {
    Account {
        program_owner: programs::token().id(),
        balance: 0,
        data: Data::from(&TokenHolding::Fungible {
            definition_id: DEFINITION_ID,
            balance,
        }),
        nonce: lee_core::account::Nonce(0),
    }
}

fn holding_balance(account: &Account) -> u128 {
    match TokenHolding::try_from(&account.data).expect("holding data must decode") {
        TokenHolding::Fungible { balance, .. } => balance,
        TokenHolding::NftMaster { .. } | TokenHolding::NftPrintedCopy { .. } => {
            panic!("fungible holding expected")
        }
    }
}

fn ata_recipient_id(keys: &KeyChain, seed: PdaSeed, identifier: u128) -> AccountId {
    AccountId::for_private_pda(
        &programs::ata().id(),
        &seed,
        &keys.nullifier_public_key,
        &keys.viewing_public_key,
        identifier,
    )
}

fn state_with(notes: &[&Note]) -> V03State {
    V03State::new()
        .with_programs([programs::ata(), programs::token()])
        .with_public_accounts([(DEFINITION_ID, definition_account())])
        .with_private_accounts(notes.iter().map(|note| {
            (
                note.commitment(),
                Nullifier::for_account_initialization(&note.account_id),
            )
        }))
}

fn transfer_private(
    state: &mut V03State,
    senders: &[(&Note, u128)],
    recipient_keys: &KeyChain,
    recipient_seed: PdaSeed,
    recipient_identifier: u128,
    recipient_id: AccountId,
) -> Result<Message, lee::error::LeeError> {
    let instruction = Program::serialize_instruction(AtaInstruction::TransferPrivate {
        recipient_seed,
        senders: senders
            .iter()
            .map(|(note, amount)| (note.seed(), *amount))
            .collect(),
    })
    .expect("instruction must serialize");

    let mut pre_states = vec![AccountWithMetadata::new(
        definition_account(),
        false,
        DEFINITION_ID,
    )];
    let mut identities = vec![InputAccountIdentity::Public];
    for (note, _amount) in senders {
        pre_states.push(note.pre_state());
        identities.push(note.witness(&*state));
    }
    pre_states.push(AccountWithMetadata::new(
        Account::default(),
        false,
        recipient_id,
    ));
    identities.push(InputAccountIdentity::Private(PrivateWitness {
        vpk: recipient_keys.viewing_public_key.clone(),
        random_seed: [1; 32],
        identifier: recipient_identifier,
        kind: WitnessKind::Pda { binding: None },
        nullifier: NullifierWitness::Init {
            npk: recipient_keys.nullifier_public_key,
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
    }));

    let (output, proof) = execute_and_prove(pre_states, instruction, identities, &ata_program())?;
    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message.clone(), witness_set);
    let mut applied = state.clone();
    applied.transition_from_privacy_preserving_transaction(&tx, 1, 0)?;
    *state = applied;
    Ok(message)
}

fn decrypt_for(message: &Message, keys: &KeyChain) -> (PrivateAccountKind, Account) {
    message
        .private_actions
        .iter()
        .find_map(|action| {
            let secret: SharedSecretKey =
                keys.calculate_shared_secret_receiver(&action.encrypted_post_state.epk)?;
            EncryptionScheme::decrypt(
                &action.encrypted_post_state.ciphertext,
                &secret,
                &action.nullifier,
            )
        })
        .expect("recipient must be able to open its note")
}

#[test]
fn private_token_send_lands_a_pda_kind_note() {
    let sender = Note::ata(KeyChain::new_os_random(), PdaSeed::new([11; 32]), 0, 500);
    let recipient_keys = KeyChain::new_os_random();
    let recipient_seed = PdaSeed::new([22; 32]);
    let recipient_id = ata_recipient_id(&recipient_keys, recipient_seed, 3);
    let mut state = state_with(&[&sender]);

    let message = transfer_private(
        &mut state,
        &[(&sender, 120)],
        &recipient_keys,
        recipient_seed,
        3,
        recipient_id,
    )
    .expect("private ATA receive must succeed");

    let (kind, account) = decrypt_for(&message, &recipient_keys);

    assert_eq!(
        kind,
        PrivateAccountKind::Pda {
            program_id: programs::ata().id(),
            seed: recipient_seed,
            identifier: 3,
        },
        "the note must carry the ATA program id and the instruction seed"
    );
    assert_eq!(
        AccountId::for_private_account(
            &recipient_keys.nullifier_public_key,
            &recipient_keys.viewing_public_key,
            &kind,
        ),
        recipient_id,
        "the recipient must recompute its id from the decrypted header alone"
    );
    assert_eq!(
        account.program_owner,
        programs::token().id(),
        "the holding must end up owned by the token program"
    );
    assert_eq!(holding_balance(&account), 120);
}

#[test]
fn regular_kind_holding_spends_through_the_private_ata_path() {
    let sender = Note::regular(KeyChain::new_os_random(), 9, 500);
    let recipient_keys = KeyChain::new_os_random();
    let recipient_seed = PdaSeed::new([23; 32]);
    let recipient_id = ata_recipient_id(&recipient_keys, recipient_seed, 0);
    let mut state = state_with(&[&sender]);

    let message = transfer_private(
        &mut state,
        &[(&sender, 70)],
        &recipient_keys,
        recipient_seed,
        0,
        recipient_id,
    )
    .expect("a regular-kind holding must be spendable through the ATA path");

    let (_kind, account) = decrypt_for(&message, &recipient_keys);
    assert_eq!(holding_balance(&account), 70);
}

#[test]
fn two_received_notes_consolidate_under_distinct_seeds() {
    let keys = KeyChain::new_os_random();
    let first = Note::ata(keys.clone(), PdaSeed::new([31; 32]), 0, 200);
    let second = Note::ata(keys, PdaSeed::new([32; 32]), 1, 300);
    let recipient_keys = KeyChain::new_os_random();
    let recipient_seed = PdaSeed::new([33; 32]);
    let recipient_id = ata_recipient_id(&recipient_keys, recipient_seed, 0);
    let mut state = state_with(&[&first, &second]);

    let message = transfer_private(
        &mut state,
        &[(&first, 200), (&second, 250)],
        &recipient_keys,
        recipient_seed,
        0,
        recipient_id,
    )
    .expect("two notes under distinct seeds must consolidate in one transaction");

    let (_kind, account) = decrypt_for(&message, &recipient_keys);
    assert_eq!(holding_balance(&account), 450);
}

#[test]
fn two_notes_forced_onto_one_seed_collide_in_the_pda_family() {
    let keys = KeyChain::new_os_random();
    let seed = PdaSeed::new([41; 32]);
    let first = Note::ata(keys.clone(), seed, 0, 200);
    let second = Note::ata(keys, seed, 1, 300);
    let recipient_keys = KeyChain::new_os_random();
    let recipient_seed = PdaSeed::new([42; 32]);
    let recipient_id = ata_recipient_id(&recipient_keys, recipient_seed, 0);
    let mut state = state_with(&[&first, &second]);

    let err = transfer_private(
        &mut state,
        &[(&first, 200), (&second, 250)],
        &recipient_keys,
        recipient_seed,
        0,
        recipient_id,
    )
    .expect_err("one seed may resolve at most one account per transaction");

    assert!(
        format!("{err:?}")
            .contains("Two different accounts resolved under the same (program, seed)"),
        "expected the PDA family-binding rejection, got {err:?}"
    );
}

#[test]
fn a_bogus_private_ata_id_is_rejected() {
    let sender = Note::ata(KeyChain::new_os_random(), PdaSeed::new([51; 32]), 0, 500);
    let recipient_keys = KeyChain::new_os_random();
    let recipient_seed = PdaSeed::new([52; 32]);
    let mut state = state_with(&[&sender]);

    let err = transfer_private(
        &mut state,
        &[(&sender, 100)],
        &recipient_keys,
        recipient_seed,
        0,
        AccountId::new([0xAB; 32]),
    )
    .expect_err("an id the ATA program cannot derive must be rejected");

    assert!(
        format!("{err:?}").contains("Inconsistent authorization for account"),
        "expected the delegated-authorization rejection, got {err:?}"
    );
}

fn consolidate_n(n: u128) -> Result<Message, lee::error::LeeError> {
    let keys = KeyChain::new_os_random();
    let notes: Vec<Note> = (0..n)
        .map(|i| {
            let byte = u8::try_from(i)
                .expect("sender count fits in u8")
                .checked_add(60)
                .expect("seed byte stays in u8");
            Note::ata(keys.clone(), PdaSeed::new([byte; 32]), i, 10)
        })
        .collect();
    let recipient_keys = KeyChain::new_os_random();
    let recipient_seed = PdaSeed::new([59; 32]);
    let recipient_id = ata_recipient_id(&recipient_keys, recipient_seed, 0);
    let mut state = state_with(&notes.iter().collect::<Vec<_>>());
    let senders: Vec<(&Note, u128)> = notes.iter().map(|note| (note, 1)).collect();
    transfer_private(
        &mut state,
        &senders,
        &recipient_keys,
        recipient_seed,
        0,
        recipient_id,
    )
}

#[test]
fn nine_notes_consolidate_and_ten_exceed_the_call_ceiling() {
    assert!(
        consolidate_n(9).is_ok(),
        "nine sender notes must fit inside the chained-call ceiling"
    );
    assert!(
        matches!(
            consolidate_n(10),
            Err(lee::error::LeeError::MaxChainedCallsDepthExceeded)
        ),
        "ten sender notes must exceed the chained-call ceiling"
    );
}

#[test]
fn a_received_ata_is_spendable_by_its_owner() {
    let funder = Note::ata(KeyChain::new_os_random(), PdaSeed::new([71; 32]), 0, 500);
    let bob = KeyChain::new_os_random();
    let bob_seed = PdaSeed::new([72; 32]);
    let bob_id = AccountId::for_private_pda(
        &programs::ata().id(),
        &bob_seed,
        &bob.nullifier_public_key,
        &bob.viewing_public_key,
        5,
    );
    let mut state = state_with(&[&funder]);

    let message = transfer_private(&mut state, &[(&funder, 300)], &bob, bob_seed, 5, bob_id)
        .expect("receive must succeed");
    let (bob_kind, bob_account) = decrypt_for(&message, &bob);

    let bob_note = Note {
        keys: bob.clone(),
        kind: bob_kind,
        account_id: bob_id,
        account: bob_account,
    };
    let carol = KeyChain::new_os_random();
    let carol_seed = PdaSeed::new([73; 32]);
    let carol_id = AccountId::for_private_pda(
        &programs::ata().id(),
        &carol_seed,
        &carol.nullifier_public_key,
        &carol.viewing_public_key,
        0,
    );

    let forward_message = transfer_private(
        &mut state,
        &[(&bob_note, 175)],
        &carol,
        carol_seed,
        0,
        carol_id,
    )
    .expect("the received ATA must be spendable by its owner");

    let (_kind, carol_account) = decrypt_for(&forward_message, &carol);
    assert_eq!(holding_balance(&carol_account), 175);
}

fn public_send_to_fresh_recipient(
    signers: &[&PrivateKey],
) -> Result<lee::ValidatedStateDiff, lee::error::LeeError> {
    let sender_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([8; 32]).expect("valid key"),
    ));

    let state = V03State::new()
        .with_programs([programs::token()])
        .with_public_accounts([
            (DEFINITION_ID, definition_account()),
            (sender_id, holding(500)),
        ]);

    let message = PublicMessage::try_new(
        programs::token().id(),
        vec![sender_id, recipient_id],
        vec![0_u128.into(); signers.len()],
        token_core::Instruction::Transfer {
            amount_to_transfer: 40,
        },
    )
    .expect("build transfer message");
    let tx = PublicTransaction::new(
        message.clone(),
        PublicWitnessSet::for_message(&message, signers),
    );

    ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
}

#[test]
fn a_public_send_claims_a_fresh_recipient_only_when_it_authorized() {
    let sender_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let recipient_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));

    let Err(err) = public_send_to_fresh_recipient(&[&sender_key]) else {
        panic!("an unauthorized fresh recipient must not be claimable")
    };
    assert!(
        format!("{err:?}").contains("ClaimedUnauthorizedAccount"),
        "expected the unauthorized-claim rejection, got {err:?}"
    );

    let diff = public_send_to_fresh_recipient(&[&sender_key, &recipient_key])
        .expect("a fresh recipient that authorized the send must receive its holding");
    assert_eq!(
        diff.public_diff()[&recipient_id].program_owner,
        programs::token().id(),
        "the authorized recipient's holding must end up token-owned"
    );
    assert_eq!(holding_balance(&diff.public_diff()[&recipient_id]), 40);
}

#[test]
fn an_owned_private_holding_initializes_under_its_own_authorization() {
    let keys = KeyChain::new_os_random();
    let identifier = 4;
    let holding_id = AccountId::for_regular_private_account(
        &keys.nullifier_public_key,
        &keys.viewing_public_key,
        identifier,
    );
    let state = V03State::new()
        .with_programs([programs::token()])
        .with_public_accounts([(DEFINITION_ID, definition_account())]);

    let (output, proof) = execute_and_prove(
        vec![
            AccountWithMetadata::new(definition_account(), false, DEFINITION_ID),
            AccountWithMetadata::new(Account::default(), true, holding_id),
        ],
        Program::serialize_instruction(token_core::Instruction::InitializeAccount)
            .expect("instruction must serialize"),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: keys.viewing_public_key.clone(),
                random_seed: [9; 32],
                identifier,
                kind: WitnessKind::Regular {
                    ask: Some(keys.private_key_holder.authorization_secret_key),
                },
                nullifier: NullifierWitness::Init {
                    npk: keys.nullifier_public_key,
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &programs::token().into(),
    )
    .expect("an authorized owned private holding must be initializable");

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message.clone(), witness_set);
    let mut state = state;
    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect("the initialize transaction must validate");

    let (kind, account) = decrypt_for(&message, &keys);
    assert_eq!(kind, PrivateAccountKind::Regular(identifier));
    assert_eq!(account.program_owner, programs::token().id());
    assert_eq!(holding_balance(&account), 0);
}
