#![cfg(test)]

use std::{borrow::Cow, collections::HashMap};

use lee::{
    PrivateKey, ProvingInput, PublicKey, PublicTransaction, V03State, execute_and_prove,
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction, circuit::Proof, message::Message, witness_set::WitnessSet,
    },
    program::Program,
    public_transaction,
};
use lee_core::{
    AuthorizationSecretKey, Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, MembershipProof,
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivacyPreservingCircuitOutput,
    PrivateAccountKind, PrivateWitness, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, AccountIdData, Nonce, ProgramShardSelector, ShardData},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use token_core::{
    HoldingKind, HoldingTarget, Instruction, MetadataStandard, NewTokenDefinition,
    NewTokenMetadata, TokenDefinition, TokenHolding,
};

const USD_ISSUER: u8 = 21;
const GOLD_ISSUER: u8 = 22;
const ALICE: u8 = 23;
const BOB: u8 = 24;
const STRANGER: u8 = 25;
const NFT_DEFINITION: u8 = 26;
const NFT_METADATA: u8 = 27;
const CAROL: u8 = 28;

struct PrivateKeys {
    ask: AuthorizationSecretKey,
    d: [u8; 32],
    z: [u8; 32],
}

impl PrivateKeys {
    fn nsk(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.ask)
    }

    fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }

    fn vpk(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&self.d, &self.z)
    }

    fn holder(&self, identifier: u128) -> HoldingTarget {
        let (npk, vpk) = (self.npk(), self.vpk());
        HoldingTarget {
            owner_id: AccountId::for_private_account(
                &npk,
                &vpk,
                &PrivateAccountKind::Regular(identifier),
            ),
            account_id_data: AccountIdData::from_private_parts(npk, vpk, identifier),
        }
    }

    fn holding_witness(
        &self,
        seed: PdaSeed,
        identifier: u128,
        account: Account,
        proof: Option<MembershipProof>,
    ) -> PrivateWitness {
        self.witness(
            WitnessKind::Pda {
                binding: (token_program_id(), seed),
            },
            identifier,
            account,
            proof,
        )
    }

    fn owner_witness(
        &self,
        ask: Option<AuthorizationSecretKey>,
        identifier: u128,
        account: Account,
        proof: Option<MembershipProof>,
    ) -> PrivateWitness {
        self.witness(WitnessKind::Regular { ask }, identifier, account, proof)
    }

    fn witness(
        &self,
        kind: WitnessKind,
        identifier: u128,
        account: Account,
        proof: Option<MembershipProof>,
    ) -> PrivateWitness {
        PrivateWitness {
            account,
            vpk: self.vpk(),
            random_seed: [0; 32],
            identifier,
            kind,
            nullifier: proof.map_or_else(
                || NullifierWitness::Init {
                    npk: self.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
                |membership_proof| NullifierWitness::Update {
                    view_tag: 0,
                    nsk: self.nsk(),
                    membership_proof,
                },
            ),
        }
    }

    fn decrypt(
        &self,
        output: &PrivacyPreservingCircuitOutput,
    ) -> Vec<(PrivateAccountKind, Account)> {
        output
            .private_actions
            .iter()
            .filter_map(|action| {
                let secret = SharedSecretKey::decapsulate(
                    &action.encrypted_post_state.epk,
                    &self.d,
                    &self.z,
                )?;
                EncryptionScheme::decrypt(
                    &action.encrypted_post_state.ciphertext,
                    &secret,
                    &action.nullifier,
                )
            })
            .collect()
    }
}

fn bob_keys() -> PrivateKeys {
    PrivateKeys {
        ask: AuthorizationSecretKey([38; 32]),
        d: [83; 32],
        z: [84; 32],
    }
}

fn carol_keys() -> PrivateKeys {
    PrivateKeys {
        ask: AuthorizationSecretKey([13; 32]),
        d: [31; 32],
        z: [32; 32],
    }
}

fn token_program_id() -> AccountId {
    programs::token().id().into()
}

fn key(seed: u8) -> PrivateKey {
    PrivateKey::try_new([seed; 32]).unwrap()
}

fn account_id(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}

fn account(seed: u8) -> AccountId {
    account_id(&key(seed))
}

fn public_holder(seed: u8) -> HoldingTarget {
    HoldingTarget {
        owner_id: account(seed),
        account_id_data: AccountIdData::public(),
    }
}

fn holding_id(holder: &HoldingTarget, definition: AccountId, kind: HoldingKind) -> AccountId {
    token_core::holding_id(holder, token_program_id(), definition, kind)
}

fn fungible_holding_id(holder: &HoldingTarget, definition: AccountId) -> AccountId {
    holding_id(holder, definition, HoldingKind::Fungible)
}

fn token_row(id: AccountId) -> ProgramShardSelector {
    ProgramShardSelector::new(id, token_program_id())
}

fn with_token_data<T>(data: &T) -> Account
where
    ShardData: for<'data> From<&'data T>,
{
    Account::default().with_shard(token_program_id(), ShardData::from(data))
}

fn fungible_definition(total_supply: u128) -> Account {
    with_token_data(&TokenDefinition::Fungible {
        name: String::from("test"),
        total_supply,
        metadata_id: None,
    })
}

fn fungible_holding(definition_id: AccountId, balance: u128) -> Account {
    with_token_data(&TokenHolding::Fungible {
        definition_id,
        balance,
    })
}

fn usd() -> AccountId {
    account(USD_ISSUER)
}

fn gold() -> AccountId {
    account(GOLD_ISSUER)
}

fn nft() -> AccountId {
    account(NFT_DEFINITION)
}

fn state() -> V03State {
    V03State::new()
        .with_public_accounts([
            (usd(), fungible_definition(1_000)),
            (gold(), fungible_definition(1_000)),
            (
                fungible_holding_id(&public_holder(ALICE), usd()),
                fungible_holding(usd(), 1_000),
            ),
            (
                fungible_holding_id(&public_holder(STRANGER), gold()),
                fungible_holding(gold(), 1_000),
            ),
            (
                nft(),
                with_token_data(&TokenDefinition::NonFungible {
                    name: String::from("nft"),
                    printable_supply: 10,
                    metadata_id: account(NFT_METADATA),
                }),
            ),
            (
                holding_id(&public_holder(STRANGER), nft(), HoldingKind::NftMaster),
                with_token_data(&TokenHolding::NftMaster {
                    definition_id: nft(),
                    print_balance: 10,
                }),
            ),
        ])
        .with_programs([programs::token()])
}

fn public_tx(
    state: &V03State,
    program: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    signers: &[&PrivateKey],
    instruction: &impl borsh::BorshSerialize,
) -> PublicTransaction {
    let nonces = signers
        .iter()
        .map(|key| state.get_account_by_id(account_id(key)).nonce)
        .collect();
    let message =
        public_transaction::Message::try_new(program, shard_selectors, nonces, instruction)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, signers);
    PublicTransaction::new(message, witness_set)
}

fn token_tx(
    state: &V03State,
    shard_selectors: Vec<ProgramShardSelector>,
    signers: &[&PrivateKey],
    instruction: &Instruction,
) -> PublicTransaction {
    public_tx(
        state,
        token_program_id(),
        shard_selectors,
        signers,
        instruction,
    )
}

fn transfer_tx(
    state: &V03State,
    sender: u8,
    recipient: &HoldingTarget,
    definition: AccountId,
    amount: u128,
) -> PublicTransaction {
    let sender_holder = public_holder(sender);
    token_tx(
        state,
        vec![
            token_row(fungible_holding_id(&sender_holder, definition)),
            token_row(fungible_holding_id(recipient, definition)),
            ProgramShardSelector::balance(account(sender)),
        ],
        &[&key(sender)],
        &Instruction::Transfer {
            sender: sender_holder,
            recipient: recipient.clone(),
            amount_to_transfer: amount,
        },
    )
}

fn transfer_into(
    state: &V03State,
    sender: u8,
    recipient: &HoldingTarget,
    definition: AccountId,
    recipient_row: AccountId,
    amount: u128,
) -> PublicTransaction {
    let sender_holder = public_holder(sender);
    token_tx(
        state,
        vec![
            token_row(fungible_holding_id(&sender_holder, definition)),
            token_row(recipient_row),
            ProgramShardSelector::balance(account(sender)),
        ],
        &[&key(sender)],
        &Instruction::Transfer {
            sender: sender_holder,
            recipient: recipient.clone(),
            amount_to_transfer: amount,
        },
    )
}

fn metadata() -> NewTokenMetadata {
    NewTokenMetadata {
        standard: MetadataStandard::Simple,
        uri: String::from("uri"),
        creators: String::from("creators"),
    }
}

fn pp_tx(
    nonces: Vec<Nonce>,
    (output, proof): (PrivacyPreservingCircuitOutput, Proof),
    signers: &[&PrivateKey],
) -> PrivacyPreservingTransaction {
    let message = Message::from_circuit_output(nonces, output);
    let witness_set = WitnessSet::for_message(&message, proof, signers);
    PrivacyPreservingTransaction::new(message, witness_set)
}

fn assert_rejected(state: &V03State, tx: &PublicTransaction, untouched: AccountId, name: &str) {
    let mut state = state.clone();
    let before = state.get_account_by_id(untouched);
    assert!(
        state.transition_from_public_transaction(tx, 1, 0).is_err(),
        "{name} was accepted"
    );
    assert_eq!(state.get_account_by_id(untouched), before, "{name}");
}

#[test]
fn nothing_occupies_bobs_future_usd_holding_with_gold() {
    let state = state();
    let bob = public_holder(BOB);
    let stranger = public_holder(STRANGER);
    let target = fungible_holding_id(&bob, usd());
    let new_definition = key(CAROL);
    let attempts = [
        (
            "initialize",
            token_tx(
                &state,
                vec![token_row(gold()), token_row(target)],
                &[],
                &Instruction::InitializeAccount {
                    holder: bob.clone(),
                },
            ),
        ),
        (
            "zero transfer",
            transfer_into(&state, STRANGER, &bob, gold(), target, 0),
        ),
        (
            "transfer",
            transfer_into(&state, STRANGER, &bob, gold(), target, 1),
        ),
        (
            "mint",
            token_tx(
                &state,
                vec![token_row(gold()), token_row(target)],
                &[&key(GOLD_ISSUER)],
                &Instruction::Mint {
                    holder: bob.clone(),
                    amount_to_mint: 1,
                },
            ),
        ),
        (
            "definition target",
            token_tx(
                &state,
                vec![
                    token_row(target),
                    token_row(fungible_holding_id(&stranger, target)),
                ],
                &[&key(STRANGER)],
                &Instruction::NewFungibleDefinition {
                    name: String::from("squat"),
                    total_supply: 1,
                    holder: stranger.clone(),
                },
            ),
        ),
        (
            "supply target",
            token_tx(
                &state,
                vec![token_row(account_id(&new_definition)), token_row(target)],
                &[&new_definition],
                &Instruction::NewFungibleDefinition {
                    name: String::from("squat"),
                    total_supply: 1,
                    holder: bob.clone(),
                },
            ),
        ),
        (
            "metadata definition target",
            token_tx(
                &state,
                vec![
                    token_row(target),
                    token_row(fungible_holding_id(&stranger, target)),
                    token_row(account(NFT_METADATA)),
                ],
                &[&key(STRANGER), &key(NFT_METADATA)],
                &Instruction::NewDefinitionWithMetadata {
                    new_definition: NewTokenDefinition::Fungible {
                        name: String::from("squat"),
                        total_supply: 1,
                    },
                    metadata: Box::new(metadata()),
                    holder: stranger.clone(),
                },
            ),
        ),
        (
            "metadata supply target",
            token_tx(
                &state,
                vec![
                    token_row(account_id(&new_definition)),
                    token_row(target),
                    token_row(account(NFT_METADATA)),
                ],
                &[&new_definition, &key(NFT_METADATA)],
                &Instruction::NewDefinitionWithMetadata {
                    new_definition: NewTokenDefinition::Fungible {
                        name: String::from("squat"),
                        total_supply: 1,
                    },
                    metadata: Box::new(metadata()),
                    holder: bob.clone(),
                },
            ),
        ),
        (
            "metadata target",
            token_tx(
                &state,
                vec![
                    token_row(account_id(&new_definition)),
                    token_row(fungible_holding_id(&bob, account_id(&new_definition))),
                    token_row(target),
                ],
                &[&new_definition],
                &Instruction::NewDefinitionWithMetadata {
                    new_definition: NewTokenDefinition::Fungible {
                        name: String::from("squat"),
                        total_supply: 1,
                    },
                    metadata: Box::new(metadata()),
                    holder: bob.clone(),
                },
            ),
        ),
        (
            "print",
            token_tx(
                &state,
                vec![
                    token_row(holding_id(&stranger, nft(), HoldingKind::NftMaster)),
                    token_row(target),
                    ProgramShardSelector::balance(account(STRANGER)),
                ],
                &[&key(STRANGER)],
                &Instruction::PrintNft {
                    master_holder: stranger.clone(),
                    copy_holder: bob.clone(),
                },
            ),
        ),
    ];

    for (name, tx) in &attempts {
        assert_rejected(&state, tx, target, name);
    }
}

#[test]
fn definition_and_metadata_targets_must_be_authorized() {
    let state = state();
    let definition = key(CAROL);
    let bob = public_holder(BOB);
    let rows = vec![
        token_row(account_id(&definition)),
        token_row(fungible_holding_id(&bob, account_id(&definition))),
        token_row(account(NFT_METADATA)),
    ];
    let instruction = Instruction::NewDefinitionWithMetadata {
        new_definition: NewTokenDefinition::Fungible {
            name: String::from("carol"),
            total_supply: 5,
        },
        metadata: Box::new(metadata()),
        holder: bob.clone(),
    };

    assert_rejected(
        &state,
        &token_tx(&state, rows.clone(), &[&key(NFT_METADATA)], &instruction),
        account_id(&definition),
        "unsigned definition",
    );
    assert_rejected(
        &state,
        &token_tx(&state, rows.clone(), &[&definition], &instruction),
        account(NFT_METADATA),
        "unsigned metadata",
    );

    let mut state = state;
    state
        .transition_from_public_transaction(
            &token_tx(
                &state,
                rows,
                &[&definition, &key(NFT_METADATA)],
                &instruction,
            ),
            1,
            0,
        )
        .unwrap();
    assert_eq!(
        state.get_account_by_id(fungible_holding_id(&bob, account_id(&definition))),
        fungible_holding(account_id(&definition), 5)
    );
}

#[test]
fn receiving_needs_no_recipient_signature_and_an_initialized_holding_stays_usable() {
    let mut state = state();
    let bob = public_holder(BOB);
    let bob_usd = fungible_holding_id(&bob, usd());
    let initialize = token_tx(
        &state,
        vec![token_row(usd()), token_row(bob_usd)],
        &[],
        &Instruction::InitializeAccount {
            holder: bob.clone(),
        },
    );

    state
        .transition_from_public_transaction(&initialize, 1, 0)
        .unwrap();
    assert_eq!(state.get_account_by_id(bob_usd), fungible_holding(usd(), 0));

    state
        .transition_from_public_transaction(&transfer_tx(&state, ALICE, &bob, usd(), 100), 2, 0)
        .unwrap();
    assert_eq!(
        state.get_account_by_id(bob_usd),
        fungible_holding(usd(), 100)
    );
    assert_eq!(
        state.get_account_by_id(fungible_holding_id(&public_holder(ALICE), usd())),
        fungible_holding(usd(), 900)
    );

    state
        .transition_from_public_transaction(&initialize, 3, 0)
        .unwrap();
    assert_eq!(
        state.get_account_by_id(bob_usd),
        fungible_holding(usd(), 100)
    );
}

#[test]
fn spending_needs_exactly_one_authorized_owner_row() {
    let state = state();
    let alice = public_holder(ALICE);
    let alice_usd = fungible_holding_id(&alice, usd());
    let bob_usd = fungible_holding_id(&public_holder(BOB), usd());
    let instruction = Instruction::Transfer {
        sender: alice,
        recipient: public_holder(BOB),
        amount_to_transfer: 100,
    };
    let attempts = [
        (
            "missing owner",
            token_tx(
                &state,
                vec![token_row(alice_usd), token_row(bob_usd)],
                &[],
                &instruction,
            ),
        ),
        (
            "unsigned owner",
            token_tx(
                &state,
                vec![
                    token_row(alice_usd),
                    token_row(bob_usd),
                    ProgramShardSelector::balance(account(ALICE)),
                ],
                &[],
                &instruction,
            ),
        ),
        (
            "wrong owner",
            token_tx(
                &state,
                vec![
                    token_row(alice_usd),
                    token_row(bob_usd),
                    ProgramShardSelector::balance(account(BOB)),
                ],
                &[&key(BOB)],
                &instruction,
            ),
        ),
        (
            "surplus row",
            token_tx(
                &state,
                vec![
                    token_row(alice_usd),
                    token_row(bob_usd),
                    ProgramShardSelector::balance(account(ALICE)),
                    ProgramShardSelector::balance(account(BOB)),
                ],
                &[&key(ALICE)],
                &instruction,
            ),
        ),
        (
            "wrong program shard",
            token_tx(
                &state,
                vec![
                    ProgramShardSelector::new(alice_usd, programs::amm().id().into()),
                    token_row(bob_usd),
                    ProgramShardSelector::balance(account(ALICE)),
                ],
                &[&key(ALICE)],
                &instruction,
            ),
        ),
    ];

    for (name, tx) in &attempts {
        assert_rejected(&state, tx, alice_usd, name);
    }
}

#[test]
fn a_definition_that_owns_the_burned_holding_is_listed_once() {
    let mut state = state();
    let issuer = public_holder(USD_ISSUER);
    let issuer_usd = fungible_holding_id(&issuer, usd());
    state = state.with_public_accounts([(issuer_usd, fungible_holding(usd(), 300))]);
    let instruction = Instruction::Burn {
        holder: issuer,
        amount_to_burn: 100,
    };

    assert_rejected(
        &state,
        &token_tx(
            &state,
            vec![
                token_row(usd()),
                token_row(issuer_usd),
                ProgramShardSelector::balance(usd()),
            ],
            &[&key(USD_ISSUER)],
            &instruction,
        ),
        issuer_usd,
        "duplicate owner",
    );

    state
        .transition_from_public_transaction(
            &token_tx(
                &state,
                vec![token_row(usd()), token_row(issuer_usd)],
                &[&key(USD_ISSUER)],
                &instruction,
            ),
            1,
            0,
        )
        .unwrap();
    assert_eq!(
        state.get_account_by_id(issuer_usd),
        fungible_holding(usd(), 200)
    );
    assert_eq!(
        state.get_account_by_id(usd()).data,
        fungible_definition(900).data
    );
}

#[test]
fn a_call_from_another_program_is_checked_the_same() {
    let forwarder = Program::new_unchecked(
        test_methods::NON_DELEGATING_FORWARDER_ID,
        Cow::Borrowed(test_methods::NON_DELEGATING_FORWARDER_ELF),
    );
    let forwarder_id: AccountId = forwarder.id().into();
    let mut state = state().with_programs([forwarder]);
    let alice = public_holder(ALICE);
    let bob = public_holder(BOB);
    let rows = vec![
        token_row(fungible_holding_id(&alice, usd())),
        token_row(fungible_holding_id(&bob, usd())),
        ProgramShardSelector::balance(account(ALICE)),
    ];
    let forwarded = Program::serialize_instruction(Instruction::Transfer {
        sender: alice.clone(),
        recipient: bob.clone(),
        amount_to_transfer: 100,
    })
    .unwrap();
    let forward = |seeds: Vec<PdaSeed>| (programs::token().id(), forwarded.clone(), true, seeds);

    assert_rejected(
        &state,
        &public_tx(
            &state,
            forwarder_id,
            rows.clone(),
            &[],
            &forward(vec![PdaSeed::new([1; 32])]),
        ),
        fungible_holding_id(&alice, usd()),
        "a foreign grant instead of the owner",
    );

    state
        .transition_from_public_transaction(
            &public_tx(&state, forwarder_id, rows, &[&key(ALICE)], &forward(vec![])),
            1,
            0,
        )
        .unwrap();
    assert_eq!(
        state.get_account_by_id(fungible_holding_id(&bob, usd())),
        fungible_holding(usd(), 100)
    );
}

#[test]
fn one_printed_copy_per_owner_at_its_own_address() {
    let mut state = state();
    let stranger = public_holder(STRANGER);
    let bob = public_holder(BOB);
    let master = holding_id(&stranger, nft(), HoldingKind::NftMaster);
    let print = |current: &V03State, copy_holder: &HoldingTarget| {
        token_tx(
            current,
            vec![
                token_row(master),
                token_row(holding_id(copy_holder, nft(), HoldingKind::NftPrintedCopy)),
                ProgramShardSelector::balance(account(STRANGER)),
            ],
            &[&key(STRANGER)],
            &Instruction::PrintNft {
                master_holder: stranger.clone(),
                copy_holder: copy_holder.clone(),
            },
        )
    };
    let copy = |owned| {
        with_token_data(&TokenHolding::NftPrintedCopy {
            definition_id: nft(),
            owned,
        })
    };
    let bob_copy = holding_id(&bob, nft(), HoldingKind::NftPrintedCopy);
    let stranger_copy = holding_id(&stranger, nft(), HoldingKind::NftPrintedCopy);
    assert_ne!(stranger_copy, master);

    state
        .transition_from_public_transaction(
            &token_tx(
                &state,
                vec![token_row(nft()), token_row(bob_copy)],
                &[],
                &Instruction::InitializeAccount {
                    holder: bob.clone(),
                },
            ),
            1,
            0,
        )
        .unwrap();
    assert_eq!(state.get_account_by_id(bob_copy), copy(false));

    state
        .transition_from_public_transaction(&print(&state, &bob), 2, 0)
        .unwrap();
    assert_eq!(state.get_account_by_id(bob_copy), copy(true));
    assert_rejected(&state, &print(&state, &bob), bob_copy, "second copy");

    state
        .transition_from_public_transaction(&print(&state, &stranger), 3, 0)
        .unwrap();
    assert_eq!(state.get_account_by_id(stranger_copy), copy(true));
    assert_eq!(
        state.get_account_by_id(master),
        with_token_data(&TokenHolding::NftMaster {
            definition_id: nft(),
            print_balance: 8,
        })
    );
}

fn receive_privately(
    state: &mut V03State,
    keys: &PrivateKeys,
    identifier: u128,
    amount: u128,
) -> Account {
    let alice = public_holder(ALICE);
    let alice_usd = fungible_holding_id(&alice, usd());
    let holder = keys.holder(identifier);
    let holding = fungible_holding_id(&holder, usd());
    let alice_account = state.get_account_by_id(account(ALICE));
    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                token_row(alice_usd),
                token_row(holding),
                ProgramShardSelector::balance(account(ALICE)),
            ],
            signers: [account(ALICE)].into(),
            public_accounts: HashMap::from([
                (alice_usd, state.get_account_by_id(alice_usd)),
                (account(ALICE), alice_account.clone()),
            ]),
            private_witnesses: vec![keys.holding_witness(
                token_core::holding_seed(holder.owner_id, usd(), HoldingKind::Fungible),
                identifier,
                Account::default(),
                None,
            )],
            instruction_data: Program::serialize_instruction(Instruction::Transfer {
                sender: alice,
                recipient: holder,
                amount_to_transfer: amount,
            })
            .unwrap(),
            dummy_inputs: vec![],
        },
        &programs::token().into(),
    )
    .unwrap();
    let received = keys.decrypt(&output);
    let [(kind, holding_account)] = received.as_slice() else {
        panic!("one note for the recipient");
    };
    assert_eq!(
        *kind,
        PrivateAccountKind::Pda {
            account_id: token_program_id(),
            seed: token_core::holding_seed(
                keys.holder(identifier).owner_id,
                usd(),
                HoldingKind::Fungible,
            ),
            identifier,
        }
    );
    let holding_account = holding_account.clone();
    let tx = pp_tx(vec![alice_account.nonce], (output, proof), &[&key(ALICE)]);
    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();
    holding_account
}

fn spend_privately(
    state: &V03State,
    keys: &PrivateKeys,
    holding_account: &Account,
    owner_account: Option<&Account>,
    owner_ask: Option<AuthorizationSecretKey>,
    sender: &HoldingTarget,
    amount: u128,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), lee::error::LeeError> {
    let holder = keys.holder(0);
    let holding = fungible_holding_id(&holder, usd());
    let owner = holder.owner_id;
    let carol = public_holder(CAROL);
    let carol_usd = fungible_holding_id(&carol, usd());
    let proof = |id, account| state.get_proof_for_commitment(&Commitment::new(&id, account));
    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                token_row(holding),
                token_row(carol_usd),
                ProgramShardSelector::balance(owner),
            ],
            public_accounts: HashMap::from([(carol_usd, state.get_account_by_id(carol_usd))]),
            private_witnesses: vec![
                keys.holding_witness(
                    token_core::holding_seed(holder.owner_id, usd(), HoldingKind::Fungible),
                    0,
                    holding_account.clone(),
                    proof(holding, holding_account),
                ),
                keys.owner_witness(
                    owner_ask,
                    0,
                    owner_account.cloned().unwrap_or_default(),
                    owner_account.and_then(|account| proof(owner, account)),
                ),
            ],
            instruction_data: Program::serialize_instruction(Instruction::Transfer {
                sender: sender.clone(),
                recipient: carol,
                amount_to_transfer: amount,
            })
            .unwrap(),
            ..Default::default()
        },
        &programs::token().into(),
    )
}

#[test]
fn a_private_holding_is_received_without_keys_and_spent_later_by_its_owner() {
    let mut state = state();
    let bob = bob_keys();
    let holder = bob.holder(0);
    let holding = fungible_holding_id(&holder, usd());
    let owner = holder.owner_id;
    let carol_usd = fungible_holding_id(&public_holder(CAROL), usd());

    let holding_account = receive_privately(&mut state, &bob, 0, 100);
    assert_eq!(
        holding_account.data.shard(token_program_id()),
        &ShardData::from(&TokenHolding::Fungible {
            definition_id: usd(),
            balance: 100,
        })
    );
    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(&owner, &Account::default()))
            .is_none()
    );

    let (output, proof) = spend_privately(
        &state,
        &bob,
        &holding_account,
        None,
        Some(bob.ask),
        &holder,
        40,
    )
    .unwrap();
    let notes = bob.decrypt(&output);
    let tx = pp_tx(vec![], (output, proof), &[]);
    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();
    assert_eq!(
        state.get_account_by_id(carol_usd),
        fungible_holding(usd(), 40)
    );
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&tx, 3, 0)
            .is_err()
    );
    let spent_holding = &notes
        .iter()
        .find(|(kind, _)| matches!(kind, PrivateAccountKind::Pda { .. }))
        .unwrap()
        .1;
    let owner_account = &notes
        .iter()
        .find(|(kind, _)| *kind == PrivateAccountKind::Regular(0))
        .unwrap()
        .1;
    assert_eq!(
        spent_holding.data.shard(token_program_id()),
        &ShardData::from(&TokenHolding::Fungible {
            definition_id: usd(),
            balance: 60,
        })
    );
    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(&owner, owner_account))
            .is_some()
    );

    let second_spend = spend_privately(
        &state,
        &bob,
        spent_holding,
        Some(owner_account),
        Some(bob.ask),
        &holder,
        10,
    )
    .unwrap();
    state
        .transition_from_privacy_preserving_transaction(&pp_tx(vec![], second_spend, &[]), 3, 0)
        .unwrap();
    assert_eq!(
        state.get_account_by_id(carol_usd),
        fungible_holding(usd(), 50)
    );
    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(&holding, spent_holding))
            .is_some()
    );
}

#[test]
fn a_private_holding_is_initialized_once() {
    let mut state = state();
    let bob = bob_keys();
    receive_privately(&mut state, &bob, 0, 100);
    receive_privately(&mut state, &bob, 1, 100);

    let alice_usd = fungible_holding_id(&public_holder(ALICE), usd());
    let holder = bob.holder(0);
    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                token_row(alice_usd),
                token_row(fungible_holding_id(&holder, usd())),
                ProgramShardSelector::balance(account(ALICE)),
            ],
            signers: [account(ALICE)].into(),
            public_accounts: HashMap::from([
                (alice_usd, state.get_account_by_id(alice_usd)),
                (account(ALICE), state.get_account_by_id(account(ALICE))),
            ]),
            private_witnesses: vec![bob.holding_witness(
                token_core::holding_seed(holder.owner_id, usd(), HoldingKind::Fungible),
                0,
                Account::default(),
                None,
            )],
            instruction_data: Program::serialize_instruction(Instruction::Transfer {
                sender: public_holder(ALICE),
                recipient: holder,
                amount_to_transfer: 1,
            })
            .unwrap(),
            dummy_inputs: vec![],
        },
        &programs::token().into(),
    )
    .unwrap();
    let nonce = state.get_account_by_id(account(ALICE)).nonce;

    assert!(
        state
            .transition_from_privacy_preserving_transaction(
                &pp_tx(vec![nonce], (output, proof), &[&key(ALICE)]),
                2,
                0
            )
            .is_err()
    );
}

#[test]
fn a_private_holding_is_spent_only_with_its_owner_keys_and_descriptor() {
    let mut state = state();
    let bob = bob_keys();
    let carol = carol_keys();
    let holding_account = receive_privately(&mut state, &bob, 0, 100);
    let holder = bob.holder(0);
    let holding = fungible_holding_id(&holder, usd());
    let seed = token_core::holding_seed(holder.owner_id, usd(), HoldingKind::Fungible);
    let proof = state
        .get_proof_for_commitment(&Commitment::new(&holding, &holding_account))
        .unwrap();

    assert!(
        spend_privately(&state, &bob, &holding_account, None, None, &holder, 40).is_err(),
        "unauthorized owner"
    );
    assert!(
        spend_privately(
            &state,
            &bob,
            &holding_account,
            None,
            Some(carol.ask),
            &holder,
            40
        )
        .is_err(),
        "another key as owner"
    );
    assert!(
        spend_privately(
            &state,
            &bob,
            &holding_account,
            None,
            Some(bob.ask),
            &carol.holder(0),
            40
        )
        .is_err(),
        "forged descriptor"
    );

    let stolen = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                token_row(holding),
                token_row(fungible_holding_id(&public_holder(CAROL), usd())),
                ProgramShardSelector::balance(holder.owner_id),
            ],
            private_witnesses: vec![
                carol.holding_witness(seed, 0, holding_account, Some(proof)),
                bob.owner_witness(Some(bob.ask), 0, Account::default(), None),
            ],
            instruction_data: Program::serialize_instruction(Instruction::Transfer {
                sender: holder,
                recipient: public_holder(CAROL),
                amount_to_transfer: 40,
            })
            .unwrap(),
            ..Default::default()
        },
        &programs::token().into(),
    );
    assert!(stolen.is_err(), "another key on the holding witness");
}

#[test]
fn a_public_and_a_private_holding_of_one_owner_move_in_one_transaction() {
    let mut state = state();
    let bob = bob_keys();
    let private_holder = bob.holder(0);
    let owner = private_holder.owner_id;
    let public_sibling = HoldingTarget {
        owner_id: owner,
        account_id_data: AccountIdData::public(),
    };
    let private_holding = fungible_holding_id(&private_holder, usd());
    let public_holding = fungible_holding_id(&public_sibling, usd());

    let holding_account = receive_privately(&mut state, &bob, 0, 100);
    let proof = |id, account| state.get_proof_for_commitment(&Commitment::new(&id, account));
    let (output, transfer_proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                token_row(private_holding),
                token_row(public_holding),
                ProgramShardSelector::balance(owner),
            ],
            public_accounts: HashMap::from([(
                public_holding,
                state.get_account_by_id(public_holding),
            )]),
            private_witnesses: vec![
                bob.holding_witness(
                    token_core::holding_seed(owner, usd(), HoldingKind::Fungible),
                    0,
                    holding_account.clone(),
                    proof(private_holding, &holding_account),
                ),
                bob.owner_witness(Some(bob.ask), 0, Account::default(), None),
            ],
            instruction_data: Program::serialize_instruction(Instruction::Transfer {
                sender: private_holder,
                recipient: public_sibling,
                amount_to_transfer: 40,
            })
            .unwrap(),
            ..Default::default()
        },
        &programs::token().into(),
    )
    .unwrap();

    state
        .transition_from_privacy_preserving_transaction(
            &pp_tx(vec![], (output, transfer_proof), &[]),
            2,
            0,
        )
        .unwrap();
    assert_eq!(
        state.get_account_by_id(public_holding),
        fungible_holding(usd(), 40)
    );
}
