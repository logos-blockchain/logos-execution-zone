use std::collections::{HashMap, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    InputAccountIdentity, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput,
    account::AccountWithMetadata,
    program::{ChainedCall, InstructionData, ProgramId, ProgramOutput},
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    error::{InvalidProgramBehaviorError, NssaError},
    program::Program,
    program_methods::{PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID},
    state::MAX_NUMBER_CHAINED_CALLS,
};

/// Proof of the privacy preserving execution circuit.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proof(pub(crate) Vec<u8>);

impl Proof {
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub const fn from_inner(inner: Vec<u8>) -> Self {
        Self(inner)
    }

    pub(crate) fn is_valid_for(&self, circuit_output: &PrivacyPreservingCircuitOutput) -> bool {
        let inner: InnerReceipt = borsh::from_slice(&self.0).unwrap();
        let receipt = Receipt::new(inner, circuit_output.to_bytes());
        receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID).is_ok()
    }
}

#[derive(Clone)]
pub struct ProgramWithDependencies {
    pub program: Program,
    // TODO: avoid having a copy of the bytecode of each dependency.
    pub dependencies: HashMap<ProgramId, Program>,
}

impl ProgramWithDependencies {
    #[must_use]
    pub const fn new(program: Program, dependencies: HashMap<ProgramId, Program>) -> Self {
        Self {
            program,
            dependencies,
        }
    }
}

impl From<Program> for ProgramWithDependencies {
    fn from(program: Program) -> Self {
        Self::new(program, HashMap::new())
    }
}

/// Generates a proof of the execution of a NSSA program inside the privacy preserving execution
/// circuit.
pub fn execute_and_prove(
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
    account_identities: Vec<InputAccountIdentity>,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), NssaError> {
    let ProgramWithDependencies {
        program: initial_program,
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();

    let initial_call = ChainedCall {
        program_id: initial_program.id(),
        instruction_data,
        pre_states,
        pda_seeds: vec![],
    };

    let mut chained_calls = VecDeque::from_iter([(initial_call, initial_program, None)]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program, caller_program_id)) = chained_calls.pop_front() {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(NssaError::MaxChainedCallsDepthExceeded);
        }

        let inner_receipt = execute_and_prove_program(
            program,
            caller_program_id,
            &chained_call.pre_states,
            &chained_call.instruction_data,
        )?;

        let program_output: ProgramOutput = inner_receipt
            .journal
            .decode()
            .map_err(|e| NssaError::ProgramOutputDeserializationError(e.to_string()))?;

        // TODO: remove clone
        program_outputs.push(program_output.clone());

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in program_output.chained_calls.into_iter().rev() {
            let next_program = dependencies.get(&new_call.program_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    program_id: new_call.program_id,
                },
            )?;
            chained_calls.push_front((new_call, next_program, Some(chained_call.program_id)));
        }

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("we check the max depth at the beginning of the loop");
    }

    let circuit_input = PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_id: program_with_dependencies.program.id(),
    };

    env_builder.write(&circuit_input).unwrap();
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &opts)
        .map_err(|e| NssaError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);

    let circuit_output: PrivacyPreservingCircuitOutput = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|e| NssaError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((circuit_output, proof))
}

fn execute_and_prove_program(
    program: &Program,
    caller_program_id: Option<ProgramId>,
    pre_states: &[AccountWithMetadata],
    instruction_data: &InstructionData,
) -> Result<Receipt, NssaError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    Program::write_inputs(
        program.id(),
        caller_program_id,
        pre_states,
        instruction_data,
        &mut env_builder,
    )?;
    let env = env_builder.build().unwrap();

    // Prove the program
    let prover = default_prover();
    Ok(prover
        .prove(env, program.elf())
        .map_err(|e| NssaError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

    use nssa_core::{
        Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, Nullifier,
        SharedSecretKey,
        account::{Account, AccountId, AccountWithMetadata, Nonce, data::Data},
        encryption::PrivateAccountKind,
        program::PdaSeed,
    };

    use super::*;
    use crate::{
        error::NssaError,
        privacy_preserving_transaction::circuit::execute_and_prove,
        program::Program,
        state::{
            CommitmentSet,
            tests::{test_private_account_keys_1, test_private_account_keys_2},
        },
    };

    #[test]
    fn prove_privacy_preserving_execution_circuit_public_and_private_pre_accounts() {
        let recipient_keys = test_private_account_keys_1();
        let program = Program::authenticated_transfer_program();
        let sender = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 100,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );

        let recipient_account_id = AccountId::from((&recipient_keys.npk(), 0));
        let recipient = AccountWithMetadata::new(Account::default(), false, recipient_account_id);

        let balance_to_move: u128 = 37;

        let expected_sender_post = Account {
            program_owner: program.id(),
            balance: 100 - balance_to_move,
            nonce: Nonce::default(),
            data: Data::default(),
        };

        let expected_recipient_post = Account {
            program_owner: program.id(),
            balance: balance_to_move,
            nonce: Nonce::private_account_nonce_init(&recipient_account_id),
            data: Data::default(),
        };

        let expected_sender_pre = sender.clone();

        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &recipient_keys.vpk());

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![
                InputAccountIdentity::Public,
                InputAccountIdentity::PrivateUnauthorized {
                    npk: recipient_keys.npk(),
                    ssk: shared_secret,
                    identifier: 0,
                },
            ],
            &Program::authenticated_transfer_program().into(),
        )
        .unwrap();

        assert!(proof.is_valid_for(&output));

        let [sender_pre] = output.public_pre_states.try_into().unwrap();
        let [sender_post] = output.public_post_states.try_into().unwrap();
        assert_eq!(sender_pre, expected_sender_pre);
        assert_eq!(sender_post, expected_sender_post);
        assert_eq!(output.new_commitments.len(), 1);
        assert_eq!(output.new_nullifiers.len(), 1);
        assert_eq!(output.ciphertexts.len(), 1);

        let (_identifier, recipient_post) = EncryptionScheme::decrypt(
            &output.ciphertexts[0],
            &shared_secret,
            &output.new_commitments[0],
            0,
        )
        .unwrap();
        assert_eq!(recipient_post, expected_recipient_post);
    }

    #[test]
    fn prove_privacy_preserving_execution_circuit_fully_private() {
        let program = Program::authenticated_transfer_program();
        let sender_keys = test_private_account_keys_1();
        let recipient_keys = test_private_account_keys_2();

        let sender_nonce = Nonce(0xdead_beef);
        let sender_pre = AccountWithMetadata::new(
            Account {
                balance: 100,
                nonce: sender_nonce,
                program_owner: program.id(),
                data: Data::default(),
            },
            true,
            AccountId::from((&sender_keys.npk(), 0)),
        );
        let sender_account_id = AccountId::from((&sender_keys.npk(), 0));
        let commitment_sender = Commitment::new(&sender_account_id, &sender_pre.account);

        let recipient_account_id = AccountId::from((&recipient_keys.npk(), 0));
        let recipient = AccountWithMetadata::new(Account::default(), false, recipient_account_id);
        let balance_to_move: u128 = 37;

        let mut commitment_set = CommitmentSet::with_capacity(2);
        commitment_set.extend(std::slice::from_ref(&commitment_sender));
        let expected_new_nullifiers = vec![
            (
                Nullifier::for_account_update(&commitment_sender, &sender_keys.nsk),
                commitment_set.digest(),
            ),
            (
                Nullifier::for_account_initialization(&recipient_account_id),
                DUMMY_COMMITMENT_HASH,
            ),
        ];

        let program = Program::authenticated_transfer_program();

        let expected_private_account_1 = Account {
            program_owner: program.id(),
            balance: 100 - balance_to_move,
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk),
            ..Default::default()
        };
        let expected_private_account_2 = Account {
            program_owner: program.id(),
            balance: balance_to_move,
            nonce: Nonce::private_account_nonce_init(&recipient_account_id),
            ..Default::default()
        };
        let expected_new_commitments = vec![
            Commitment::new(&sender_account_id, &expected_private_account_1),
            Commitment::new(&recipient_account_id, &expected_private_account_2),
        ];

        let esk_1 = [3; 32];
        let shared_secret_1 = SharedSecretKey::new(&esk_1, &sender_keys.vpk());

        let esk_2 = [5; 32];
        let shared_secret_2 = SharedSecretKey::new(&esk_2, &recipient_keys.vpk());

        let (output, proof) = execute_and_prove(
            vec![sender_pre, recipient],
            Program::serialize_instruction(balance_to_move).unwrap(),
            vec![
                InputAccountIdentity::PrivateAuthorizedUpdate {
                    ssk: shared_secret_1,
                    nsk: sender_keys.nsk,
                    membership_proof: commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                    identifier: 0,
                },
                InputAccountIdentity::PrivateUnauthorized {
                    npk: recipient_keys.npk(),
                    ssk: shared_secret_2,
                    identifier: 0,
                },
            ],
            &program.into(),
        )
        .unwrap();

        assert!(proof.is_valid_for(&output));
        assert!(output.public_pre_states.is_empty());
        assert!(output.public_post_states.is_empty());
        assert_eq!(output.new_commitments, expected_new_commitments);
        assert_eq!(output.new_nullifiers, expected_new_nullifiers);
        assert_eq!(output.ciphertexts.len(), 2);

        let (_identifier, sender_post) = EncryptionScheme::decrypt(
            &output.ciphertexts[0],
            &shared_secret_1,
            &expected_new_commitments[0],
            0,
        )
        .unwrap();
        assert_eq!(sender_post, expected_private_account_1);

        let (_identifier, recipient_post) = EncryptionScheme::decrypt(
            &output.ciphertexts[1],
            &shared_secret_2,
            &expected_new_commitments[1],
            1,
        )
        .unwrap();
        assert_eq!(recipient_post, expected_private_account_2);
    }

    #[test]
    fn circuit_fails_when_chained_validity_windows_have_empty_intersection() {
        let account_keys = test_private_account_keys_1();
        let pre = AccountWithMetadata::new(
            Account::default(),
            false,
            AccountId::from((&account_keys.npk(), 0)),
        );

        let validity_window_chain_caller = Program::validity_window_chain_caller();
        let validity_window = Program::validity_window();

        let instruction = Program::serialize_instruction((
            Some(1_u64),
            Some(4_u64),
            validity_window.id(),
            Some(4_u64),
            Some(7_u64),
        ))
        .unwrap();

        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &account_keys.vpk());

        let program_with_deps = ProgramWithDependencies::new(
            validity_window_chain_caller,
            [(validity_window.id(), validity_window)].into(),
        );

        let result = execute_and_prove(
            vec![pre],
            instruction,
            vec![InputAccountIdentity::PrivateUnauthorized {
                npk: account_keys.npk(),
                ssk: shared_secret,
                identifier: 0,
            }],
            &program_with_deps,
        );

        assert!(matches!(result, Err(NssaError::CircuitProvingError(_))));
    }

    /// A private PDA claimed with a non-default identifier produces a ciphertext that decrypts
    /// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
    #[test]
    fn private_pda_claim_with_custom_identifier_encrypts_correct_kind() {
        let program = Program::pda_claimer();
        let keys = test_private_account_keys_1();
        let npk = keys.npk();
        let seed = PdaSeed::new([42; 32]);
        let identifier: u128 = 99;
        let shared_secret = SharedSecretKey::new(&[55; 32], &keys.vpk());

        let account_id = AccountId::for_private_pda(&program.id(), &seed, &npk, identifier);
        let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

        let (output, _proof) = execute_and_prove(
            vec![pre_state],
            Program::serialize_instruction(seed).unwrap(),
            vec![InputAccountIdentity::PrivatePdaInit {
                npk,
                ssk: shared_secret.clone(),
                identifier,
            }],
            &program.clone().into(),
        )
        .unwrap();

        let commitment = output.new_commitments[0].clone();
        let (kind, _account) =
            EncryptionScheme::decrypt(&output.ciphertexts[0], &shared_secret, &commitment, 0)
                .unwrap();

        assert_eq!(
            kind,
            PrivateAccountKind::Pda { program_id: program.id(), seed, identifier },
        );
    }

    /// A private PDA family has two members (identifier=0 and identifier=1, same seed/npk).
    /// Each is funded in a separate transaction; commitments must be distinct and ciphertexts
    /// must carry the correct `PrivateAccountKind::Pda { identifier }`. Alice then spends both.
    #[test]
    fn two_private_pda_family_members_receive_and_spend() {
        let alice_keys = test_private_account_keys_1();
        let alice_npk = alice_keys.npk();
        let recipient_keys = test_private_account_keys_2();

        let proxy = Program::auth_transfer_proxy();
        let auth_transfer = Program::authenticated_transfer_program();
        let proxy_id = proxy.id();
        let auth_transfer_id = auth_transfer.id();
        let seed = PdaSeed::new([42; 32]);
        let amount: u128 = 100;

        let program_with_deps = ProgramWithDependencies::new(
            proxy,
            [(auth_transfer_id, auth_transfer)].into(),
        );

        let alice_pda_0_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, 0);
        let alice_pda_1_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, 1);

        // Public funder account: already owned by auth_transfer so its balance can be debited.
        let funder = AccountWithMetadata::new(
            Account { program_owner: auth_transfer_id, balance: 500, ..Account::default() },
            true,
            AccountId::new([0xAB; 32]),
        );

        let alice_shared_0 = SharedSecretKey::new(&[10; 32], &alice_keys.vpk());
        let alice_shared_1 = SharedSecretKey::new(&[11; 32], &alice_keys.vpk());

        // ── Receive 0: fund alice_pda_0 (identifier = 0) ────────────────────────────────────────
        let (output_recv_0, _) = execute_and_prove(
            vec![
                AccountWithMetadata::new(Account::default(), false, alice_pda_0_id),
                funder.clone(),
            ],
            Program::serialize_instruction((seed, amount, auth_transfer_id)).unwrap(),
            vec![
                InputAccountIdentity::PrivatePdaInit {
                    npk: alice_npk,
                    ssk: alice_shared_0.clone(),
                    identifier: 0,
                },
                InputAccountIdentity::Public,
            ],
            &program_with_deps,
        )
        .unwrap();

        assert_eq!(output_recv_0.new_commitments.len(), 1);
        let commitment_pda_0 = output_recv_0.new_commitments[0].clone();

        let (kind_0, alice_pda_0_account) = EncryptionScheme::decrypt(
            &output_recv_0.ciphertexts[0],
            &alice_shared_0,
            &commitment_pda_0,
            0,
        )
        .unwrap();
        assert_eq!(
            kind_0,
            PrivateAccountKind::Pda { program_id: proxy_id, seed, identifier: 0 },
        );
        assert_eq!(alice_pda_0_account.balance, amount);

        // ── Receive 1: fund alice_pda_1 (identifier = 1, same seed) ─────────────────────────────
        let (output_recv_1, _) = execute_and_prove(
            vec![
                AccountWithMetadata::new(Account::default(), false, alice_pda_1_id),
                funder.clone(),
            ],
            Program::serialize_instruction((seed, amount, auth_transfer_id)).unwrap(),
            vec![
                InputAccountIdentity::PrivatePdaInit {
                    npk: alice_npk,
                    ssk: alice_shared_1.clone(),
                    identifier: 1,
                },
                InputAccountIdentity::Public,
            ],
            &program_with_deps,
        )
        .unwrap();

        assert_eq!(output_recv_1.new_commitments.len(), 1);
        let commitment_pda_1 = output_recv_1.new_commitments[0].clone();

        let (kind_1, alice_pda_1_account) = EncryptionScheme::decrypt(
            &output_recv_1.ciphertexts[0],
            &alice_shared_1,
            &commitment_pda_1,
            0,
        )
        .unwrap();
        assert_eq!(
            kind_1,
            PrivateAccountKind::Pda { program_id: proxy_id, seed, identifier: 1 },
        );
        assert_eq!(alice_pda_1_account.balance, amount);

        // Different identifiers produce distinct commitments.
        assert_ne!(commitment_pda_0, commitment_pda_1);

        // ── Spend 0: alice spends alice_pda_0 ───────────────────────────────────────────────────
        let mut cs_0 = CommitmentSet::with_capacity(1);
        cs_0.extend(std::slice::from_ref(&commitment_pda_0));
        let proof_pda_0 = cs_0.get_proof_for(&commitment_pda_0);

        let recipient_0_id = AccountId::from((&recipient_keys.npk(), 0u128));
        let (output_spend_0, _) = execute_and_prove(
            vec![
                AccountWithMetadata::new(alice_pda_0_account, true, alice_pda_0_id),
                AccountWithMetadata::new(Account::default(), false, recipient_0_id),
            ],
            Program::serialize_instruction((seed, amount, auth_transfer_id)).unwrap(),
            vec![
                InputAccountIdentity::PrivatePdaUpdate {
                    ssk: alice_shared_0.clone(),
                    nsk: alice_keys.nsk,
                    membership_proof: proof_pda_0.expect("pda_0 commitment must be in the set"),
                    identifier: 0,
                },
                InputAccountIdentity::PrivateUnauthorized {
                    npk: recipient_keys.npk(),
                    ssk: SharedSecretKey::new(&[20; 32], &recipient_keys.vpk()),
                    identifier: 0,
                },
            ],
            &program_with_deps,
        )
        .unwrap();

        assert_eq!(output_spend_0.new_commitments.len(), 2);
        assert_eq!(output_spend_0.new_nullifiers.len(), 2);

        // ── Spend 1: alice spends alice_pda_1 ───────────────────────────────────────────────────
        let mut cs_1 = CommitmentSet::with_capacity(1);
        cs_1.extend(std::slice::from_ref(&commitment_pda_1));
        let proof_pda_1 = cs_1.get_proof_for(&commitment_pda_1);

        let recipient_1_id = AccountId::from((&recipient_keys.npk(), 1u128));
        let (output_spend_1, _) = execute_and_prove(
            vec![
                AccountWithMetadata::new(alice_pda_1_account, true, alice_pda_1_id),
                AccountWithMetadata::new(Account::default(), false, recipient_1_id),
            ],
            Program::serialize_instruction((seed, amount, auth_transfer_id)).unwrap(),
            vec![
                InputAccountIdentity::PrivatePdaUpdate {
                    ssk: alice_shared_1.clone(),
                    nsk: alice_keys.nsk,
                    membership_proof: proof_pda_1.expect("pda_1 commitment must be in the set"),
                    identifier: 1,
                },
                InputAccountIdentity::PrivateUnauthorized {
                    npk: recipient_keys.npk(),
                    ssk: SharedSecretKey::new(&[21; 32], &recipient_keys.vpk()),
                    identifier: 1,
                },
            ],
            &program_with_deps,
        )
        .unwrap();

        assert_eq!(output_spend_1.new_commitments.len(), 2);
        assert_eq!(output_spend_1.new_nullifiers.len(), 2);
    }

    /// Group PDA deposit: creates a new PDA and transfers balance from the
    /// counterparty. Both accounts owned by `private_pda_spender`.
    #[test]
    fn group_pda_deposit() {
        let program = Program::private_pda_spender();
        let noop = Program::noop();
        let keys = test_private_account_keys_1();
        let npk = keys.npk();
        let seed = PdaSeed::new([42; 32]);
        let shared_secret_pda = SharedSecretKey::new(&[55; 32], &keys.vpk());

        // PDA (new, mask 3)
        let pda_id = AccountId::for_private_pda(&program.id(), &seed, &npk, 0);
        let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

        // Sender (mask 0, public, owned by this program, has balance)
        let sender_id = AccountId::new([99; 32]);
        let sender_pre = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 10000,
                ..Account::default()
            },
            true,
            sender_id,
        );

        let noop_id = noop.id();
        let program_with_deps = ProgramWithDependencies::new(program, [(noop_id, noop)].into());

        let instruction = Program::serialize_instruction((seed, noop_id, 500_u128, true)).unwrap();

        // PDA is mask 3 (private PDA), sender is mask 0 (public).
        // The noop chained call is required to establish the mask-3 (seed, npk) binding
        // that the circuit enforces for private PDAs. Without a caller providing pda_seeds,
        // the circuit's binding check rejects the account.
        let result = execute_and_prove(
            vec![pda_pre, sender_pre],
            instruction,
            vec![
                InputAccountIdentity::PrivatePdaInit {
                    npk,
                    ssk: shared_secret_pda,
                    identifier: 0,
                },
                InputAccountIdentity::Public,
            ],
            &program_with_deps,
        );

        let (output, _proof) = result.expect("group PDA deposit should succeed");
        // Only PDA (mask 3) produces a commitment; sender (mask 0) is public.
        assert_eq!(output.new_commitments.len(), 1);
    }

    /// Group PDA spend binding: the noop chained call with `pda_seeds` establishes
    /// the mask-3 binding for an existing-but-default PDA. Uses amount=0 because
    /// testing with a pre-funded PDA requires a two-tx sequence with membership proofs.
    #[test]
    fn group_pda_spend_binding() {
        let program = Program::private_pda_spender();
        let noop = Program::noop();
        let keys = test_private_account_keys_1();
        let npk = keys.npk();
        let seed = PdaSeed::new([42; 32]);
        let shared_secret_pda = SharedSecretKey::new(&[55; 32], &keys.vpk());

        let pda_id = AccountId::for_private_pda(&program.id(), &seed, &npk, 0);
        let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

        let bob_id = AccountId::new([88; 32]);
        let bob_pre = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 10000,
                ..Account::default()
            },
            true,
            bob_id,
        );

        let noop_id = noop.id();
        let program_with_deps = ProgramWithDependencies::new(program, [(noop_id, noop)].into());

        let instruction = Program::serialize_instruction((seed, noop_id, 0_u128, false)).unwrap();

        let result = execute_and_prove(
            vec![pda_pre, bob_pre],
            instruction,
            vec![
                InputAccountIdentity::PrivatePdaInit {
                    npk,
                    ssk: shared_secret_pda,
                    identifier: 0,
                },
                InputAccountIdentity::Public,
            ],
            &program_with_deps,
        );

        let (output, _proof) = result.expect("group PDA spend binding should succeed");
        assert_eq!(output.new_commitments.len(), 1);
    }
}
