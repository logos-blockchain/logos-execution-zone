use std::collections::{HashMap, HashSet, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, InputAccountIdentity, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput, ProgramImageClaim,
    account::{Account, AccountId, AccountWithMetadata},
    from_frame,
    program::{
        ChainedCall, InstructionData, ProgramOutput, compute_public_authorized_pdas, post_state,
    },
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
    error::{InvalidProgramBehaviorError, LeeError},
    program::{Program, check_exit_code},
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
        let Ok(inner) = borsh::from_slice::<InnerReceipt>(&self.0) else {
            return false;
        };
        let receipt = Receipt::new(inner, circuit_output.to_bytes());
        receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID).is_ok()
    }
}

#[derive(Clone)]
pub struct ProgramWithDependencies {
    pub program: Program,
    /// Where `program` is actually deployed — never assumed to be its bytecode's bijection
    /// address, since the same bytecode may be deployed more than once at different addresses.
    pub self_account_id: AccountId,
    // TODO: avoid having a copy of the bytecode of each dependency.
    /// Every program a chained call may target, keyed by the account address it's deployed at —
    /// never its bytecode identity, for the same reason. The caller building this off-chain
    /// (e.g. the wallet) already knows which program lives where; there's no live state to look
    /// it up against inside a pure proving function.
    pub dependencies: HashMap<AccountId, Program>,
}

impl ProgramWithDependencies {
    #[must_use]
    pub const fn new(
        program: Program,
        self_account_id: AccountId,
        dependencies: HashMap<AccountId, Program>,
    ) -> Self {
        Self {
            program,
            self_account_id,
            dependencies,
        }
    }
}

impl From<Program> for ProgramWithDependencies {
    /// Assumes `program` lives at its bijection address — the common case (genesis-seeded
    /// builtins, or anything not yet moved by `program_loader`). Use [`Self::new`] directly for a
    /// program deployed elsewhere.
    fn from(program: Program) -> Self {
        let self_account_id = AccountId::from(program.id());
        Self::new(program, self_account_id, HashMap::new())
    }
}

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
pub fn execute_and_prove(
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
    account_identities: Vec<InputAccountIdentity>,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    execute_and_prove_with_padded_inputs(
        pre_states,
        instruction_data,
        account_identities,
        vec![],
        program_with_dependencies,
    )
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Public entry point — taking ownership signals the caller hands off its top-level \
              account values for the duration of the proof; callers already construct these \
              freshly per call, so a borrow would just push the clone to every call site"
)]
pub fn execute_and_prove_with_padded_inputs(
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
    account_identities: Vec<InputAccountIdentity>,
    dummy_inputs: Vec<DummyInput>,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let ProgramWithDependencies {
        program: initial_program,
        self_account_id: initial_account_id,
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();

    // Best-effort mirror of the account state the circuit will independently derive; getting it
    // wrong just wastes a proving attempt, since the circuit itself is the source of truth.
    let mut materialized_state: HashMap<AccountId, Account> = pre_states
        .iter()
        .map(|pre| (pre.account_id, pre.account.clone()))
        .collect();
    let pre_state_ids: Vec<AccountId> = pre_states.iter().map(|pre| pre.account_id).collect();
    // Captured before pre_states moves into initial_call below.
    let initial_pre_states: Vec<AccountId> = pre_state_ids.clone();

    // Non-PDA accounts authorized at their first sight, anywhere in the call tree — mirrors
    // the circuit's own `globally_authorized`. Seeded from top-level `is_authorized` since the
    // circuit never independently re-verifies a credential; nothing else could supply it.
    let mut globally_authorized: HashSet<AccountId> = pre_states
        .iter()
        .filter(|pre| pre.is_authorized)
        .map(|pre| pre.account_id)
        .collect();

    // First-sighting position in the circuit's own traversal order, for private-PDA witness
    // lookup. Assigned lazily from each call's actual output (below), including the top-level
    // one — never pre-seeded from raw input order, which the top-level program is free to not
    // honor in its own output.
    let mut position_by_account: HashMap<AccountId, usize> = HashMap::new();
    let mut next_position: usize = 0;

    let initial_call = ChainedCall {
        program_account_id: *initial_account_id,
        instruction_data,
        pre_state_ids,
        pda_seeds: vec![],
    };

    let mut chained_calls =
        VecDeque::from_iter([(initial_call, initial_program, None, HashSet::new())]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program, caller_account_id, caller_authorized_accounts)) =
        chained_calls.pop_front()
    {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(LeeError::MaxChainedCallsDepthExceeded);
        }

        // Best-effort mirror of what the circuit will independently authorize (see comment at
        // the top), used only to build this callee's input. The top-level call's pre_states
        // came straight from the caller, not a `ChainedCall`, and are used as-is.
        let authorized_pdas =
            compute_public_authorized_pdas(caller_account_id, &chained_call.pda_seeds);

        let real_pre_states: Vec<AccountWithMetadata> = if let Some(caller_id) = caller_account_id {
            let mut resolved = Vec::with_capacity(chained_call.pre_state_ids.len());
            for account_id in &chained_call.pre_state_ids {
                let account = materialized_state.get(account_id).cloned().ok_or(
                    InvalidProgramBehaviorError::UnknownChainedCallAccount {
                        account_id: *account_id,
                    },
                )?;

                let position = *position_by_account.entry(*account_id).or_insert_with(|| {
                    let pos = next_position;
                    next_position = next_position
                        .checked_add(1)
                        .expect("account position count cannot overflow usize");
                    pos
                });
                let private_pda_witness = account_identities
                    .get(position)
                    .and_then(InputAccountIdentity::npk_vpk_if_private_pda);

                let pda_match = authorized_pdas.contains(account_id)
                    || private_pda_witness.is_some_and(|(npk, vpk, identifier)| {
                        chained_call.pda_seeds.iter().any(|seed| {
                            AccountId::for_private_pda(&caller_id, seed, &npk, &vpk, identifier)
                                == *account_id
                        })
                    });

                let is_authorized = caller_authorized_accounts.contains(account_id)
                    || globally_authorized.contains(account_id)
                    || pda_match;

                resolved.push(AccountWithMetadata::new(
                    account,
                    is_authorized,
                    *account_id,
                ));
            }
            resolved
        } else {
            pre_states.clone()
        };

        let inner_receipt = execute_and_prove_program(
            program,
            chained_call.program_account_id,
            caller_account_id,
            &real_pre_states,
            &chained_call.instruction_data,
        )?;

        let program_output: ProgramOutput =
            borsh::from_slice(from_frame(&inner_receipt.journal.bytes).ok_or_else(|| {
                LeeError::ProgramOutputDeserializationError(
                    "malformed inner-receipt journal frame".to_owned(),
                )
            })?)
            .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;

        // Authorization scoped to this call's own subtree: starts from what this call itself
        // inherited from its caller, plus every account this call's own output reports
        // authorized — handed to this call's children only, never to its siblings. Mirrors
        // `authorized_accounts.extend(authorized_output_accounts)` in-circuit.
        let mut authorized_output_accounts = caller_authorized_accounts;

        for diff in &program_output.state_diffs {
            let pre = &diff.pre_state;
            let account_id = pre.account_id;

            // Assigned here, after this call has actually run, uniformly for the top-level
            // call too — it's free to never echo a given account in its own output at all.
            let first_sighting = !position_by_account.contains_key(&account_id);
            let position = *position_by_account.entry(account_id).or_insert_with(|| {
                let pos = next_position;
                next_position = next_position
                    .checked_add(1)
                    .expect("account position count cannot overflow usize");
                pos
            });
            let private_pda_witness = account_identities
                .get(position)
                .and_then(InputAccountIdentity::npk_vpk_if_private_pda);
            let pda_match = authorized_pdas.contains(&account_id)
                || caller_account_id.is_some_and(|caller_id| {
                    private_pda_witness.is_some_and(|(npk, vpk, identifier)| {
                        chained_call.pda_seeds.iter().any(|seed| {
                            AccountId::for_private_pda(&caller_id, seed, &npk, &vpk, identifier)
                                == account_id
                        })
                    })
                });

            // A data write to an unowned account acquires it; the guest doesn't write this into
            // its own post_state, the circuit does it afterward, so predict it here too.
            let post = post_state(diff, chained_call.program_account_id)
                .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?;
            materialized_state.insert(account_id, post);
            if pre.is_authorized {
                authorized_output_accounts.insert(account_id);
                // Only a first-sighted, non-pda-matched account is a "regular account
                // authorized by real credential" claim — mirrors the circuit's own
                // `authorize_first_sight_without_pda_witness` else-branch. A pda match is
                // already captured, subtree-scoped, by `authorized_output_accounts` above.
                if first_sighting && !pda_match {
                    globally_authorized.insert(account_id);
                }
            }
        }

        // TODO: remove clone
        program_outputs.push(program_output.clone());

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in program_output.chained_calls.into_iter().rev() {
            let next_program = dependencies.get(&new_call.program_account_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    program_account_id: new_call.program_account_id,
                },
            )?;
            chained_calls.push_front((
                new_call,
                next_program,
                Some(chained_call.program_account_id),
                authorized_output_accounts.clone(),
            ));
        }

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("we check the max depth at the beginning of the loop");
    }

    // Every address-deployed program actually invoked, claimed against its real bytecode
    // identity — the guest circuit uses these for `env::verify`, unchecked; the sequencer
    // verifies each one against real chain state before accepting the proof (see
    // `ProgramImageClaim`'s doc comment).
    let program_image_claims: Vec<ProgramImageClaim> =
        std::iter::once((*initial_account_id, initial_program.id()))
            .chain(
                dependencies
                    .iter()
                    .map(|(account_id, program)| (*account_id, program.id())),
            )
            .map(|(account_id, image_id)| ProgramImageClaim {
                account_id,
                image_id,
            })
            .collect();

    let circuit_input = PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_account_id: *initial_account_id,
        dummy_inputs,
        initial_pre_states,
        program_image_claims,
    };

    let circuit_input_payload = borsh::to_vec(&circuit_input)?;
    env_builder.write_slice(&to_frame(&circuit_input_payload));
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &opts)
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);

    let circuit_output: PrivacyPreservingCircuitOutput = borsh::from_slice(
        from_frame(&prove_info.receipt.journal.bytes).ok_or_else(|| {
            LeeError::CircuitOutputDeserializationError(
                "malformed circuit journal frame".to_owned(),
            )
        })?,
    )
    .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((circuit_output, proof))
}

fn execute_and_prove_program(
    program: &Program,
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: &[AccountWithMetadata],
    instruction_data: &InstructionData,
) -> Result<Receipt, LeeError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    program.write_inputs(
        self_account_id,
        caller_account_id,
        pre_states,
        instruction_data,
        &mut env_builder,
    )?;
    let env = env_builder.build().unwrap();

    // Prove the program
    let prover = default_prover();
    let prove_info = prover
        .prove(env, program.elf())
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?;

    // The local prover proves any exit code, and the circuit's `env::verify` only resolves a
    // `Halted(0)` claim, so gate here for a typed error before the expensive circuit proof.
    let exit_code = prove_info
        .receipt
        .claim()
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .as_value()
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .exit_code;
    check_exit_code(
        exit_code,
        prove_info.stats.user_cycles,
        LeeError::ProgramProveFailed,
    )?;
    Ok(prove_info.receipt)
}

#[cfg(test)]
mod tests;
