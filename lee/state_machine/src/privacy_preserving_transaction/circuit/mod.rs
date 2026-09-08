use std::collections::{HashMap, HashSet, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, PrivateWitness,
    ProgramImageClaim, WitnessKind,
    account::{Account, AccountData, AccountId, AccountInput, Data, ProgramShardSelector},
    from_frame,
    program::{ChainedCall, InstructionData, ProgramOutput, compute_public_authorized_pdas},
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
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

/// Inputs for proving an LEE program's execution.
#[derive(Default)]
pub struct ProvingInput {
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub signers: HashSet<AccountId>,
    pub public_accounts: HashMap<AccountId, Account>,
    pub private_witnesses: Vec<PrivateWitness>,
    pub instruction_data: InstructionData,
    pub dummy_inputs: Vec<DummyInput>,
}

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
pub fn execute_and_prove(
    input: ProvingInput,
    program_with_dependencies: &ProgramWithDependencies,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    execute_and_prove_with(input, program_with_dependencies, &mut |_| Ok(None))
}

/// Like [`execute_and_prove`], with `resolve` for additional public shards used by chained calls.
/// `resolve` is called at most once per selector; `None` keeps the local value.
pub fn execute_and_prove_with(
    input: ProvingInput,
    program_with_dependencies: &ProgramWithDependencies,
    resolve: &mut dyn FnMut(ProgramShardSelector) -> Result<Option<Data>, LeeError>,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let ProvingInput {
        shard_selectors,
        signers,
        public_accounts,
        private_witnesses,
        instruction_data,
        dummy_inputs,
    } = input;
    let ProgramWithDependencies {
        program: initial_program,
        self_account_id: initial_account_id,
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();

    // Identify private accounts by their witnesses.
    let witness_by_account: HashMap<AccountId, usize> = private_witnesses
        .iter()
        .enumerate()
        .map(|(index, witness)| (witness.account_id(), index))
        .collect();
    let witness_at = |account_id: &AccountId| {
        witness_by_account
            .get(account_id)
            .map(|index| &private_witnesses[*index])
    };

    let mut materialized: HashMap<AccountId, AccountData> = shard_selectors
        .iter()
        .map(|shard_selector| {
            let account = witness_at(&shard_selector.account_id).map_or_else(
                || {
                    public_accounts
                        .get(&shard_selector.account_id)
                        .map(|account| account.data.clone())
                        .unwrap_or_default()
                },
                |witness| witness.account.data.clone(),
            );
            (shard_selector.account_id, account)
        })
        .collect();

    let is_authorized_top = |account_id: &AccountId| {
        signers.contains(account_id)
            || matches!(
                witness_at(account_id).map(|witness| &witness.kind),
                Some(&WitnessKind::Regular { ask: Some(_) })
            )
    };

    // Accounts authorized by credentials remain authorized across calls.
    let mut globally_authorized: HashSet<AccountId> = shard_selectors
        .iter()
        .map(|shard_selector| shard_selector.account_id)
        .filter(|account_id| {
            is_authorized_top(account_id)
                && !witness_at(account_id).is_some_and(PrivateWitness::is_pda)
        })
        .collect();

    // Accounts the traversal has already reached, so a later sighting is not a first one.
    let mut seen: HashSet<AccountId> = HashSet::new();

    // Shard selectors whose values must not be fetched again.
    let mut covered: HashSet<ProgramShardSelector> = shard_selectors.iter().copied().collect();

    let top_level_pre_states: Vec<AccountInput> = shard_selectors
        .iter()
        .map(|shard_selector| {
            AccountInput::at(
                *shard_selector,
                is_authorized_top(&shard_selector.account_id),
                &materialized[&shard_selector.account_id],
            )
        })
        .collect();

    let initial_call = ChainedCall {
        program_account_id: *initial_account_id,
        instruction_data,
        shard_selectors: shard_selectors.clone(),
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

        // Best-effort mirror of what the circuit will independently authorize, used only to build
        // this callee's input. The top-level call's shard selectors were resolved against the
        // prover's own accounts above and are used as-is.
        let authorized_pdas =
            compute_public_authorized_pdas(caller_account_id, &chained_call.pda_seeds);
        let seed_derives_private_pda = |account_id: &AccountId| {
            let Some(caller_id) = caller_account_id else {
                return false;
            };
            witness_at(account_id)
                .and_then(PrivateWitness::pda_binding)
                .is_some_and(|(bound_program, bound_seed)| {
                    bound_program == caller_id && chained_call.pda_seeds.contains(&bound_seed)
                })
        };

        let real_pre_states: Vec<AccountInput> = if caller_account_id.is_some() {
            let mut resolved = Vec::with_capacity(chained_call.shard_selectors.len());
            for shard_selector in &chained_call.shard_selectors {
                let account_id = shard_selector.account_id;
                let is_authorized = caller_authorized_accounts.contains(&account_id)
                    || globally_authorized.contains(&account_id)
                    || authorized_pdas.contains(&account_id)
                    || seed_derives_private_pda(&account_id);
                let witnessed = witness_at(&account_id).is_some();

                let account = materialized
                    .get_mut(&account_id)
                    .ok_or(InvalidProgramBehaviorError::UnknownChainedCallAccount { account_id })?;

                // Fetch unseen public shards without overwriting earlier writes.
                if !witnessed
                    && let Some(program_account_id) = shard_selector.program_account_id
                    && covered.insert(*shard_selector)
                    && let Some(data) = resolve(*shard_selector)?
                {
                    account.set_shard(program_account_id, data);
                }

                resolved.push(AccountInput::at(*shard_selector, is_authorized, account));
                seen.insert(account_id);
            }
            resolved
        } else {
            top_level_pre_states.clone()
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

            let first_sighting = seen.insert(account_id);
            let pda_match =
                authorized_pdas.contains(&account_id) || seed_derives_private_pda(&account_id);

            materialized
                .entry(account_id)
                .or_default()
                .apply_diff(diff)
                .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?;
            covered.insert(ProgramShardSelector::from(pre));

            if pre.is_authorized {
                authorized_output_accounts.insert(account_id);
                // Keep authorization from credentials available across calls.
                if first_sighting && !pda_match {
                    globally_authorized.insert(account_id);
                }
            }
        }

        // Keep chained calls in the output for the circuit.
        let new_calls = program_output.chained_calls.clone();
        program_outputs.push(program_output);

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in new_calls.into_iter().rev() {
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
        private_witnesses,
        program_account_id: *initial_account_id,
        dummy_inputs,
        initial_shard_selectors: shard_selectors,
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
    pre_states: &[AccountInput],
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
    Ok(prover
        .prove(env, program.elf())
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests;
