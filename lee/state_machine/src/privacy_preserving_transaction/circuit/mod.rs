use std::collections::{HashMap, HashSet, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, InputAccount, InputAccountIdentity, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput,
    account::{Account, AccountId, AccountWithMetadata},
    from_frame,
    program::{
        CallerData, ChainedCall, InstructionData, MAX_NUMBER_CHAINED_CALLS, ProgramEffects,
        ProgramId, ProgramOutput, match_caller_seed_as_private_pda,
        match_caller_seed_as_public_pda,
    },
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
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

/// Generates a proof of the execution of a LEE program inside the privacy preserving execution
/// circuit.
///
/// `account_identities[i]` describes `pre_states[i]`. The circuit keys these by `AccountId`, so
/// this is the caller's own order throughout — not the order the entry program happens to commit
/// its `pre_states` in, which the caller cannot know before it runs.
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

/// As [`execute_and_prove`], with dummy private inputs padding the output. `account_identities[i]`
/// describes `pre_states[i]`.
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
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_effects: Vec<ProgramEffects> = Vec::new();

    // Best-effort mirror of the account state the circuit will independently derive; getting it
    // wrong just wastes a proving attempt, since the circuit itself is the source of truth.
    let mut materialized_state: HashMap<AccountId, Account> = pre_states
        .iter()
        .map(|pre| (pre.account_id, pre.account.clone()))
        .collect();

    // The transaction's own credentials. Nothing downstream can re-derive these — a private
    // account's authorization may come from a witnessed `ask` with no public-derivable equivalent
    // — and the circuit reads them back as `InputAccount::is_authorized`. Consulted at an
    // account's first sight, wherever in the call tree that falls: the entry program need not
    // name every account it was handed.
    let attested_credentials: HashSet<AccountId> = pre_states
        .iter()
        .filter(|pre| pre.is_authorized)
        .map(|pre| pre.account_id)
        .collect();

    // `zip` below would silently drop a surplus identity, where the circuit's own count check
    // rejects it. Too few still reaches that check as an unresolvable account.
    ensure!(
        account_identities.len() <= pre_states.len(),
        LeeError::InvalidInput("More account identities than accounts".into())
    );

    // An account first sighted at depth was untouched until then — reaching it is what lets a
    // program modify it — so its top-level value is still its first-sight value, and the circuit
    // can be handed all of them up front.
    let input_accounts: Vec<InputAccount> = pre_states
        .iter()
        .zip(account_identities)
        .map(|(pre, identity)| InputAccount {
            account_id: pre.account_id,
            account: pre.account.clone(),
            is_authorized: pre.is_authorized,
            identity,
        })
        .collect();

    let private_pda_witnesses: HashMap<_, _> = input_accounts
        .iter()
        .filter_map(|input| Some((input.account_id, input.identity.npk_vpk_if_private_pda()?)))
        .collect();

    // Mirrors the circuit's `globally_authorized`: only a plain account's own credential is
    // remembered transaction-wide, and only at the sight that establishes it. A PDA is re-derived
    // from its caller's seeds at every sight instead, so it must never land here — an entry would
    // authorize it in calls the circuit leaves it unauthorized in, and the journals would part.
    let mut globally_authorized: HashSet<AccountId> = HashSet::new();

    // The accounts the walk has already reached. A plain account's attested credential is
    // consulted at its first sight only; every later sight derives its authorization instead.
    let mut sighted: HashSet<AccountId> = HashSet::new();
    let mut top_level_accounts: Vec<AccountId> = Vec::new();

    let top_level_program_id = initial_program.id();
    let top_level_instruction_data = instruction_data.clone();
    let initial_call = ChainedCall {
        program_id: top_level_program_id,
        instruction_data,
        // No caller names the entry call's accounts, so nothing resolves them from refs; the
        // walk hands it `pre_states` verbatim instead.
        accounts: Vec::new(),
        pda_seeds: vec![],
    };

    let initial_caller = CallerData {
        program_id: None,
        authorized_accounts: HashSet::new(),
    };
    let mut chained_calls = VecDeque::from_iter([(initial_call, initial_program, initial_caller)]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program, caller)) = chained_calls.pop_front() {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(LeeError::MaxChainedCallsDepthExceeded);
        }

        // The entry call's pre_states came straight from the caller of `execute_and_prove` and
        // already carry the attested credentials, so there is nothing to resolve: no caller named
        // them and no seeds delegate them.
        let real_pre_states: Vec<AccountWithMetadata> = if caller.program_id.is_some() {
            let mut resolved = Vec::with_capacity(chained_call.accounts.len());
            for account_id in &chained_call.accounts {
                let account = materialized_state.get(account_id).cloned().ok_or(
                    InvalidProgramBehaviorError::UnknownChainedCallAccount {
                        account_id: *account_id,
                    },
                )?;

                let first_sight = sighted.insert(*account_id);
                let private_pda_witness = private_pda_witnesses.get(account_id);
                let public_pda_seed_match =
                    match_caller_seed_as_public_pda(&caller, &chained_call.pda_seeds, *account_id)
                        .is_some();

                let is_authorized =
                    if first_sight && private_pda_witness.is_none() && !public_pda_seed_match {
                        // The circuit's first-sight fallthrough: nothing derives a plain account's
                        // authorization, so its own credential decides — and it is the only kind of
                        // authorization worth remembering transaction-wide.
                        let attested = attested_credentials.contains(account_id);
                        if attested {
                            globally_authorized.insert(*account_id);
                        }
                        attested
                    } else {
                        public_pda_seed_match
                            || match_caller_seed_as_private_pda(
                                &private_pda_witnesses,
                                &caller,
                                &chained_call.pda_seeds,
                                *account_id,
                            )
                            .is_some()
                            || globally_authorized.contains(account_id)
                            || caller.authorized_accounts.contains(account_id)
                    };

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
            caller.program_id,
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

        if caller.program_id.is_none() {
            // The top-level program is handed the transaction's own accounts and may commit them
            // in an order of its own choosing; nothing else names them, so its order is the one
            // the circuit walks.
            top_level_accounts = program_output
                .pre_states
                .iter()
                .map(|pre| pre.account_id)
                .collect();
            for pre in &program_output.pre_states {
                sighted.insert(pre.account_id);
                // The same first-sight rule, minus the seed matches an entry call cannot have: a
                // private account's witnessed `ask` is a credential like a signature, a private
                // PDA's authorization is not. Taken from the transaction's own credentials, not
                // from the journal's echo of them — the circuit derives from the former.
                if attested_credentials.contains(&pre.account_id)
                    && !private_pda_witnesses.contains_key(&pre.account_id)
                {
                    globally_authorized.insert(pre.account_id);
                }
            }
        }

        // What this call's own callees inherit: what it inherited, plus what it was authorized
        // for here. Per path, not transaction-wide — a sibling call is not a descendant.
        let mut authorized_accounts = caller.authorized_accounts;
        for (pre, post) in program_output
            .pre_states
            .iter()
            .zip(&program_output.effects.post_states)
        {
            // A successful claim reassigns ownership; the guest doesn't write this into its own
            // diff, the circuit does it afterward, so predict it here too. Otherwise the owner is
            // inherited from the pre-state — an `AccountDiff` carries no ownership.
            materialized_state.insert(
                pre.account_id,
                post.materialize(&pre.account, chained_call.program_id)
                    .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?,
            );
            if pre.is_authorized {
                authorized_accounts.insert(pre.account_id);
            }
        }

        // Prove circuit.
        env_builder.add_assumption(inner_receipt);

        for new_call in program_output.effects.chained_calls.iter().rev() {
            let next_program = dependencies.get(&new_call.program_id).ok_or(
                InvalidProgramBehaviorError::UndeclaredProgramDependency {
                    program_id: new_call.program_id,
                },
            )?;
            chained_calls.push_front((
                new_call.clone(),
                next_program,
                CallerData {
                    program_id: Some(chained_call.program_id),
                    authorized_accounts: authorized_accounts.clone(),
                },
            ));
        }

        program_effects.push(program_output.effects);

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("we check the max depth at the beginning of the loop");
    }

    let circuit_input = PrivacyPreservingCircuitInput {
        program_effects,
        top_level_program_id,
        top_level_instruction_data,
        top_level_accounts,
        input_accounts,
        dummy_inputs,
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
    caller_program_id: Option<ProgramId>,
    pre_states: &[AccountWithMetadata],
    instruction_data: &InstructionData,
) -> Result<Receipt, LeeError> {
    // Write inputs to the program
    let mut env_builder = ExecutorEnv::builder();
    program.write_inputs(
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
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests;
