use std::collections::{HashMap, HashSet, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    DummyInput, InputAccountIdentity, PrivacyPreservingCircuitInput,
    PrivacyPreservingCircuitOutput,
    account::{Account, AccountId, AccountWithMetadata, apply_balance_diff},
    program::{
        ChainedCall, DEFAULT_PROGRAM_OWNER, InstructionData, ProgramId, ProgramOutput,
        UpdateFromDiffOutput, compute_public_authorized_pdas,
    },
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
        dependencies,
    } = program_with_dependencies;
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();
    let mut update_from_diff_results = Vec::new();

    // Captured before `pre_states` moves below — this is the only place `is_authorized` is
    // caller-supplied; every later pre_state's authorization is derived inside the circuit from
    // this same list. Public accounts only: a private (`npk`/`vpk`-derived) `AccountId` could
    // never match a real signature, so including one would make it permanently unverifiable.
    let signer_account_ids: Vec<AccountId> = pre_states
        .iter()
        .zip(&account_identities)
        .filter(|(pre, identity)| pre.is_authorized && identity.is_public())
        .map(|(pre, _)| pre.account_id)
        .collect();

    // Tracks each account's currently-known materialized state as calls are proven, so a
    // chained call naming an account by id (rather than supplying a value) can be resolved to
    // the real thing rather than trusting whatever the calling guest program predicted. Mirrors
    // `state_diff` in the public-transaction path, and the circuit's own `self.post_states` —
    // this is the host-side counterpart, since the host has no access to the circuit's internal
    // state (it drives execution and proving sequentially, before the outer circuit ever runs).
    let mut materialized_state: HashMap<AccountId, Account> = pre_states
        .iter()
        .map(|pre| (pre.account_id, pre.account.clone()))
        .collect();
    let pre_state_refs: Vec<AccountId> = pre_states.iter().map(|pre| pre.account_id).collect();

    // Host-side best-effort mirror of the circuit's own authorization derivation
    // (`resolve_authorization_and_record_bindings`), used only to decide what `is_authorized`
    // to feed a *chained* callee — getting this wrong isn't a security issue (the circuit is the
    // actual source of truth and simply fails to prove on a mismatch), only a wasted proving
    // attempt. Seeded from every top-level account's own `is_authorized`, not just
    // `signer_account_ids` (public-only) — a private account's authorization comes from a
    // witnessed `ask` with no public-derivable equivalent, and still needs to propagate forward
    // if that account gets named again in a later chained call.
    let mut host_authorized_accounts: HashSet<AccountId> = pre_states
        .iter()
        .filter(|pre| pre.is_authorized)
        .map(|pre| pre.account_id)
        .collect();

    // Position of each account's first sighting, in the same traversal order the circuit uses
    // internally (`account_identities` is supplied 1:1 with that order, by contract). Needed to
    // look up a private-PDA account's witnessed `(npk, vpk, identifier)`, since a private PDA's
    // authorization can't be derived from `AccountId` alone the way a public PDA's can.
    let mut position_by_account: HashMap<AccountId, usize> = pre_states
        .iter()
        .enumerate()
        .map(|(pos, pre)| (pre.account_id, pos))
        .collect();
    let mut next_position = pre_states.len();

    let initial_call = ChainedCall {
        program_id: initial_program.id(),
        instruction_data,
        pre_state_refs,
        pda_seeds: vec![],
    };

    let mut chained_calls = VecDeque::from_iter([(initial_call, initial_program, None)]);
    let mut chain_calls_counter = 0;
    while let Some((chained_call, program, caller_program_id)) = chained_calls.pop_front() {
        if chain_calls_counter >= MAX_NUMBER_CHAINED_CALLS {
            return Err(LeeError::MaxChainedCallsDepthExceeded);
        }

        // The very first call (`caller_program_id.is_none()`) is the only one whose pre_states
        // were directly supplied by the caller of `execute_and_prove`, not by another guest
        // program's `ChainedCall` — use them as-is, since a private account's `is_authorized`
        // here can't be re-derived from `host_authorized_accounts`/`authorized_pdas` (both
        // scoped to what's publicly re-derivable) without silently dropping legitimate
        // authorization backed by a witnessed `ask`.
        let real_pre_states: Vec<AccountWithMetadata> = if let Some(caller_id) = caller_program_id {
            let authorized_pdas =
                compute_public_authorized_pdas(caller_program_id, &chained_call.pda_seeds);

            // Resolve the callee's actual pre_states from the tracked state above — the calling
            // guest program only named which accounts to call with, it never supplied a value.
            let mut resolved = Vec::with_capacity(chained_call.pre_state_refs.len());
            for account_id in &chained_call.pre_state_refs {
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

                let is_authorized = host_authorized_accounts.contains(account_id)
                    || authorized_pdas.contains(account_id)
                    || private_pda_witness.is_some_and(|(npk, vpk, identifier)| {
                        chained_call.pda_seeds.iter().any(|seed| {
                            AccountId::for_private_pda(&caller_id, seed, &npk, &vpk, identifier)
                                == *account_id
                        })
                    });

                resolved.push(AccountWithMetadata::new(
                    account,
                    is_authorized,
                    *account_id,
                ));
            }
            resolved
        } else {
            // The very first call is the only one whose pre_states were directly supplied by the
            // caller of `execute_and_prove`, not by another guest program's `ChainedCall` — use
            // them as-is, since a private account's `is_authorized` here can't be re-derived from
            // the checks above (all scoped to what's publicly/PDA re-derivable) without silently
            // dropping legitimate authorization backed by a witnessed `ask`.
            pre_states.clone()
        };

        let inner_receipt = execute_and_prove_program(
            program,
            caller_program_id,
            &real_pre_states,
            &chained_call.instruction_data,
        )?;

        let program_output: ProgramOutput = inner_receipt
            .journal
            .decode()
            .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;

        // Prove `update_from_diff` for every account this call's diff writes data to, in the
        // same order `execution_state::derive_from_outputs` will visit them, so
        // `update_from_diff_results` lines up positionally with the circuit's own traversal.
        // Dispatched to the account's *owner* program, not necessarily the caller — falls back
        // to the caller only when the account is still unclaimed (default owner). Also
        // materializes each diff into `materialized_state` below, mirroring the circuit's own
        // `validate_and_sync_states` — a best-effort mirror, not authoritative: if it's ever
        // wrong, the circuit (the real source of truth) just fails to prove.
        for (pre, diff_output) in program_output
            .pre_states
            .iter()
            .zip(&program_output.post_states)
        {
            let diff = diff_output.diff();
            let balance = apply_balance_diff(pre.account.balance, diff.diff_balance)
                .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?;

            let data = if let Some(diff_data) = diff.diff_data.as_ref() {
                let owner_id: ProgramId = if pre.account.program_owner == DEFAULT_PROGRAM_OWNER {
                    chained_call.program_id
                } else {
                    pre.account.program_owner.into()
                };
                let owner_program = if owner_id == program.id() {
                    program
                } else {
                    dependencies.get(&owner_id).ok_or(
                        InvalidProgramBehaviorError::UndeclaredProgramDependency {
                            program_id: owner_id,
                        },
                    )?
                };
                let update_receipt =
                    owner_program.prove_update_from_diff(&pre.account, diff_data)?;
                let update_output: UpdateFromDiffOutput = update_receipt
                    .journal
                    .decode()
                    .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;
                update_from_diff_results.push(update_output.data.clone());
                env_builder.add_assumption(update_receipt);
                update_output.data
            } else {
                pre.account.data.clone()
            };

            let program_owner = if diff_output.required_claim().is_some() {
                AccountId::from(chained_call.program_id)
            } else {
                pre.account.program_owner
            };

            materialized_state.insert(
                pre.account_id,
                Account {
                    program_owner,
                    balance,
                    data,
                    nonce: pre.account.nonce,
                },
            );

            // Authorization propagates forward: once an account is authorized at any point in
            // the chain, it stays authorized for later calls — mirrors the union in the
            // public-transaction path and the circuit's own `authorized_accounts` set.
            if pre.is_authorized {
                host_authorized_accounts.insert(pre.account_id);
            }
        }

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
        dummy_inputs,
        update_from_diff_results,
        signer_account_ids,
    };

    env_builder.write(&circuit_input).unwrap();
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &opts)
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);

    let circuit_output: PrivacyPreservingCircuitOutput = prove_info
        .receipt
        .journal
        .decode()
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
        .map_err(|e| LeeError::ProgramProveFailed(e.to_string()))?
        .receipt)
}

#[cfg(test)]
mod tests;
