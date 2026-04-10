use std::collections::{HashMap, VecDeque};

use log::debug;
use nssa_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{ChainedCall, ProgramId, ProgramOutput},
};

use crate::{PublicTransaction, V03State, error::NssaError};

pub trait Validator {
    fn validate_pre_execution(&mut self) -> Result<(), NssaError>;

    fn on_chained_call(&mut self) -> Result<(), NssaError>;

    fn validate_output(
        &mut self,
        state_diff: &HashMap<AccountId, Account>,
        caller_program_id: Option<ProgramId>,
        chained_call: &ChainedCall,
        program_output: &ProgramOutput,
    ) -> Result<(), NssaError>;

    fn validate_post_execution(
        &mut self,
        state_diff: &HashMap<AccountId, Account>,
    ) -> Result<(), NssaError>;
}

pub fn execute(
    mut validator: impl Validator,
    tx: &PublicTransaction,
    state: &V03State,
) -> Result<HashMap<AccountId, Account>, NssaError> {
    validator.validate_pre_execution()?;

    let message = tx.message();
    let signer_account_ids = tx.signer_account_ids();

    // Build pre_states for execution
    let input_pre_states: Vec<_> = message
        .account_ids
        .iter()
        .map(|account_id| {
            AccountWithMetadata::new(
                state.get_account_by_id(*account_id),
                signer_account_ids.contains(account_id),
                *account_id,
            )
        })
        .collect();

    let mut state_diff: HashMap<AccountId, Account> = HashMap::new();

    let initial_call = ChainedCall {
        program_id: message.program_id,
        instruction_data: message.instruction_data.clone(),
        pre_states: input_pre_states,
        pda_seeds: vec![],
    };

    let mut chained_calls = VecDeque::from_iter([(initial_call, None)]);

    while let Some((chained_call, caller_program_id)) = chained_calls.pop_front() {
        validator.on_chained_call()?;

        // Check that the `program_id` corresponds to a deployed program
        let Some(program) = state.programs().get(&chained_call.program_id) else {
            return Err(NssaError::InvalidInput("Unknown program".into()));
        };

        debug!(
            "Program {:?} pre_states: {:?}, instruction_data: {:?}",
            chained_call.program_id, chained_call.pre_states, chained_call.instruction_data
        );
        let mut program_output = program.execute(
            caller_program_id,
            &chained_call.pre_states,
            &chained_call.instruction_data,
        )?;
        debug!(
            "Program {:?} output: {:?}",
            chained_call.program_id, program_output
        );

        validator.validate_output(
            &state_diff,
            caller_program_id,
            &chained_call,
            &program_output,
        )?;

        for post in program_output
            .post_states
            .iter_mut()
            .filter(|post| post.required_claim().is_some())
        {
            post.account_mut().program_owner = chained_call.program_id;
        }

        // Update the state diff
        for (pre, post) in program_output
            .pre_states
            .iter()
            .zip(program_output.post_states.iter())
        {
            state_diff.insert(pre.account_id, post.account().clone());
        }

        for new_call in program_output.chained_calls.into_iter().rev() {
            chained_calls.push_front((new_call, Some(chained_call.program_id)));
        }
    }

    validator.validate_post_execution(&state_diff)?;

    Ok(state_diff)
}
