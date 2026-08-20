use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};

/// PDA authorization program that delegates balance operations to `simple_transfer`.
///
/// The PDA is owned by `simple_transfer`, not by this program. This program's role
/// is solely to provide PDA authorization via `pda_seeds` in chained calls.
///
/// Instruction: `(pda_seed, simple_transfer_id, amount, is_withdraw)`.
///
/// **Init** (`is_withdraw = false`, 1 pre-state `[pda]`):
/// Chains to `simple_transfer` with `instruction=0` (init path) and `pda_seeds=[seed]`
/// to initialize the PDA under `simple_transfer`'s ownership.
///
/// **Withdraw** (`is_withdraw = true`, 2 pre-states `[pda, recipient]`):
/// Chains to `simple_transfer` with the amount and `pda_seeds=[seed]` to authorize
/// the PDA for a balance transfer. The actual balance modification happens in
/// `simple_transfer`, not here.
///
/// **Deposit**: done directly via `simple_transfer` (no need for this program).
type Instruction = (PdaSeed, ProgramId, u128, bool);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (pda_seed, simple_transfer_id, amount, is_withdraw),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "simple_transfer_proxy program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    if is_withdraw {
        let Ok([pda_pre, recipient_pre]) = <[_; 2]>::try_from(pre_states.clone()) else {
            panic!("expected exactly 2 pre_states for withdraw: [pda, recipient]");
        };

        // Post-states stay unchanged in this program. The actual balance transfer
        // happens in the chained call to simple_transfer.
        let pda_post = AccountDiffOutput::new(AccountDiff {
            id: pda_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        });
        let recipient_post = AccountDiffOutput::new(AccountDiff {
            id: recipient_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        });

        // Chain to simple_transfer with pda_seeds to authorize the PDA.
        // The circuit's assert_authorization_and_record_bindings establishes the
        // private PDA (seed, npk) binding when pda_seeds match the private PDA derivation.
        let auth_call = ChainedCall::new(
            simple_transfer_id,
            vec![pda_pre.account_id, recipient_pre.account_id],
            &amount,
        )
        .with_pda_seeds(vec![pda_seed]);

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![pda_post, recipient_post],
        )
        .with_chained_calls(vec![auth_call])
        .write();
    } else {
        // Init: initialize the PDA under simple_transfer's ownership.
        let Ok([pda_pre]) = <[_; 1]>::try_from(pre_states.clone()) else {
            panic!("expected exactly 1 pre_state for init: [pda]");
        };

        let pda_post = AccountDiffOutput::new(AccountDiff {
            id: pda_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        });

        // Chain to simple_transfer with instruction=0 (init path) and pda_seeds
        // to authorize the PDA. simple_transfer will claim it with Claim::Authorized.
        let auth_call = ChainedCall::new(simple_transfer_id, vec![pda_pre.account_id], &amount)
            .with_pda_seeds(vec![pda_seed]);

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![pda_post],
        )
        .with_chained_calls(vec![auth_call])
        .write();
    }
}
