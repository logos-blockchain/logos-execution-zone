use lee_core::{
    account::AccountId,
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

// Mirrors `stripped_token`'s `TokenAccountData`/`Instruction` layout — guest binaries can't
// import each other's types.
#[derive(borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    #[expect(
        dead_code,
        reason = "mirrors stripped_token's own Instruction shape exactly"
    )]
    Initialize {
        balance: u128,
    },
    Transfer {
        amount: u128,
    },
}

/// The `AccountId` of the `stripped_token` instance whose accounts this reads and compares.
type Instruction = AccountId;

fn token_balance(data: &lee_core::account::Data) -> u128 {
    if data.is_empty() {
        0
    } else {
        borsh::from_slice::<TokenAccountData>(data)
            .expect("account data must decode as TokenAccountData")
            .balance
    }
}

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: stripped_token_account_id,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([account1_pre, account2_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let balance1 = token_balance(&account1_pre.account.data);
    let balance2 = token_balance(&account2_pre.account.data);

    let transfer_instruction_data =
        borsh::to_vec(&StrippedTokenInstruction::Transfer { amount: 1 }).unwrap();
    let chained_calls = match balance1.cmp(&balance2) {
        std::cmp::Ordering::Greater => vec![ChainedCall {
            program_account_id: stripped_token_account_id,
            instruction_data: transfer_instruction_data,
            pre_state_ids: vec![account1_pre.account_id, account2_pre.account_id],
            pda_seeds: vec![],
        }],
        std::cmp::Ordering::Less => vec![ChainedCall {
            program_account_id: stripped_token_account_id,
            instruction_data: transfer_instruction_data,
            pre_state_ids: vec![account2_pre.account_id, account1_pre.account_id],
            pda_seeds: vec![],
        }],
        std::cmp::Ordering::Equal => vec![],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::unchanged(account1_pre),
            AccountStateDiff::unchanged(account2_pre),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
