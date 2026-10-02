//! Flash swap initiator, demonstrates the "read → lend → callback → read" pattern using ordered
//! sends and native balance reads.
//!
//! # Pattern
//!
//! A flash swap lets a program optimistically transfer tokens out, run arbitrary user
//! logic (the callback), then assert that invariants hold after the callback. The entire
//! sequence is a single atomic transaction: if any step fails, all state changes roll back.
//!
//! # How it works
//!
//! - `Initiate` (external): records the loan and reads the vault balance.
//! - The first reply checks the vault holds the proposed balance, then sends, in order:
//!   1. A custody transfer out of the vault to the receiver
//!   2. The user callback (arbitrary logic, e.g. arbitrage)
//!   3. A second read of the vault balance
//! - The second reply requires the vault balance to be back at its value before the swap.
//!
//! Pending swaps form a stack, so a callback may start another swap: depth-first execution
//! answers the inner swap's reads before the outer swap's second read.
//!
//! If the callback does not return funds, the second check fails and the whole transaction rolls
//! back.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID, custody_transfer, decode_balance},
    program::{Call, PdaSeed, ReadState, ReceiveInput, Response, StateReply, run_actor_with},
};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Loan {
    vault: AccountId,
    receiver: AccountId,
    callback: Actor,
    amount_out: u128,
    vault_balance: u128,
    callback_message: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum FlashSwapMessage {
    Initiate(Loan),
}

#[derive(BorshSerialize, BorshDeserialize)]
enum Phase {
    Lending(Loan),
    Repaying {
        vault: AccountId,
        vault_balance: u128,
    },
}

impl Phase {
    const fn expected(&self) -> (AccountId, u128) {
        match self {
            Self::Lending(Loan {
                vault,
                vault_balance,
                ..
            })
            | Self::Repaying {
                vault,
                vault_balance,
            } => (*vault, *vault_balance),
        }
    }
}

fn read_vault(vault: AccountId, reply_to: Actor) -> Call {
    Call::new(
        Actor::native_balance(vault),
        &native_token::Message::ReadState(ReadState { reply_to }),
    )
}

fn pending(input: &ReceiveInput) -> Vec<Phase> {
    if input.pre_state.is_empty() {
        Vec::new()
    } else {
        borsh::from_slice(&input.pre_state).expect("the initiator holds its pending swaps")
    }
}

fn keep(pending: &[Phase]) -> Response {
    Response::write(if pending.is_empty() {
        Vec::new()
    } else {
        borsh::to_vec(pending).expect("pending swaps encode")
    })
}

fn answer(input: &ReceiveInput, mut pending: Vec<Phase>, reply: &StateReply) -> Response {
    let phase = pending.pop().expect("a reply must answer a pending read");
    let (vault, vault_balance) = phase.expected();
    assert_eq!(
        reply.subject,
        Actor::native_balance(vault),
        "the reply must read the vault"
    );
    let balance = decode_balance(&reply.state).expect("the vault holds a canonical balance");
    match phase {
        Phase::Lending(Loan {
            receiver,
            callback,
            amount_out,
            callback_message,
            ..
        }) => {
            assert_eq!(
                balance, vault_balance,
                "the vault must hold the proposed balance"
            );
            pending.push(Phase::Repaying {
                vault,
                vault_balance,
            });
            keep(&pending)
                .send(custody_transfer(
                    vault,
                    PdaSeed::new([0; 32]),
                    receiver,
                    amount_out,
                ))
                .send(Call {
                    to: callback,
                    message: callback_message,
                    pda_seeds: Vec::new(),
                })
                .send(read_vault(vault, input.receiver))
        }
        Phase::Repaying { .. } => {
            assert_eq!(
                balance, vault_balance,
                "the vault must end where it started"
            );
            keep(&pending)
        }
    }
}

fn main() {
    run_actor_with(|input| {
        let mut pending = pending(input);
        if input.origin == Some(NATIVE_TOKEN_PROGRAM_ID) {
            let native_token::Message::StateReply(reply) =
                borsh::from_slice(&input.message).expect("a native message must decode")
            else {
                panic!("the native program sends the initiator only state replies");
            };
            return answer(input, pending, &reply);
        }
        let FlashSwapMessage::Initiate(loan) =
            borsh::from_slice(&input.message).expect("a flash swap message must decode");
        let read = read_vault(loan.vault, input.receiver);
        pending.push(Phase::Lending(loan));
        keep(&pending).send(read)
    })
}
