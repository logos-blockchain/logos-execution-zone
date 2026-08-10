use authenticated_transfer_core::Instruction as TransferInstruction;
use cacp_bond_core::{
    BondState, Instruction, MantleSignature, Phase, Settlement, escrow_account_id, escrow_seed,
    proof_commitment, state_account_id, state_seed,
};
use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "CACP bond is only invoked by top-level public transactions"
    );
    let [initiator, counterparty, escrow, state_meta, clock] =
        <[AccountWithMetadata; 5]>::try_from(pre_states)
            .expect("CACP bond instructions require five accounts");
    let current_block = read_clock(&clock);

    let (state, transfers, claim_state) = match instruction {
        Instruction::Open {
            proposal_id,
            counterparty: declared_counterparty,
            initiator_mantle_key,
            counterparty_mantle_key,
            stake_amount,
            challenge_bond,
            response_window_blocks,
        } => {
            assert!(initiator.is_authorized, "initiator must authorize Open");
            assert_eq!(
                counterparty.account_id, declared_counterparty,
                "counterparty account does not match the instruction"
            );
            assert!(stake_amount > 0, "stake must be non-zero");
            assert!(challenge_bond > 0, "challenge bond must be non-zero");
            assert!(
                response_window_blocks > 0,
                "response window must be non-zero"
            );
            assert!(
                state_meta.account.data.is_empty(),
                "proposal already exists"
            );
            assert!(
                state_meta.account.balance == 0,
                "state PDA cannot hold funds"
            );
            assert_eq!(
                state_meta.account_id,
                state_account_id(self_program_id, &proposal_id),
                "wrong proposal state PDA"
            );
            assert_eq!(
                escrow.account_id,
                escrow_account_id(self_program_id, &proposal_id),
                "wrong proposal escrow PDA"
            );
            let state = BondState {
                proposal_id,
                initiator: initiator.account_id,
                counterparty: counterparty.account_id,
                initiator_mantle_key,
                counterparty_mantle_key,
                stake_amount,
                challenge_bond,
                response_window_blocks,
                expires_at_block: deadline(current_block, response_window_blocks),
                tx_hash: None,
                accept_commitment: None,
                phase: Phase::AwaitingCounterparty,
                settlement: None,
            };
            let transfer = deposit_call(&initiator, &escrow, stake_amount, proposal_id);
            (state, vec![transfer], true)
        }
        other => {
            let mut state = load_state(self_program_id, &state_meta, &escrow)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_instruction_proposal(&other, state.proposal_id);
            let transfers = apply_instruction(
                &mut state,
                &initiator,
                &counterparty,
                &escrow,
                current_block,
                other,
            );
            (state, transfers, false)
        }
    };

    let mut state_account = state_meta.account.clone();
    state_account.data = state
        .to_bytes()
        .try_into()
        .expect("CACP bond state fits in account data");
    let state_post = if claim_state {
        AccountPostState::new_claimed_if_default(
            state_account,
            Claim::Pda(state_seed(&state.proposal_id)),
        )
    } else {
        AccountPostState::new(state_account)
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![
            initiator.clone(),
            counterparty.clone(),
            escrow.clone(),
            state_meta,
            clock.clone(),
        ],
        vec![
            AccountPostState::new(initiator.account),
            AccountPostState::new(counterparty.account),
            AccountPostState::new(escrow.account),
            state_post,
            AccountPostState::new(clock.account),
        ],
    )
    .with_chained_calls(transfers)
    .write();
}

fn apply_instruction(
    state: &mut BondState,
    initiator: &AccountWithMetadata,
    counterparty: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
    current_block: u64,
    instruction: Instruction,
) -> Vec<ChainedCall> {
    ensure_accounts(state, initiator, counterparty);
    match instruction {
        Instruction::Join {
            tx_hash,
            accept_commitment,
            ..
        } => {
            assert!(
                counterparty.is_authorized,
                "counterparty must authorize Join"
            );
            assert_eq!(state.phase, Phase::AwaitingCounterparty);
            assert_window_open(state, current_block);
            state.tx_hash = Some(tx_hash);
            state.accept_commitment = Some(accept_commitment);
            state.phase = Phase::AwaitingAccept;
            restart_window(state, current_block);
            vec![deposit_call(
                counterparty,
                escrow,
                state.stake_amount,
                state.proposal_id,
            )]
        }
        Instruction::ChallengeAccept { .. } => {
            assert!(
                initiator.is_authorized,
                "initiator must authorize challenge"
            );
            assert_eq!(state.phase, Phase::AwaitingAccept);
            assert_window_elapsed(state, current_block);
            state.phase = Phase::AcceptChallenged;
            restart_window(state, current_block);
            vec![deposit_call(
                initiator,
                escrow,
                state.challenge_bond,
                state.proposal_id,
            )]
        }
        Instruction::DiscloseAccept { proof, .. } => {
            assert!(
                counterparty.is_authorized,
                "counterparty must authorize ACCEPT disclosure"
            );
            assert!(
                matches!(state.phase, Phase::AwaitingAccept | Phase::AcceptChallenged),
                "ACCEPT is not currently owed"
            );
            assert_window_open(state, current_block);
            verify_counterparty_proof(state, &proof);
            let challenged = state.phase == Phase::AcceptChallenged;
            state.phase = Phase::AwaitingFinalize;
            restart_window(state, current_block);
            if challenged {
                vec![payout_call(
                    escrow,
                    counterparty,
                    state.challenge_bond,
                    state.proposal_id,
                )]
            } else {
                Vec::new()
            }
        }
        Instruction::ChallengeFinalize { .. } => {
            assert!(
                counterparty.is_authorized,
                "counterparty must authorize FINALIZE challenge"
            );
            assert_eq!(state.phase, Phase::AwaitingFinalize);
            assert_window_elapsed(state, current_block);
            state.phase = Phase::FinalizeChallenged;
            restart_window(state, current_block);
            vec![deposit_call(
                counterparty,
                escrow,
                state.challenge_bond,
                state.proposal_id,
            )]
        }
        Instruction::DiscloseFinalize { proof, .. } => {
            assert!(
                initiator.is_authorized,
                "initiator must authorize FINALIZE disclosure"
            );
            assert!(
                matches!(
                    state.phase,
                    Phase::AwaitingFinalize | Phase::FinalizeChallenged
                ),
                "FINALIZE is not currently owed"
            );
            assert_window_open(state, current_block);
            verify_initiator_proof(state, &proof);
            let challenged = state.phase == Phase::FinalizeChallenged;
            settle_completed(state);
            completed_payouts(
                state,
                initiator,
                counterparty,
                escrow,
                challenged.then_some(true),
            )
        }
        Instruction::Complete {
            initiator_proof,
            counterparty_proof,
            ..
        } => {
            assert!(
                initiator.is_authorized || counterparty.is_authorized,
                "a participant must authorize completion"
            );
            assert!(state.phase != Phase::Settled, "proposal is already settled");
            verify_counterparty_proof(state, &counterparty_proof);
            verify_initiator_proof(state, &initiator_proof);
            let challenged = match state.phase {
                Phase::AcceptChallenged => Some(false),
                Phase::FinalizeChallenged => Some(true),
                _ => None,
            };
            settle_completed(state);
            completed_payouts(state, initiator, counterparty, escrow, challenged)
        }
        Instruction::SettleTimeout { .. } => match state.phase {
            Phase::AwaitingCounterparty => {
                assert!(initiator.is_authorized, "initiator must authorize refund");
                assert_window_elapsed(state, current_block);
                state.phase = Phase::Settled;
                state.settlement = Some(Settlement::CounterpartyDidNotEngage);
                vec![payout_call(
                    escrow,
                    initiator,
                    state.stake_amount,
                    state.proposal_id,
                )]
            }
            Phase::AcceptChallenged => {
                assert!(
                    initiator.is_authorized,
                    "initiator must authorize forfeiture"
                );
                assert_window_elapsed(state, current_block);
                state.phase = Phase::Settled;
                state.settlement = Some(Settlement::CounterpartyForfeited);
                vec![payout_call(
                    escrow,
                    initiator,
                    two_stakes_plus_bond(state),
                    state.proposal_id,
                )]
            }
            Phase::FinalizeChallenged => {
                assert!(
                    counterparty.is_authorized,
                    "counterparty must authorize forfeiture"
                );
                assert_window_elapsed(state, current_block);
                state.phase = Phase::Settled;
                state.settlement = Some(Settlement::InitiatorForfeited);
                vec![payout_call(
                    escrow,
                    counterparty,
                    two_stakes_plus_bond(state),
                    state.proposal_id,
                )]
            }
            _ => panic!("the current phase has no timeout settlement"),
        },
        Instruction::Open { .. } => unreachable!("Open is handled before state loading"),
    }
}

fn completed_payouts(
    state: &BondState,
    initiator: &AccountWithMetadata,
    counterparty: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
    challenged: Option<bool>,
) -> Vec<ChainedCall> {
    let initiator_amount = state
        .stake_amount
        .checked_add(if challenged == Some(true) {
            state.challenge_bond
        } else {
            0
        })
        .expect("initiator payout overflow");
    let counterparty_amount = state
        .stake_amount
        .checked_add(if challenged == Some(false) {
            state.challenge_bond
        } else {
            0
        })
        .expect("counterparty payout overflow");
    vec![
        payout_call(escrow, initiator, initiator_amount, state.proposal_id),
        payout_call(escrow, counterparty, counterparty_amount, state.proposal_id),
    ]
}

fn deposit_call(
    sender: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
    amount: u128,
    proposal_id: [u8; 32],
) -> ChainedCall {
    assert!(sender.is_authorized, "stake sender must be authorized");
    let mut escrow_for_transfer = escrow.clone();
    escrow_for_transfer.is_authorized = true;
    ChainedCall::new(
        sender.account.program_owner,
        vec![sender.clone(), escrow_for_transfer],
        &TransferInstruction::Transfer { amount },
    )
    .with_pda_seeds(vec![escrow_seed(&proposal_id)])
}

fn payout_call(
    escrow: &AccountWithMetadata,
    recipient: &AccountWithMetadata,
    amount: u128,
    proposal_id: [u8; 32],
) -> ChainedCall {
    let mut escrow_for_transfer = escrow.clone();
    escrow_for_transfer.is_authorized = true;
    ChainedCall::new(
        escrow.account.program_owner,
        vec![escrow_for_transfer, recipient.clone()],
        &TransferInstruction::Transfer { amount },
    )
    .with_pda_seeds(vec![escrow_seed(&proposal_id)])
}

fn load_state(
    program_id: [u32; 8],
    state_meta: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
) -> Result<BondState, &'static str> {
    let state =
        BondState::from_bytes(&state_meta.account.data).map_err(|_| "invalid bond state")?;
    assert_eq!(
        state_meta.account_id,
        state_account_id(program_id, &state.proposal_id),
        "wrong proposal state PDA"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(program_id, &state.proposal_id),
        "wrong proposal escrow PDA"
    );
    Ok(state)
}

fn ensure_accounts(
    state: &BondState,
    initiator: &AccountWithMetadata,
    counterparty: &AccountWithMetadata,
) {
    assert_eq!(
        initiator.account_id, state.initiator,
        "wrong initiator account"
    );
    assert_eq!(
        counterparty.account_id, state.counterparty,
        "wrong counterparty account"
    );
}

fn assert_instruction_proposal(instruction: &Instruction, expected: [u8; 32]) {
    let actual = match instruction {
        Instruction::Open { proposal_id, .. }
        | Instruction::Join { proposal_id, .. }
        | Instruction::ChallengeAccept { proposal_id }
        | Instruction::DiscloseAccept { proposal_id, .. }
        | Instruction::ChallengeFinalize { proposal_id }
        | Instruction::DiscloseFinalize { proposal_id, .. }
        | Instruction::Complete { proposal_id, .. }
        | Instruction::SettleTimeout { proposal_id } => proposal_id,
    };
    assert_eq!(*actual, expected, "instruction targets the wrong proposal");
}

fn read_clock(clock: &AccountWithMetadata) -> u64 {
    assert_eq!(
        clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID,
        "fifth account must be the one-block clock"
    );
    ClockAccountData::from_bytes(&clock.account.data).block_id
}

fn restart_window(state: &mut BondState, current_block: u64) {
    state.expires_at_block = deadline(current_block, state.response_window_blocks);
}

fn deadline(current_block: u64, window: u64) -> u64 {
    current_block
        .checked_add(window)
        .expect("response-window deadline overflow")
}

fn assert_window_open(state: &BondState, current_block: u64) {
    assert!(
        current_block < state.expires_at_block,
        "response window has elapsed"
    );
}

fn assert_window_elapsed(state: &BondState, current_block: u64) {
    assert!(
        current_block >= state.expires_at_block,
        "response window is still open"
    );
}

fn verify_counterparty_proof(state: &BondState, proof: &MantleSignature) {
    assert_eq!(
        state.accept_commitment,
        Some(proof_commitment(proof)),
        "ACCEPT disclosure does not open the registered commitment"
    );
    verify_proof(state.counterparty_mantle_key, state.tx_hash, proof);
}

fn verify_initiator_proof(state: &BondState, proof: &MantleSignature) {
    verify_proof(state.initiator_mantle_key, state.tx_hash, proof);
}

fn verify_proof(public_key: [u8; 32], tx_hash: Option<[u8; 32]>, proof: &MantleSignature) {
    let key = VerifyingKey::from_bytes(&public_key).expect("registered Mantle key is valid");
    let signature = Signature::from_slice(proof.as_bytes()).expect("signature must be 64 bytes");
    key.verify(
        &tx_hash.expect("counterparty must register the Mantle transaction hash"),
        &signature,
    )
    .expect("disclosed signature must verify against the registered transaction");
}

fn settle_completed(state: &mut BondState) {
    state.phase = Phase::Settled;
    state.settlement = Some(Settlement::Completed);
}

fn two_stakes_plus_bond(state: &BondState) -> u128 {
    state
        .stake_amount
        .checked_mul(2)
        .and_then(|amount| amount.checked_add(state.challenge_bond))
        .expect("forfeiture payout overflow")
}
