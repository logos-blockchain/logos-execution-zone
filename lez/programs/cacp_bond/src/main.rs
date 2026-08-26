// Submission provenance and full references
//
// This source accompanies:
// Q. Jiang, “Costly Escalation in Cross-Zone Atomic Coordination: A Neutral-Zone Fee
// and Stake Mechanism for CACP,” MSc Emerging Digital Technologies dissertation,
// Department of Computer Science, University College London, 2026.
//
// The project specifications, platform specifications, and design literature are:
// [1] T. Lavaur, “[1.1.1] Cross-Channel Messaging,” The Logos Blockchain Project,
// specification version 1.1.1, 6 May 2026. [Online]. Available:
// https://nomos-tech.notion.site/1-1-1-Template-Cross-Channel-Messaging-33e261aa09df80b2a6aaca0e7cfd2ce7.
// [Accessed: 24 Aug. 2026].
// [3] T. Lavaur, “[1.5.0] Mantle,” The Logos Blockchain Project, specification version
// 1.5.0, 6 May 2026. [Online]. Available:
// https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85.
// [Accessed: 24 Aug. 2026].
// [4] Logos Blockchain Project, “LEE v0.3 Specifications,” Logos Improvement Proposal
// 237, Standards Track, raw status, 8 June 2026. [Online]. Available:
// https://lip.logos.co/blockchain/raw/lez/lee-v0.3-specifications.html.
// [Accessed: 24 Aug. 2026].
// [14] N. Asokan, M. Schunter, and M. Waidner, “Optimistic Protocols for Fair
// Exchange,” in Proc. 4th ACM Conference on Computer and Communications Security,
// pp. 7–17, 1997, doi: 10.1145/266420.266426.
// [15] N. Asokan, V. Shoup, and M. Waidner, “Optimistic Fair Exchange of Digital
// Signatures,” in Advances in Cryptology—EUROCRYPT 1998, pp. 591–606, 1998,
// doi: 10.1007/BFb0054156.
// [16] S. Dziembowski, L. Eckey, and S. Faust, “FairSwap: How to Fairly Exchange
// Digital Goods,” in Proc. 2018 ACM SIGSAC Conference on Computer and Communications
// Security, pp. 967–984, 2018, doi: 10.1145/3243734.3243857.
// [18] I. Bentov and R. Kumaresan, “How to Use Bitcoin to Design Fair Protocols,” in
// Advances in Cryptology—CRYPTO 2014, pp. 421–439, 2014,
// doi: 10.1007/978-3-662-44381-1_24.
// [23] Q. Jiang, “Specification for CACP: Cross-Zone Atomic Coordination Protocol,”
// University College London, project specification, 2026.
// [24] Q. Jiang, “LEZ CACP Costly Escalation Bond Protocol,” University College
// London, project specification, 2026.

use authenticated_transfer_core::Instruction as TransferInstruction;
use cacp_bond_core::{
    AgreementId, BondState, Instruction, MantleSignature, Phase, Settlement, TimeoutPayout,
    burn_account_id, burn_seed, can_challenge_accept, can_challenge_finalize, can_complete,
    can_disclose_accept, can_disclose_finalize, escrow_account_id, escrow_seed, state_account_id,
    state_seed, timeout_resolution,
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
    match instruction {
        Instruction::Open { agreement } => {
            let [
                initiator,
                counterparty,
                escrow,
                state_meta,
                clock,
                burn_sink,
            ] = <[AccountWithMetadata; 6]>::try_from(pre_states)
                .expect("Open requires six accounts");
            let current_block = read_clock(&clock);
            assert!(initiator.is_authorized, "initiator must authorize Open");
            assert!(agreement.is_valid(), "bond agreement is invalid");
            assert_eq!(
                initiator.account_id, agreement.initiator,
                "initiator account does not match the agreement"
            );
            assert_eq!(
                counterparty.account_id, agreement.counterparty,
                "counterparty account does not match the agreement"
            );
            assert!(
                state_meta.account.data.is_empty(),
                "proposal already exists"
            );
            assert!(
                state_meta.account.balance == 0,
                "state PDA cannot hold funds"
            );
            let agreement_id = agreement.id(self_program_id);
            assert_eq!(
                state_meta.account_id,
                state_account_id(self_program_id, &agreement_id),
                "wrong agreement state PDA"
            );
            assert_eq!(
                escrow.account_id,
                escrow_account_id(self_program_id, &agreement_id),
                "wrong agreement escrow PDA"
            );
            assert_eq!(
                burn_sink.account_id,
                burn_account_id(self_program_id),
                "wrong protocol-fixed burn account"
            );
            let state = BondState {
                agreement_id,
                expires_at_block: deadline(current_block, agreement.response_window_blocks),
                agreement,
                initiator_fees_burned: 0,
                counterparty_fees_burned: 0,
                phase: Phase::AwaitingCounterparty,
                settlement: None,
            };
            let participant_deposit = state
                .agreement
                .participant_deposit()
                .expect("validated agreement deposit does not overflow");
            let transfer =
                deposit_call(&initiator, &escrow, participant_deposit, state.agreement_id);
            let mut state_account = state_meta.account.clone();
            state_account.data = state
                .to_bytes()
                .try_into()
                .expect("CACP bond state fits in account data");
            let state_post = AccountPostState::new_claimed_if_default(
                state_account,
                Claim::Pda(state_seed(&state.agreement_id)),
            );
            let burn_post = AccountPostState::new_claimed_if_default(
                burn_sink.account.clone(),
                Claim::Pda(burn_seed()),
            );
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
                    burn_sink,
                ],
                vec![
                    AccountPostState::new(initiator.account),
                    AccountPostState::new(counterparty.account),
                    AccountPostState::new(escrow.account),
                    state_post,
                    AccountPostState::new(clock.account),
                    burn_post,
                ],
            )
            .with_chained_calls(vec![transfer])
            .write();
        }
        other => {
            let [
                initiator,
                counterparty,
                escrow,
                state_meta,
                clock,
                burn_sink,
            ] = <[AccountWithMetadata; 6]>::try_from(pre_states)
                .expect("non-Open CACP bond instructions require six accounts");
            let current_block = read_clock(&clock);
            let mut state = load_state(self_program_id, &state_meta, &escrow)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_instruction_agreement(&other, state.agreement_id);
            let transfers = apply_instruction(
                self_program_id,
                &mut state,
                &initiator,
                &counterparty,
                &escrow,
                &burn_sink,
                current_block,
                other,
            );
            let mut state_account = state_meta.account.clone();
            state_account.data = state
                .to_bytes()
                .try_into()
                .expect("CACP bond state fits in account data");
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
                    burn_sink.clone(),
                ],
                vec![
                    AccountPostState::new(initiator.account),
                    AccountPostState::new(counterparty.account),
                    AccountPostState::new(escrow.account),
                    AccountPostState::new(state_account),
                    AccountPostState::new(clock.account),
                    AccountPostState::new(burn_sink.account),
                ],
            )
            .with_chained_calls(transfers)
            .write();
        }
    }
}

fn apply_instruction(
    program_id: [u32; 8],
    state: &mut BondState,
    initiator: &AccountWithMetadata,
    counterparty: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
    burn_sink: &AccountWithMetadata,
    current_block: u64,
    instruction: Instruction,
) -> Vec<ChainedCall> {
    ensure_accounts(program_id, state, initiator, counterparty, burn_sink);
    match instruction {
        Instruction::Join { .. } => {
            assert!(
                counterparty.is_authorized,
                "counterparty must authorize Join"
            );
            assert_eq!(state.phase, Phase::AwaitingCounterparty);
            assert_window_open(state, current_block);
            state.phase = Phase::AwaitingAccept;
            restart_window(state, current_block);
            vec![deposit_call(
                counterparty,
                escrow,
                state
                    .agreement
                    .participant_deposit()
                    .expect("validated agreement deposit does not overflow"),
                state.agreement_id,
            )]
        }
        Instruction::ChallengeAccept { .. } => {
            assert!(
                initiator.is_authorized,
                "initiator must authorize challenge"
            );
            assert!(can_challenge_accept(state.phase));
            assert_window_open(state, current_block);
            state.phase = Phase::AcceptChallenged;
            restart_window(state, current_block);
            let fee = state.agreement.challenge_fee;
            record_fee_burn(state, true, fee);
            escrow_transfers(escrow, state.agreement_id, vec![(burn_sink, fee)])
        }
        Instruction::DiscloseAccept { proof, .. } => {
            assert!(
                counterparty.is_authorized,
                "counterparty must authorize ACCEPT disclosure"
            );
            assert!(can_disclose_accept(state.phase));
            assert_window_open(state, current_block);
            verify_counterparty_proof(state, &proof);
            state.phase = Phase::AwaitingFinalize;
            restart_window(state, current_block);
            let fee = state.agreement.response_fee;
            record_fee_burn(state, false, fee);
            escrow_transfers(escrow, state.agreement_id, vec![(burn_sink, fee)])
        }
        Instruction::ChallengeFinalize { accept_proof, .. } => {
            assert!(
                counterparty.is_authorized,
                "counterparty must authorize FINALIZE challenge"
            );
            assert!(can_challenge_finalize(state.phase));
            assert_window_open(state, current_block);
            // B gives A the exact missing Mantle proof before asking the neutral
            // zone to force A's matching proof.
            verify_counterparty_proof(state, &accept_proof);
            state.phase = Phase::FinalizeChallenged;
            restart_window(state, current_block);
            let fee = state.agreement.challenge_fee;
            record_fee_burn(state, false, fee);
            escrow_transfers(escrow, state.agreement_id, vec![(burn_sink, fee)])
        }
        Instruction::DiscloseFinalize { proof, .. } => {
            assert!(
                initiator.is_authorized,
                "initiator must authorize FINALIZE disclosure"
            );
            assert!(can_disclose_finalize(state.phase));
            assert_window_open(state, current_block);
            verify_initiator_proof(state, &proof);
            let fee = state.agreement.response_fee;
            record_fee_burn(state, true, fee);
            settle_completed(state);
            let [initiator_refund, counterparty_refund] = completed_payouts(state);
            escrow_transfers(
                escrow,
                state.agreement_id,
                vec![
                    (burn_sink, fee),
                    (initiator, initiator_refund),
                    (counterparty, counterparty_refund),
                ],
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
            assert!(
                can_complete(state.phase),
                "agreement is not ready for completion"
            );
            verify_counterparty_proof(state, &counterparty_proof);
            verify_initiator_proof(state, &initiator_proof);
            settle_completed(state);
            let [initiator_refund, counterparty_refund] = completed_payouts(state);
            escrow_transfers(
                escrow,
                state.agreement_id,
                vec![
                    (initiator, initiator_refund),
                    (counterparty, counterparty_refund),
                ],
            )
        }
        Instruction::SettleTimeout { .. } => {
            let resolution = timeout_resolution(state.phase)
                .expect("the current phase has no timeout settlement");
            assert_window_elapsed(state, current_block);
            let payouts = match resolution.payout {
                TimeoutPayout::RefundInitiatorStake => {
                    assert!(initiator.is_authorized, "initiator must authorize refund");
                    escrow_transfers(
                        escrow,
                        state.agreement_id,
                        vec![(
                            initiator,
                            state
                                .participant_refund(true)
                                .expect("initiator refund is valid"),
                        )],
                    )
                }
                TimeoutPayout::RefundBothStakes => {
                    assert!(
                        initiator.is_authorized || counterparty.is_authorized,
                        "a participant must authorize refund"
                    );
                    let [initiator_refund, counterparty_refund] = completed_payouts(state);
                    escrow_transfers(
                        escrow,
                        state.agreement_id,
                        vec![
                            (initiator, initiator_refund),
                            (counterparty, counterparty_refund),
                        ],
                    )
                }
                TimeoutPayout::AwardEscrowToInitiator => {
                    assert!(
                        initiator.is_authorized,
                        "initiator must authorize forfeiture"
                    );
                    let [initiator_payout, counterparty_refund] = forfeiture_payouts(state, false);
                    escrow_transfers(
                        escrow,
                        state.agreement_id,
                        vec![
                            (initiator, initiator_payout),
                            (counterparty, counterparty_refund),
                        ],
                    )
                }
                TimeoutPayout::AwardEscrowToCounterparty => {
                    assert!(
                        counterparty.is_authorized,
                        "counterparty must authorize forfeiture"
                    );
                    let [initiator_refund, counterparty_payout] = forfeiture_payouts(state, true);
                    escrow_transfers(
                        escrow,
                        state.agreement_id,
                        vec![
                            (initiator, initiator_refund),
                            (counterparty, counterparty_payout),
                        ],
                    )
                }
            };
            state.phase = Phase::Settled;
            state.settlement = Some(resolution.settlement);
            payouts
        }
        Instruction::Open { .. } => unreachable!("Open is handled before state loading"),
    }
}

fn completed_payouts(state: &BondState) -> [u128; 2] {
    [
        state
            .participant_refund(true)
            .expect("initiator refund is valid"),
        state
            .participant_refund(false)
            .expect("counterparty refund is valid"),
    ]
}

fn forfeiture_payouts(state: &BondState, initiator_forfeited: bool) -> [u128; 2] {
    if initiator_forfeited {
        [
            state
                .remaining_fee_reserve(true)
                .expect("initiator fee reserve is valid"),
            state
                .participant_refund(false)
                .and_then(|refund| refund.checked_add(state.agreement.stake_amount))
                .expect("counterparty forfeiture payout is valid"),
        ]
    } else {
        [
            state
                .participant_refund(true)
                .and_then(|refund| refund.checked_add(state.agreement.stake_amount))
                .expect("initiator forfeiture payout is valid"),
            state
                .remaining_fee_reserve(false)
                .expect("counterparty fee reserve is valid"),
        ]
    }
}

fn record_fee_burn(state: &mut BondState, initiator: bool, amount: u128) {
    let fees_burned = if initiator {
        &mut state.initiator_fees_burned
    } else {
        &mut state.counterparty_fees_burned
    };
    *fees_burned = fees_burned
        .checked_add(amount)
        .expect("burned fee total overflow");
    assert!(
        *fees_burned
            <= state
                .agreement
                .fee_reserve()
                .expect("validated agreement fee reserve does not overflow"),
        "participant exhausted the prepaid escalation reserve"
    );
}

fn deposit_call(
    sender: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
    amount: u128,
    agreement_id: AgreementId,
) -> ChainedCall {
    assert!(sender.is_authorized, "deposit sender must be authorized");
    let mut escrow_for_transfer = escrow.clone();
    escrow_for_transfer.is_authorized = true;
    ChainedCall::new(
        sender.account.program_owner.into(),
        vec![sender.clone(), escrow_for_transfer],
        &TransferInstruction::Transfer { amount },
    )
    .with_pda_seeds(vec![escrow_seed(&agreement_id)])
}

/// Native balance cannot disappear under LEE's conservation rules. "Burning"
/// therefore means transferring prepaid fees to the program-derived sink,
/// which participants cannot select and this program never spends from.
fn escrow_transfers<'a>(
    escrow: &AccountWithMetadata,
    agreement_id: AgreementId,
    transfers: Vec<(&'a AccountWithMetadata, u128)>,
) -> Vec<ChainedCall> {
    let mut current_escrow = escrow.clone();
    let mut calls = Vec::new();
    for (recipient, amount) in transfers {
        if amount == 0 {
            continue;
        }
        calls.push(payout_call(
            &current_escrow,
            recipient,
            amount,
            agreement_id,
        ));
        current_escrow.account.balance = current_escrow
            .account
            .balance
            .checked_sub(amount)
            .expect("escrow contains the planned transfer amount");
    }
    calls
}

fn payout_call(
    escrow: &AccountWithMetadata,
    recipient: &AccountWithMetadata,
    amount: u128,
    agreement_id: AgreementId,
) -> ChainedCall {
    let mut escrow_for_transfer = escrow.clone();
    escrow_for_transfer.is_authorized = true;
    ChainedCall::new(
        escrow.account.program_owner.into(),
        vec![escrow_for_transfer, recipient.clone()],
        &TransferInstruction::Transfer { amount },
    )
    .with_pda_seeds(vec![escrow_seed(&agreement_id)])
}

fn load_state(
    program_id: [u32; 8],
    state_meta: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
) -> Result<BondState, &'static str> {
    let state =
        BondState::from_bytes(&state_meta.account.data).map_err(|_| "invalid bond state")?;
    assert!(
        state.agreement.is_valid(),
        "stored bond agreement is invalid"
    );
    assert_eq!(
        state.agreement.id(program_id),
        state.agreement_id,
        "stored agreement ID does not match its executable terms"
    );
    assert_eq!(
        state_meta.account_id,
        state_account_id(program_id, &state.agreement_id),
        "wrong agreement state PDA"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(program_id, &state.agreement_id),
        "wrong agreement escrow PDA"
    );
    let participant_deposit = state
        .agreement
        .participant_deposit()
        .ok_or("invalid participant deposit")?;
    let deposits = if state.phase == Phase::AwaitingCounterparty {
        participant_deposit
    } else if state.phase == Phase::Settled {
        0
    } else {
        participant_deposit
            .checked_mul(2)
            .ok_or("escrow deposit total overflow")?
            .checked_sub(state.initiator_fees_burned)
            .and_then(|balance| balance.checked_sub(state.counterparty_fees_burned))
            .ok_or("escrow fee accounting underflow")?
    };
    assert_eq!(
        escrow.account.balance, deposits,
        "escrow balance does not match deposits and prepaid fee burns"
    );
    Ok(state)
}

fn ensure_accounts(
    program_id: [u32; 8],
    state: &BondState,
    initiator: &AccountWithMetadata,
    counterparty: &AccountWithMetadata,
    burn_sink: &AccountWithMetadata,
) {
    assert_eq!(
        initiator.account_id, state.agreement.initiator,
        "wrong initiator account"
    );
    assert_eq!(
        counterparty.account_id, state.agreement.counterparty,
        "wrong counterparty account"
    );
    assert_eq!(
        burn_sink.account_id,
        burn_account_id(program_id),
        "wrong protocol-fixed burn account"
    );
}

fn assert_instruction_agreement(instruction: &Instruction, expected: AgreementId) {
    let actual = match instruction {
        Instruction::Join { agreement_id }
        | Instruction::ChallengeAccept { agreement_id }
        | Instruction::DiscloseAccept { agreement_id, .. }
        | Instruction::ChallengeFinalize { agreement_id, .. }
        | Instruction::DiscloseFinalize { agreement_id, .. }
        | Instruction::Complete { agreement_id, .. }
        | Instruction::SettleTimeout { agreement_id } => agreement_id,
        Instruction::Open { .. } => unreachable!("Open is handled before state loading"),
    };
    assert_eq!(*actual, expected, "instruction targets the wrong agreement");
}

fn read_clock(clock: &AccountWithMetadata) -> u64 {
    assert_eq!(
        clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID,
        "fifth account must be the one-block clock"
    );
    ClockAccountData::from_bytes(&clock.account.data).block_id
}

fn restart_window(state: &mut BondState, current_block: u64) {
    state.expires_at_block = deadline(current_block, state.agreement.response_window_blocks);
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
    verify_proof(
        state.agreement.counterparty_mantle_key,
        state.agreement.tx_hash,
        proof,
    );
}

fn verify_initiator_proof(state: &BondState, proof: &MantleSignature) {
    verify_proof(
        state.agreement.initiator_mantle_key,
        state.agreement.tx_hash,
        proof,
    );
}

fn verify_proof(public_key: [u8; 32], tx_hash: [u8; 32], proof: &MantleSignature) {
    let key = VerifyingKey::from_bytes(&public_key).expect("registered Mantle key is valid");
    let signature = Signature::from_slice(proof.as_bytes()).expect("signature must be 64 bytes");
    key.verify(&tx_hash, &signature)
        .expect("disclosed signature must verify against the registered transaction");
}

fn settle_completed(state: &mut BondState) {
    state.phase = Phase::Settled;
    state.settlement = Some(Settlement::Completed);
}
