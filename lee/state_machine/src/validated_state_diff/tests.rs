use std::collections::HashMap;

use lee_core::{
    DeferredResolution,
    account::{Account, AccountId, BalanceDiff, Nonce},
};

use crate::{
    PrivateKey, PublicKey, V03State,
    error::LeeError,
    privacy_preserving_transaction::message::PublicActionWithID,
    public_transaction::{Message, WitnessSet},
    validated_state_diff::ValidatedStateDiff,
};

// Host-side mirror of `stripped_token`'s `Instruction`/`TokenAccountData`/`TokenDiff` — the
// guest crate isn't a host dependency, so these can't be imported directly, only match the
// borsh layout.
#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    Initialize { balance: u128 },
    Transfer { amount: u128 },
}

#[derive(borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

#[derive(borsh::BorshSerialize)]
enum TokenDiff {
    #[expect(dead_code, reason = "mirrors stripped_token's own TokenDiff shape exactly")]
    Add(u128),
    Sub(u128),
}

fn token_balance(state: &V03State, account_id: AccountId) -> u128 {
    let data: TokenAccountData =
        borsh::from_slice(state.get_account_by_id(account_id).data.as_ref())
            .expect("account data must decode as TokenAccountData");
    data.balance
}

fn initialize_stripped_token_account(
    state: &mut V03State,
    program_id: AccountId,
    account_id: AccountId,
    balance: u128,
    block_id: u64,
) {
    let message = Message::try_new(
        program_id,
        vec![account_id],
        vec![],
        StrippedTokenInstruction::Initialize { balance },
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(
            &crate::PublicTransaction::new(message, witness_set),
            block_id,
            0,
        )
        .unwrap();
}

/// Moves `amount` from `sender` to `receiver` via a real public transaction — the competing
/// activity a `Deferred` payload can be stale against by the time settlement replays it.
fn transfer_stripped_token(
    state: &mut V03State,
    program_id: AccountId,
    sender: AccountId,
    receiver: AccountId,
    amount: u128,
    block_id: u64,
) {
    let message = Message::try_new(
        program_id,
        vec![sender, receiver],
        vec![],
        StrippedTokenInstruction::Transfer { amount },
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(
            &crate::PublicTransaction::new(message, witness_set),
            block_id,
            0,
        )
        .unwrap();
}

/// A `Deferred` action carrying a `TokenDiff::Sub(amount)` delta for `stripped_token` — as if
/// this had been the payload a privacy-preserving proof committed to, unresolved, for
/// settlement to replay.
fn deferred_sub_action(account_id: AccountId, program_id: AccountId, amount: u128) -> PublicActionWithID {
    PublicActionWithID::Deferred {
        account_id,
        resolutions: vec![DeferredResolution {
            executing_account_id: program_id,
            caller_account_id: None,
            post_balance_diff: BalanceDiff::Add(0),
            post_data: Some(
                borsh::to_vec(&TokenDiff::Sub(amount))
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        }],
    }
}

/// End-to-end proof that `resolve_public_action` actually invokes `Incremental` and resolves a
/// `Deferred` action's `TokenDiff` delta into a real balance, host-side and unproven — the
/// settlement-time counterpart to `resolve_diff`'s own role in `execute_authorized`.
#[test]
fn resolve_public_action_replays_a_deferred_action_against_live_state() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([1; 32]);

    let mut state = V03State::new().with_test_programs();
    initialize_stripped_token_account(&mut state, program_id, account_id, 100, 1);
    assert_eq!(token_balance(&state, account_id), 100);

    let action = deferred_sub_action(account_id, program_id, 30);
    let mut cycles_used = 0;
    let (resolved_account_id, resolved) = super::resolve_public_action(
        &action,
        &state,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        &mut cycles_used,
    )
    .expect("resolves");

    assert_eq!(resolved_account_id, account_id);
    let data: TokenAccountData = borsh::from_slice(resolved.data.as_ref())
        .expect("resolved data must decode as TokenAccountData: did Incremental resolution run?");
    assert_eq!(data.balance, 70);
}

/// The actual point of `Deferred`: the resolved value reflects whatever the account holds at
/// settlement time, not whatever it held when the (now-stale) deferred payload was built.
#[test]
fn resolve_public_action_reflects_live_state_not_stale_state() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([1; 32]);

    let mut state = V03State::new().with_test_programs();
    initialize_stripped_token_account(&mut state, program_id, account_id, 100, 1);

    // Fixed "at proof-generation time" — a Sub(30) delta computed against balance 100.
    let action = deferred_sub_action(account_id, program_id, 30);

    // The account changes before settlement actually resolves the deferred delta (`Initialize`
    // is itself a delta — this adds 500 on top of the existing 100).
    initialize_stripped_token_account(&mut state, program_id, account_id, 500, 2);
    assert_eq!(token_balance(&state, account_id), 600);

    let mut cycles_used = 0;
    let (_, resolved) = super::resolve_public_action(
        &action,
        &state,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        &mut cycles_used,
    )
    .expect("resolves");

    // 600 - 30, not 100 - 30: resolution used live state at settlement, not the balance that
    // existed when the deferred payload was built.
    let data: TokenAccountData = borsh::from_slice(resolved.data.as_ref()).unwrap();
    assert_eq!(data.balance, 570);
}

/// The flip side of live-state resolution: if the account can no longer cover a stale `Deferred`
/// debit — e.g. a competing transfer spent the balance away between proof generation and
/// settlement — `Incremental` underflows and resolution fails outright. There's no partial
/// application: `from_privacy_preserving_transaction`'s `.collect::<Result<...>>()` means one
/// failing resolution rejects the whole transaction, the same as any other invalid diff would.
#[test]
fn resolve_public_action_fails_when_live_balance_cannot_cover_a_stale_deferred_debit() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([1; 32]);
    let other_account_id = AccountId::new([2; 32]);

    let mut state = V03State::new().with_test_programs();
    initialize_stripped_token_account(&mut state, program_id, account_id, 100, 1);

    // Fixed "at proof-generation time" — a Sub(80) delta computed against balance 100.
    let action = deferred_sub_action(account_id, program_id, 80);

    // Before settlement, a competing public transfer spends most of the balance away.
    transfer_stripped_token(&mut state, program_id, account_id, other_account_id, 60, 2);
    assert_eq!(token_balance(&state, account_id), 40);

    let mut cycles_used = 0;
    let result = super::resolve_public_action(
        &action,
        &state,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        &mut cycles_used,
    );

    assert!(
        result.is_err(),
        "a deferred Sub(80) against a live balance of 40 must fail, not underflow silently"
    );
}

/// A program that never implemented `Incremental` (predates it entirely) falls back to
/// copy/replace — the deferred payload applies verbatim, exactly like a `Bound` action would.
#[test]
fn resolve_public_action_falls_back_to_copy_replace_when_incremental_is_unsupported() {
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let account_id = AccountId::new([1; 32]);
    let state = V03State::new().with_test_programs();

    let action = PublicActionWithID::Deferred {
        account_id,
        resolutions: vec![DeferredResolution {
            executing_account_id: program_id,
            caller_account_id: None,
            post_balance_diff: BalanceDiff::Add(42),
            post_data: Some(vec![1, 2, 3].try_into().unwrap()),
        }],
    };
    let mut cycles_used = 0;
    let (_, resolved) = super::resolve_public_action(
        &action,
        &state,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        &mut cycles_used,
    )
    .expect("resolves");

    assert_eq!(resolved.balance, 42);
    assert_eq!(resolved.data.as_ref(), &[1, 2, 3]);
}

/// A `Bound` action (`deferred: None`) passes through unchanged — regression guard against
/// `resolve_public_action` disturbing today's only real code path.
#[test]
fn resolve_public_action_passes_a_bound_action_through_unchanged() {
    let account_id = AccountId::new([1; 32]);
    let state = V03State::new();
    let post_state = Account {
        balance: 555,
        ..Account::default()
    };
    let action = PublicActionWithID::Bound {
        account_id,
        post_state: post_state.clone(),
    };
    let mut cycles_used = 0;
    let (resolved_account_id, resolved) = super::resolve_public_action(
        &action,
        &state,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        &mut cycles_used,
    )
    .expect("resolves");

    assert_eq!(resolved_account_id, account_id);
    assert_eq!(resolved, post_state);
}

fn public_state_from_balances(initial_data: &[(AccountId, u128)]) -> HashMap<AccountId, Account> {
    initial_data
        .iter()
        .copied()
        .map(|(account_id, balance)| {
            (
                account_id,
                Account {
                    program_owner: crate::test_methods::simple_balance_transfer().id().into(),
                    balance,
                    ..Account::default()
                },
            )
        })
        .collect()
}

#[test]
fn public_diff_reflects_a_successful_transfer() {
    // A successful native transfer must record the debited sender in
    // `public_diff()`.  Catches the mutation that replaces `public_diff` with
    // `HashMap::new()` (which would hide every account change).
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let message =
        Message::try_new(program_id, vec![from, to], vec![Nonce(0), Nonce(0)], 5_u128).unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("a valid native transfer must validate");
    let public_diff = diff.public_diff();

    assert!(
        public_diff.contains_key(&from),
        "public_diff must contain the debited sender",
    );
    assert_eq!(
        public_diff[&from].balance, 95,
        "sender balance in the diff must reflect the debit",
    );
}

/// Regression test: a `PrivacyPreservingTransaction` carrying a structurally invalid
/// proof must be rejected with a clean `Err`.
#[test]
fn privacy_garbage_proof_is_rejected() {
    use lee_core::{
        Commitment, EncryptedAccountData, Nullifier, PrivateAction,
        account::Account,
        encryption::{Ciphertext, EphemeralPublicKey},
        program::{BlockValidityWindow, TimestampValidityWindow},
    };

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::Proof, message::Message, witness_set::WitnessSet,
        },
    };

    let state = V03State::new();

    // Minimal message that passes every check up to proof verification: a single
    // commitment satisfies the non-empty requirement, no signers makes the
    // nonce/signature checks vacuously true, and unbounded validity windows are valid
    // for any block/timestamp.
    let account_id = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([1_u8; 32]).unwrap(),
    ));
    let commitment = Commitment::new(&account_id, &Account::default());
    let message = Message {
        public_actions: vec![],
        nonces: vec![],
        private_actions: vec![PrivateAction {
            nullifier: Nullifier::for_account_initialization(&account_id),
            root: [0; 32],
            commitment,
            encrypted_post_state: EncryptedAccountData {
                ciphertext: Ciphertext::from_inner(vec![]),
                epk: EphemeralPublicKey(vec![]),
                view_tag: 0,
            },
        }],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        program_image_claims: vec![],
    };

    // Garbage proof bytes: not a valid borsh-encoded `InnerReceipt`.
    let garbage_proof = Proof::from_inner(vec![0xff_u8; 64]);
    let witness_set = WitnessSet::for_message(&message, garbage_proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

    match result {
        Err(LeeError::InvalidPrivacyPreservingProof) => {}
        Err(other) => panic!("expected InvalidPrivacyPreservingProof, got {other:?}"),
        Ok(_) => panic!("garbage proof was accepted instead of rejected"),
    }
}

fn metering_transfer_fixture() -> (V03State, crate::PublicTransaction) {
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let message =
        Message::try_new(program_id, vec![from, to], vec![Nonce(0), Nonce(0)], 5_u128).unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    (state, crate::PublicTransaction::new(message, witness_set))
}

#[test]
fn budgeted_execution_reports_cycles_and_matching_diff() {
    // The same tx through both entry points: identical diff, nonzero cycles.
    let (state, tx) = metering_transfer_fixture();
    let (diff, outcome) = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect("executes");
    let unbudgeted =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).expect("executes");
    assert_eq!(diff.public_diff(), unbudgeted.public_diff());
    assert!(outcome.cycles > 0);
    assert!(outcome.cycles <= crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET);
}

#[test]
fn exhausted_budget_surfaces_out_of_gas() {
    let (state, tx) = metering_transfer_fixture();
    let result =
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, &state, 1, 0, 1_024);
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

#[test]
fn chained_calls_share_one_budget() {
    // A chain-calling tx must exhaust when the budget covers less than the
    // whole chain, even though each individual call would fit.
    let chain_caller = crate::test_methods::chain_caller();
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 1_000), (to, 0)]))
        .with_test_programs();
    let instruction: (
        u128,
        lee_core::program::ProgramId,
        u32,
        Option<lee_core::program::PdaSeed>,
    ) = (
        37,
        crate::test_methods::simple_balance_transfer().id(),
        2,
        None,
    );
    // The chain_caller program permutes the account order in the chain call.
    let message = Message::try_new(
        chain_caller.id().into(),
        vec![to, from],
        vec![Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let full_cycles = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &tx,
        &state,
        1,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect("executes under the default budget")
    .1
    .cycles;

    // `cycles()` and the session limit gate the same unpadded user-cycle
    // counter, but the limit is only checked before each instruction and one
    // instruction (an ecall) can add up to MAX_INSN_CYCLES (~25k) at once, so a
    // boundary budget (`full_cycles - 1`) can still complete. A quarter of the
    // chain's total is decisively insufficient.
    let starved_budget = full_cycles >> 2;
    let starved = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &tx,
        &state,
        1,
        0,
        starved_budget,
    );
    assert!(matches!(starved, Err(LeeError::OutOfGas { .. })));
}

#[test]
fn free_outcome_is_zero_cycles() {
    assert_eq!(crate::ExecutionOutcome::FREE.cycles, 0);
}

#[test]
fn metered_guest_panic_is_charged_the_full_budget() {
    // A transfer beyond the sender's balance panics the guest mid-execution —
    // a chargeable failure that is not OutOfGas. The panic drops the session
    // and its count, so it pays the whole declared budget.
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let message = Message::try_new(
        program_id,
        vec![from, to],
        vec![Nonce(0), Nonce(0)],
        1_000_u128,
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget);
    assert_eq!(
        outcome.cycles, budget,
        "a panic pays its full declared budget"
    );
    result.expect("a charged revert still yields an applicable diff");
}

#[test]
fn metered_nonzero_exit_is_charged_its_metered_cycles() {
    // Unlike a panic, `env::exit(n)` keeps the session, so the revert pays what
    // it actually ran rather than the whole budget.
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(crate::test_methods::exits_nonzero()));
    let program_id: AccountId = crate::test_methods::exits_nonzero().id().into();
    let message = Message::try_new(program_id, vec![from], vec![Nonce(0)], ()).unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget);
    assert!(
        outcome.cycles > 0 && outcome.cycles < budget,
        "a non-zero exit is metered, not charged the full budget: {}",
        outcome.cycles
    );
    let diff = result.expect("a charged revert still yields an applicable diff");
    assert!(
        diff.public_diff().is_empty(),
        "a reverted action moves no balances"
    );
}

#[test]
fn chained_nonzero_exit_adds_callee_cycles_to_callers() {
    // The accumulation branch only matters once the caller has burned cycles: a chained
    // callee's non-zero exit must charge caller + callee, not just the callee.
    let chain_caller = crate::test_methods::chain_caller();
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 1_000), (to, 0)]))
        .with_test_programs();
    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let run = |num_chain_calls: u32| {
        let instruction: (
            u128,
            lee_core::program::ProgramId,
            u32,
            Option<lee_core::program::PdaSeed>,
        ) = (
            0,
            crate::test_methods::exits_nonzero().id(),
            num_chain_calls,
            None,
        );
        let message = Message::try_new(
            chain_caller.id().into(),
            vec![to, from],
            vec![Nonce(0)],
            instruction,
        )
        .unwrap();
        let witness_set = WitnessSet::for_message(&message, &[&from_key]);
        let tx = crate::PublicTransaction::new(message, witness_set);
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget)
    };

    let (caller_only, ok) = run(0);
    ok.expect("the caller alone succeeds");

    // The callee alone, so the assertion below fails if its cycles are never folded in: a
    // caller with one chained call burns only marginally more than with none.
    let callee_message = Message::try_new(
        crate::test_methods::exits_nonzero().id().into(),
        vec![from],
        vec![Nonce(0)],
        (),
    )
    .unwrap();
    let callee_witness_set = WitnessSet::for_message(&callee_message, &[&from_key]);
    let callee_tx = crate::PublicTransaction::new(callee_message, callee_witness_set);
    let (callee_alone, _) =
        ValidatedStateDiff::from_public_transaction_metered(&callee_tx, &state, 1, 0, budget);

    let (outcome, result) = run(1);
    assert!(
        outcome.cycles >= caller_only.cycles.saturating_add(callee_alone.cycles)
            && outcome.cycles < budget,
        "caller + callee cycles are metered: {} vs caller-only {} + callee-only {}",
        outcome.cycles,
        caller_only.cycles,
        callee_alone.cycles
    );
    let diff = result.expect("a charged revert still yields an applicable diff");
    assert!(
        diff.public_diff().is_empty(),
        "a reverted action moves no balances"
    );
}

#[test]
fn metered_revert_reports_cycles_and_yields_a_nonce_only_diff() {
    let (mut state, tx) = metering_transfer_fixture();
    let from = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([1_u8; 32]).unwrap(),
    ));
    let to = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([2_u8; 32]).unwrap(),
    ));
    let from_before = state.get_account_by_id(from).balance;

    // A budget too small to finish the transfer: the action runs out of gas.
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, 1_024);
    assert_eq!(
        outcome.cycles, 1_024,
        "out-of-gas is metered at the whole budget"
    );

    // The revert is buried as a successful return: the diff carries no effects,
    // only the signers' nonce advances, so the charged tx cannot be replayed.
    let diff = result.expect("a reverted action still yields an applicable diff");
    assert!(
        diff.public_diff().is_empty(),
        "a reverted action moves no balances"
    );
    drop(state.apply_state_diff(diff));
    assert_eq!(
        state.get_account_by_id(from).balance,
        from_before,
        "the transfer was reverted"
    );
    assert_eq!(state.get_account_by_id(from).nonce.0, 1);
    assert_eq!(state.get_account_by_id(to).nonce.0, 1);
}
