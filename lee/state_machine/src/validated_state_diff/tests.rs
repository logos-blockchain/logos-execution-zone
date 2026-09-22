use lee_core::{
    account::{AccountId, Nonce, ProgramShardSelector},
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::InstructionData,
};

use crate::{
    PrivateKey, PublicKey, V03State,
    error::LeeError,
    public_transaction::{Message, WitnessSet},
    validated_state_diff::ValidatedStateDiff,
};

const CHAINED_CALLS: usize = 3;

type ForwarderInstruction = (
    Option<(AccountId, Vec<u8>)>,
    Vec<(AccountId, ProgramShardSelector, InstructionData)>,
);

#[test]
fn public_diff_reflects_a_successful_transfer() {
    // A successful native transfer must record the debited sender in
    // `public_diff()`.  Catches the mutation that replaces `public_diff` with
    // `HashMap::new()` (which would hide every account change).
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new().with_public_account_balances([(from, 100)]);
    let message = Message::try_new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::balance(from),
            ProgramShardSelector::balance(to),
        ],
        vec![Nonce(0), Nonce(0)],
        NativeInstruction::Transfer { amount: 5 },
    )
    .unwrap();
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
        public_diff[&from].data.balance(),
        Ok(95),
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

fn metering_write_fixture() -> (V03State, crate::PublicTransaction) {
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let program = crate::test_methods::reordering_writer();
    let program_id = AccountId::from_builtin_program(program.id());
    let state = V03State::new()
        .with_public_account_balances([(from, 100)])
        .with_programs(std::iter::once(program));
    let message = Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::new(from, program_id),
            ProgramShardSelector::new(to, program_id),
        ],
        vec![Nonce(0), Nonce(0)],
        vec![7_u8; 4],
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    (state, crate::PublicTransaction::new(message, witness_set))
}

#[test]
fn budgeted_execution_reports_cycles_and_matching_diff() {
    // The same tx through both entry points: identical diff, nonzero cycles.
    let (state, tx) = metering_write_fixture();
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
    let (state, tx) = metering_write_fixture();
    let result =
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, &state, 1, 0, 1_024);
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

#[test]
fn chained_calls_share_one_budget() {
    // A chain-calling tx must exhaust when the budget covers less than the
    // whole chain, even though each individual call would fit.
    let forwarder_id = AccountId::from_builtin_program(crate::test_methods::shard_forwarder().id());
    let echo_id = AccountId::from_builtin_program(crate::test_methods::noop().id());
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let state = V03State::new()
        .with_public_account_balances([(from, 1_000)])
        .with_test_programs();
    let callee = (
        echo_id,
        ProgramShardSelector::new(from, echo_id),
        InstructionData::new(),
    );
    let forwarding = |callees: Vec<_>| {
        let instruction: ForwarderInstruction = (None, callees);
        let message = Message::try_new(
            forwarder_id,
            vec![ProgramShardSelector::new(from, forwarder_id)],
            vec![Nonce(0)],
            instruction,
        )
        .unwrap();
        let witness_set = WitnessSet::for_message(&message, &[&from_key]);
        crate::PublicTransaction::new(message, witness_set)
    };
    let one_callee = forwarding(vec![callee.clone()]);
    let chain = forwarding(vec![callee; CHAINED_CALLS]);
    let cycles_under = |tx, budget| {
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(tx, &state, 1, 0, budget)
    };
    let spent = |tx| {
        cycles_under(tx, crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET)
            .expect("executes under the default budget")
            .1
            .cycles
    };

    let budget = spent(&one_callee);

    assert!(
        cycles_under(&one_callee, budget).is_ok(),
        "the budget must cover the root call and a whole chained callee"
    );
    assert!(
        budget < spent(&chain),
        "the budget must not cover the whole chain"
    );
    assert!(matches!(
        cycles_under(&chain, budget),
        Err(LeeError::OutOfGas { budget: remaining }) if remaining < budget
    ));
}

#[test]
fn free_outcome_is_zero_cycles() {
    assert_eq!(crate::ExecutionOutcome::FREE.cycles, 0);
}

#[test]
fn metered_guest_panic_is_charged_the_full_budget() {
    // An unauthorized pre_state panics the guest mid-execution — a chargeable
    // failure that is not OutOfGas. It still pays the whole declared budget:
    // metering written back on an error path must never undercharge.
    let program_id =
        AccountId::from_builtin_program(crate::test_methods::auth_asserting_noop().id());
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let unsigned = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_account_balances([(from, 100)])
        .with_test_programs();
    let message = Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::new(from, program_id),
            ProgramShardSelector::new(unsigned, program_id),
        ],
        vec![Nonce(0)],
        (),
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key]);
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
        .with_public_account_balances([(from, 100)])
        .with_programs(std::iter::once(crate::test_methods::exits_nonzero()));
    let program_id = AccountId::from_builtin_program(crate::test_methods::exits_nonzero().id());
    let message = Message::try_new(
        program_id,
        vec![ProgramShardSelector::balance(from)],
        vec![Nonce(0)],
        (),
    )
    .unwrap();
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
        .with_public_account_balances([(from, 1_000), (to, 0)])
        .with_test_programs();
    let budget = crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET;
    let run = |num_chain_calls: u32| {
        let instruction: (
            lee_core::program::InstructionData,
            lee_core::program::ProgramId,
            u32,
            Option<lee_core::program::PdaSeed>,
        ) = (
            Vec::new(),
            crate::test_methods::exits_nonzero().id(),
            num_chain_calls,
            None,
        );
        let message = Message::try_new(
            AccountId::from_builtin_program(chain_caller.id()),
            vec![
                ProgramShardSelector::balance(to),
                ProgramShardSelector::balance(from),
            ],
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
        AccountId::from_builtin_program(crate::test_methods::exits_nonzero().id()),
        vec![ProgramShardSelector::balance(from)],
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
    let (mut state, tx) = metering_write_fixture();
    let from = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([1_u8; 32]).unwrap(),
    ));
    let to = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([2_u8; 32]).unwrap(),
    ));
    let from_before = state.get_account_by_id(from);

    // A budget too small to finish the write: the action runs out of gas.
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
        "a reverted action writes no shard"
    );
    drop(state.apply_state_diff(diff));
    assert_eq!(
        state.get_account_by_id(from).data,
        from_before.data,
        "the write was reverted"
    );
    assert_eq!(state.get_account_by_id(from).nonce.0, 1);
    assert_eq!(state.get_account_by_id(to).nonce.0, 1);
}
