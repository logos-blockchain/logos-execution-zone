use super::*;

// Host-side mirror of `stripped_token`'s `Instruction`/`TokenAccountData` — the guest crate
// isn't a host dependency, so these can't be imported directly, only match the borsh layout.
#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    Initialize { balance: u128 },
    Transfer { amount: u128 },
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

// Host-side mirror of `stripped_token_and_forward`'s own `TokenDiff` — used only by the
// owned-account settlement tests below, where `stripped_token_and_forward` writes to (and so
// becomes the owner of) the account itself, rather than forwarding the write to `stripped_token`.
#[derive(borsh::BorshSerialize)]
enum TokenDiff {
    Add(u128),
}

// Host-side mirror of `stripped_token_and_forward`'s `ProbeAssertion` — `Real` wraps the real
// `lee_core::program::DeferReads`, a genuine host dependency, so no separate mirror is needed for
// it. Variant order must match the guest's exactly (borsh discriminants are positional), so
// `None`/`Unrelated` stay even though only `Real` is ever constructed here.
#[expect(dead_code, reason = "kept only to preserve the guest's borsh discriminants")]
#[derive(borsh::BorshSerialize)]
enum ProbeAssertion {
    None,
    Real(lee_core::program::DeferReads),
    Unrelated,
}

fn token_balance(state: &V03State, account_id: AccountId) -> u128 {
    let data: TokenAccountData = borsh::from_slice(
        state.get_account_by_id(account_id).data.as_ref(),
    )
    .expect("account data must decode as TokenAccountData: did Incremental resolution run?");
    data.balance
}

fn initialize_token_account(
    state: &mut V03State,
    stripped_token_program_id: AccountId,
    account_id: AccountId,
    balance: u128,
    block_id: BlockId,
) {
    let message = public_transaction::Message::try_new(
        stripped_token_program_id,
        vec![account_id],
        vec![],
        StrippedTokenInstruction::Initialize { balance },
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(
            &PublicTransaction::new(message, witness_set),
            block_id,
            0,
        )
        .unwrap();
}

/// End-to-end proof that `resolve_diff` actually invokes `Incremental` and resolves
/// `stripped_token`'s `TokenDiff` deltas into real balances: if it silently fell back to
/// copy/replace instead, the account's `data` would hold raw `TokenDiff` bytes, and decoding it
/// here as `TokenAccountData` would fail outright.
#[test]
fn stripped_token_transfer_resolves_through_incremental_dispatch() {
    let mut state = V03State::new().with_test_programs();
    let program_id: AccountId = crate::test_methods::stripped_token().id().into();
    let sender_id = AccountId::new([1; 32]);
    let receiver_id = AccountId::new([2; 32]);

    // Initialize only the sender — the receiver stays untouched, exercising `Incremental`'s
    // empty-data-defaults-to-zero path for a never-initialized account.
    let initialize_message = public_transaction::Message::try_new(
        program_id,
        vec![sender_id],
        vec![],
        StrippedTokenInstruction::Initialize { balance: 100 },
    )
    .unwrap();
    let initialize_witness_set =
        public_transaction::WitnessSet::for_message(&initialize_message, &[]);
    state
        .transition_from_public_transaction(
            &PublicTransaction::new(initialize_message, initialize_witness_set),
            1,
            0,
        )
        .unwrap();

    assert_eq!(token_balance(&state, sender_id), 100);
    // Account.balance (native) is a completely separate field this program never touches.
    assert_eq!(state.get_account_by_id(sender_id).balance, 0);

    let transfer_message = public_transaction::Message::try_new(
        program_id,
        vec![sender_id, receiver_id],
        vec![],
        StrippedTokenInstruction::Transfer { amount: 30 },
    )
    .unwrap();
    let transfer_witness_set = public_transaction::WitnessSet::for_message(&transfer_message, &[]);
    state
        .transition_from_public_transaction(
            &PublicTransaction::new(transfer_message, transfer_witness_set),
            2,
            0,
        )
        .unwrap();

    assert_eq!(token_balance(&state, sender_id), 70);
    assert_eq!(token_balance(&state, receiver_id), 30);
    assert_eq!(state.get_account_by_id(sender_id).balance, 0);
    assert_eq!(state.get_account_by_id(receiver_id).balance, 0);
}

fn robinhood_message(
    robinhood_program_id: AccountId,
    stripped_token_program_id: AccountId,
    account1_id: AccountId,
    account2_id: AccountId,
) -> public_transaction::Message {
    public_transaction::Message::try_new(
        robinhood_program_id,
        vec![account1_id, account2_id],
        vec![],
        stripped_token_program_id,
    )
    .unwrap()
}

/// `stripped_token_robinhood` reads both accounts' real balances to pick a route, but its own
/// diffs are always unchanged — the actual movement happens in the chained `stripped_token`
/// call. This is the scenario `Bound`/`Deferred` inference exists for: robinhood forces both
/// accounts it touches to `Bound` (it needs live values now, and doesn't support
/// `CallKind::Incremental`), even though the chained `Transfer` on the same accounts would
/// otherwise be `Deferred`-eligible on its own.
#[test]
fn stripped_token_robinhood_moves_one_unit_from_the_larger_account_to_the_smaller() {
    let mut state = V03State::new().with_test_programs();
    let stripped_token_program = crate::test_methods::stripped_token();
    let stripped_token_program_id: AccountId = stripped_token_program.id().into();
    let robinhood_program_id: AccountId =
        crate::test_methods::stripped_token_robinhood().id().into();
    let account1_id = AccountId::new([1; 32]);
    let account2_id = AccountId::new([2; 32]);

    initialize_token_account(&mut state, stripped_token_program_id, account1_id, 100, 1);
    initialize_token_account(&mut state, stripped_token_program_id, account2_id, 40, 2);

    let message = robinhood_message(
        robinhood_program_id,
        stripped_token_program_id,
        account1_id,
        account2_id,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 3, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account1_id), 99);
    assert_eq!(token_balance(&state, account2_id), 41);
}

/// Same as above with sizes swapped, proving the route follows whichever account is larger, not
/// a fixed position.
#[test]
fn stripped_token_robinhood_follows_whichever_account_is_actually_larger() {
    let mut state = V03State::new().with_test_programs();
    let stripped_token_program = crate::test_methods::stripped_token();
    let stripped_token_program_id: AccountId = stripped_token_program.id().into();
    let robinhood_program_id: AccountId =
        crate::test_methods::stripped_token_robinhood().id().into();
    let account1_id = AccountId::new([1; 32]);
    let account2_id = AccountId::new([2; 32]);

    // account2 is now the larger one — the opposite of the previous test.
    initialize_token_account(&mut state, stripped_token_program_id, account1_id, 40, 1);
    initialize_token_account(&mut state, stripped_token_program_id, account2_id, 100, 2);

    let message = robinhood_message(
        robinhood_program_id,
        stripped_token_program_id,
        account1_id,
        account2_id,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 3, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account1_id), 41);
    assert_eq!(token_balance(&state, account2_id), 99);
}

/// Equal balances trigger no chained call at all — a real no-op, not a same-amount round trip.
#[test]
fn stripped_token_robinhood_does_nothing_when_balances_are_equal() {
    let mut state = V03State::new().with_test_programs();
    let stripped_token_program = crate::test_methods::stripped_token();
    let stripped_token_program_id: AccountId = stripped_token_program.id().into();
    let robinhood_program_id: AccountId =
        crate::test_methods::stripped_token_robinhood().id().into();
    let account1_id = AccountId::new([1; 32]);
    let account2_id = AccountId::new([2; 32]);

    initialize_token_account(&mut state, stripped_token_program_id, account1_id, 50, 1);
    initialize_token_account(&mut state, stripped_token_program_id, account2_id, 50, 2);

    let message = robinhood_message(
        robinhood_program_id,
        stripped_token_program_id,
        account1_id,
        account2_id,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 3, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account1_id), 50);
    assert_eq!(token_balance(&state, account2_id), 50);
}

// ── Privacy-preserving `Deferred` settlement, end to end ──
//
// The tests above settle `Incremental` diffs produced by the *public*-transaction path. These
// exercise the other producer of an `Incremental`-eligible diff: a real privacy-preserving
// circuit run classifying a touch `Deferred` (via `stripped_token_and_forward` asserting a
// `DeferReads` claim on `Probe`), proving it, and settling it through
// `transition_from_privacy_preserving_transaction`. Unlike `validated_state_diff::tests`'
// `resolve_public_action_*` tests, nothing here hand-constructs a `DeferredResolution` — it comes
// out of a genuine circuit proof.
//
// All three variants are covered, across two account shapes: `deferred_initialize_tx` forwards a
// write to `stripped_token`, so `stripped_token_and_forward`'s own touch on the account is
// always a read — covering `ReadOnly` covering it and `WriteOnly` not (plus `All`, which covers
// either way). `write_then_read_tx` covers the write side instead: `stripped_token_and_forward`
// writes the account itself, then reads it again in a second, independent call — see that
// function's doc comment for why a third, forced touch is also needed to reach this safely.

/// Proves a privacy-preserving transaction that forwards `stripped_token`'s
/// `Initialize { balance }` through `stripped_token_and_forward`, asserting `claim` on `Probe`.
/// Also returns the circuit's own `PublicAction` for the touch — callers assert on its exact
/// shape directly, since a `Bound` and a `Deferred` initialize settle to the same final balance
/// here and so can't be told apart from settled state alone.
fn deferred_initialize_tx(
    forward_program_id: AccountId,
    token_program_id: AccountId,
    account_id: AccountId,
    balance: u128,
    claim: lee_core::program::DeferReads,
) -> (PrivacyPreservingTransaction, PublicAction) {
    let program_with_deps = ProgramWithDependencies::new(
        crate::test_methods::stripped_token_and_forward(),
        forward_program_id,
        [(token_program_id, crate::test_methods::stripped_token())].into(),
    );

    let pre = AccountWithMetadata::new(Account::default(), false, account_id);
    let instruction = Program::serialize_instruction((
        Vec::<u8>::new(),
        token_program_id,
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance }).unwrap(),
        ProbeAssertion::Real(claim),
    ))
    .unwrap();

    // A privacy-preserving transaction requires at least one private action; this account is
    // untouched by any chained call and exists purely to satisfy that (see
    // `stripped_token_and_forward`'s optional padding account).
    let padding_keys = test_private_account_keys_1();
    let padding_id =
        AccountId::for_regular_private_account(&padding_keys.npk(), &padding_keys.vpk(), 0);

    let (output, proof) = execute_and_prove(
        vec![pre, AccountWithMetadata::new(Account::default(), false, padding_id)],
        instruction,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: padding_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: padding_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program_with_deps,
    )
    .expect("an asserted-safe read chained into a genuine write must prove");

    let [action] = &*output.public_actions else {
        panic!("expected exactly one public action");
    };
    let action = action.clone();

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    (PrivacyPreservingTransaction::new(message, witness_set), action)
}

/// End-to-end proof that a `Deferred` public action produced by a real circuit run settles
/// correctly: `transition_from_privacy_preserving_transaction` must still run `stripped_token`'s
/// `Incremental` dispatch on it, landing a real, decodable balance rather than the raw,
/// unresolved `TokenDiff` bytes the circuit carried through unproven.
#[test]
fn a_deferred_initialize_from_a_real_circuit_run_settles_correctly() {
    let mut state = V03State::new().with_test_programs();
    let forward_program_id: AccountId =
        crate::test_methods::stripped_token_and_forward().id().into();
    let token_program_id: AccountId = crate::test_methods::stripped_token().id().into();
    let account_id = AccountId::new([1; 32]);
    let balance: u128 = 42;

    let (tx, action) = deferred_initialize_tx(
        forward_program_id,
        token_program_id,
        account_id,
        balance,
        lee_core::program::DeferReads::All,
    );
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!("DeferReads::All must classify the touch Deferred");
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, token_program_id);
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap().as_slice()
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account_id), balance);
}

/// Same as above, but with `DeferReads::ReadOnly` instead of `All`. The account is owned by
/// `stripped_token`, not the asserting `stripped_token_and_forward`, so `ReadOnly` covers it just
/// as `All` does — settlement must resolve it the same way.
#[test]
fn a_deferred_initialize_with_a_read_only_claim_settles_correctly() {
    let mut state = V03State::new().with_test_programs();
    let forward_program_id: AccountId =
        crate::test_methods::stripped_token_and_forward().id().into();
    let token_program_id: AccountId = crate::test_methods::stripped_token().id().into();
    let account_id = AccountId::new([1; 32]);
    let balance: u128 = 42;

    let (tx, action) = deferred_initialize_tx(
        forward_program_id,
        token_program_id,
        account_id,
        balance,
        lee_core::program::DeferReads::ReadOnly,
    );
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!("DeferReads::ReadOnly must cover a non-owned account and classify the touch Deferred");
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, token_program_id);
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(balance)).unwrap().as_slice()
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account_id), balance);
}

/// `DeferReads::WriteOnly` on the same touch: `stripped_token_and_forward`'s own touch on the
/// account is a read (it collapses to `unchanged`), which `WriteOnly` doesn't cover, so it's
/// resolved `Bound` in-circuit instead of `Deferred`. Settlement for `Bound` is just the
/// message's `post_state` copied through — no `Incremental` re-resolution runs — but this
/// confirms `transition_from_privacy_preserving_transaction` still lands the right balance
/// either way, regardless of which path a given `DeferReads` claim routes the account through.
#[test]
fn a_write_only_initialize_forced_bound_settles_correctly() {
    let mut state = V03State::new().with_test_programs();
    let forward_program_id: AccountId =
        crate::test_methods::stripped_token_and_forward().id().into();
    let token_program_id: AccountId = crate::test_methods::stripped_token().id().into();
    let account_id = AccountId::new([1; 32]);
    let balance: u128 = 42;

    let (tx, action) = deferred_initialize_tx(
        forward_program_id,
        token_program_id,
        account_id,
        balance,
        lee_core::program::DeferReads::WriteOnly,
    );
    let PublicAction::Bound { pre, post } = action else {
        panic!("DeferReads::WriteOnly must not cover a read touch, forcing Bound");
    };
    assert_eq!(pre.account_id, account_id);
    assert_eq!(pre.account, Account::default());
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("stripped_token's Incremental resolution must have run in-circuit");
    assert_eq!(data.balance, balance);
    assert_eq!(post.program_owner, token_program_id);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account_id), balance);
}

/// Same `DeferReads::All`-asserted `Deferred` touch, except the account's live balance changes
/// (via an ordinary public transaction) *after* the proof is generated but *before* it settles.
/// This is the concrete behavioral case `Deferred` exists for: settlement must resolve
/// `Incremental` against the live value at apply time, not whatever the account held when the
/// proof was generated.
#[test]
fn a_deferred_initialize_reflects_state_mutated_after_proving() {
    let mut state = V03State::new().with_test_programs();
    let forward_program_id: AccountId =
        crate::test_methods::stripped_token_and_forward().id().into();
    let token_program_id: AccountId = crate::test_methods::stripped_token().id().into();
    let account_id = AccountId::new([1; 32]);
    let delta: u128 = 42;

    // Proof is generated while the account is still uninitialized (balance 0).
    let (tx, action) = deferred_initialize_tx(
        forward_program_id,
        token_program_id,
        account_id,
        delta,
        lee_core::program::DeferReads::All,
    );
    let PublicAction::Deferred {
        account_id: deferred_account_id,
        resolutions,
    } = action
    else {
        panic!("DeferReads::All must classify the touch Deferred");
    };
    assert_eq!(deferred_account_id, account_id);
    let [resolution] = <[_; 1]>::try_from(resolutions).unwrap();
    assert_eq!(resolution.executing_account_id, token_program_id);
    assert_eq!(
        resolution.post_data.unwrap().as_ref(),
        borsh::to_vec(&TokenDiff::Add(delta)).unwrap().as_slice()
    );

    // The account gets initialized for real, live, after the proof already exists.
    initialize_token_account(&mut state, token_program_id, account_id, 10, 1);
    assert_eq!(token_balance(&state, account_id), 10);

    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();

    // `stripped_token`'s Incremental interprets the deferred `Initialize`'s raw post_data as a
    // `TokenDiff::Add` delta against whatever the account holds at settlement time — 10 (live),
    // not 0 (the value the proof was generated against).
    assert_eq!(token_balance(&state, account_id), 10 + delta);
}

/// Proves a privacy-preserving transaction where `stripped_token_and_forward` writes an account
/// itself, then asserts the *same* claim again on a second, self-chained read of that same
/// account — showing one claim gets checked independently per call, once against a write and
/// once against a read.
///
/// `stripped_token_and_forward` always forwards, so this needs three touches, all legitimate:
/// (1) top-level, it genuinely writes `TokenDiff::Add(1)`, asserting `claim` on its own `Probe`;
/// (2) chained into itself again, it echoes the account's now-current data verbatim, so this diff
/// collapses to a no-op read, and asserts the *same* `claim` on this call's own, independent
/// `Probe`; (3) forced onward once more, it lands on `defer_asserting_noop`, which — unlike plain
/// `noop` — is `Incremental`-aware and asserts `DeferReads::All`, so it doesn't disturb whatever
/// (1) and (2) already decided.
///
/// Also returns the circuit's own `PublicAction` for the account — callers assert on its exact
/// shape directly, since touches (1)/(2) settle to the same final balance either way.
fn write_then_read_tx(
    forward_program_id: AccountId,
    terminator_account_id: AccountId,
    account_id: AccountId,
    claim: lee_core::program::DeferReads,
) -> (PrivacyPreservingTransaction, PublicAction) {
    let program_with_deps = ProgramWithDependencies::new(
        crate::test_methods::stripped_token_and_forward(),
        forward_program_id,
        [
            (
                forward_program_id,
                crate::test_methods::stripped_token_and_forward(),
            ),
            (
                terminator_account_id,
                crate::test_methods::defer_asserting_noop(),
            ),
        ]
        .into(),
    );

    let pre = AccountWithMetadata::new(Account::default(), false, account_id);

    // Touch 2 (self-chained): echoes the account's post-touch-1 data verbatim, so its diff
    // collapses to `post_data: None` and triggers a second, independent `Probe` — asserting the
    // same `claim` again, now checked against a read instead of a write.
    let touch2_instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenAccountData { balance: 1 }).unwrap(),
        terminator_account_id,
        Program::serialize_instruction(()).unwrap(),
        ProbeAssertion::Real(claim),
    ))
    .unwrap();

    // Touch 1 (top-level): a genuine `TokenDiff::Add(1)` on a fresh account, asserting `claim`
    // on its own `Probe`.
    let instruction = Program::serialize_instruction((
        borsh::to_vec(&TokenDiff::Add(1)).unwrap(),
        forward_program_id,
        touch2_instruction,
        ProbeAssertion::Real(claim),
    ))
    .unwrap();

    // A privacy-preserving transaction requires at least one private action; this account is
    // untouched by any chained call and exists purely to satisfy that.
    let padding_keys = test_private_account_keys_1();
    let padding_id =
        AccountId::for_regular_private_account(&padding_keys.npk(), &padding_keys.vpk(), 0);

    let (output, proof) = execute_and_prove(
        vec![pre, AccountWithMetadata::new(Account::default(), false, padding_id)],
        instruction,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: padding_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: padding_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program_with_deps,
    )
    .expect("a self-write followed by a self-read of an owned account must prove");

    let [action] = &*output.public_actions else {
        panic!("expected exactly one public action");
    };
    let action = action.clone();

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    (PrivacyPreservingTransaction::new(message, witness_set), action)
}

/// End-to-end proof that `DeferReads::WriteOnly` covers touch (1) (a write, `Deferred`-eligible)
/// but not touch (2) (a read, a *different*, independent call asserting the identical claim) —
/// forcing `Bound` and discarding touch (1)'s pending resolution, all the way through to
/// settlement. Even forced `Bound`, `transition_from_privacy_preserving_transaction` must still
/// land touch (1)'s real, `Incremental`-resolved value, not raw `TokenDiff` bytes.
#[test]
fn a_write_only_claim_settles_bound_once_a_later_read_discards_it() {
    let mut state = V03State::new().with_test_programs();
    let forward_program_id: AccountId =
        crate::test_methods::stripped_token_and_forward().id().into();
    let terminator_account_id: AccountId =
        crate::test_methods::defer_asserting_noop().id().into();
    let account_id = AccountId::new([1; 32]);

    let (tx, action) = write_then_read_tx(
        forward_program_id,
        terminator_account_id,
        account_id,
        lee_core::program::DeferReads::WriteOnly,
    );
    let PublicAction::Bound { pre, post } = action else {
        panic!("touch (2) is a read, which WriteOnly doesn't cover: expected Bound");
    };
    assert_eq!(pre.account_id, account_id);
    assert_eq!(pre.account, Account::default());
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("touch (1)'s Incremental resolution must have run in-circuit");
    assert_eq!(data.balance, 1);
    assert_eq!(post.program_owner, forward_program_id);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account_id), 1);
    assert_eq!(
        state.get_account_by_id(account_id).program_owner,
        forward_program_id
    );
}

/// The other direction: `DeferReads::ReadOnly` doesn't cover touch (1) (a write), forcing
/// `Bound` immediately — before touch (2) (a read, covered by the identical claim) ever runs.
/// Settlement lands the same real, resolved value either way.
#[test]
fn a_read_only_claim_settles_bound_from_an_uncovered_earlier_write() {
    let mut state = V03State::new().with_test_programs();
    let forward_program_id: AccountId =
        crate::test_methods::stripped_token_and_forward().id().into();
    let terminator_account_id: AccountId =
        crate::test_methods::defer_asserting_noop().id().into();
    let account_id = AccountId::new([1; 32]);

    let (tx, action) = write_then_read_tx(
        forward_program_id,
        terminator_account_id,
        account_id,
        lee_core::program::DeferReads::ReadOnly,
    );
    let PublicAction::Bound { pre, post } = action else {
        panic!("touch (1) is a write, which ReadOnly doesn't cover: expected Bound");
    };
    assert_eq!(pre.account_id, account_id);
    assert_eq!(pre.account, Account::default());
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("touch (1)'s Incremental resolution must have run in-circuit");
    assert_eq!(data.balance, 1);
    assert_eq!(post.program_owner, forward_program_id);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account_id), 1);
    assert_eq!(
        state.get_account_by_id(account_id).program_owner,
        forward_program_id
    );
}
